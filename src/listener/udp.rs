use crate::log::{Dir, Logger};
use crate::profile::Compiled;
use crate::ts;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

const BUF: usize = 65_535;
const SWEEP_SECS: u64 = 5;

struct Peer {
    conn: u64,
    last_seen: u64,
}

/// udp has no connections, so we synthesise one per source address and
/// retire it after `idle_secs` of silence. that gives every peer a stable
/// conn id for the raw dumps without leaking state on a long run.
pub async fn run(
    name: String,
    bind: String,
    profile: Option<Arc<Compiled>>,
    logger: Arc<Logger>,
    idle_secs: u64,
    max_peers: usize,
) -> Result<()> {
    let sock = UdpSocket::bind(&bind)
        .await
        .with_context(|| format!("binding udp {bind}"))?;
    let addr = sock.local_addr()?;
    let local = addr.to_string();
    logger.listening(
        "udp",
        &name,
        &local,
        profile.as_ref().map(|p| p.name.as_str()).unwrap_or("none"),
    );

    // a udp source address is whatever the sender wrote in the header, so a
    // profile that replies will answer forged sources too. that makes this an
    // open reflector for anyone who can reach the port, and an amplifier
    // whenever the reply is larger than what triggered it.
    if let Some(p) = &profile
        && p.responds()
        && !addr.ip().is_loopback()
    {
        let ratio = match p.max_response_bytes() {
            Some(n) => format!("a 1-byte datagram draws up to {n} bytes"),
            None => "replies mirror the request size".to_string(),
        };
        logger.warn(
            "udp",
            &name,
            &format!(
                "profile {:?} replies to unverified source addresses on a non-loopback bind. \
                 udp sources are trivially forged, so this is an open reflector: {ratio}, \
                 sent wherever the sender claimed to be. bind loopback or an isolated \
                 interface unless that is intended",
                p.name
            ),
        );
    }

    let mut peers: HashMap<SocketAddr, Peer> = HashMap::new();
    let mut overflow_conn: Option<u64> = None;
    let mut overflow_count: u64 = 0;
    let mut buf = vec![0u8; BUF];
    let mut sweep = tokio::time::interval(std::time::Duration::from_secs(SWEEP_SECS));
    sweep.tick().await; // the first tick is immediate

    loop {
        tokio::select! {
            res = sock.recv_from(&mut buf) => {
                let (n, peer_addr) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        logger.error("udp", &name, None, &format!("recv: {e}"));
                        continue;
                    }
                };
                let now = ts::now_millis();
                let peer = peer_addr.to_string();

                let data = &buf[..n];
                let known = peers.contains_key(&peer_addr);

                // a flood of forged sources would otherwise grow the peer table
                // for the whole idle window. past the cap we keep capturing but
                // stop tracking and stop replying, which bounds both the memory
                // and the reflection.
                if !known && peers.len() >= max_peers {
                    let conn = *overflow_conn.get_or_insert_with(|| {
                        let id = logger.next_conn_id();
                        logger.open("udp", &name, id, &local, "overflow", None);
                        logger.warn(
                            "udp",
                            &name,
                            &format!(
                                "peer table hit {max_peers} entries. further new sources are \
                                 captured under one overflow stream, untracked and unanswered. \
                                 raise --udp-max-peers if this is legitimate traffic"
                            ),
                        );
                        id
                    });
                    overflow_count += 1;
                    logger.data("udp", &name, conn, &peer, Dir::Rx, data, None);
                    continue;
                }

                let mut first = false;
                let entry = peers.entry(peer_addr).or_insert_with(|| {
                    first = true;
                    Peer { conn: logger.next_conn_id(), last_seen: now }
                });
                entry.last_seen = now;
                let conn = entry.conn;
                if first {
                    // udp needs TPROXY + IP_RECVORIGDSTADDR to recover the
                    // pre-NAT destination; REDIRECT alone does not carry it.
                    logger.open("udp", &name, conn, &local, &peer, None);
                }

                logger.data("udp", &name, conn, &peer, Dir::Rx, data, None);

                if let Some(p) = &profile {
                    if first && let Some(a) = &p.on_connect {
                        reply(&sock, peer_addr, a, data, conn, &name, &peer, "on_connect", &logger).await;
                    }
                    if let Some((rule, action)) = p.eval(data, first) {
                        let rule = rule.to_string();
                        reply(&sock, peer_addr, action, data, conn, &name, &peer, &rule, &logger).await;
                    }
                }
            }
            _ = sweep.tick() => {
                let now = ts::now_millis();
                let cutoff = idle_secs.saturating_mul(1000);
                peers.retain(|addr, p| {
                    if now.saturating_sub(p.last_seen) < cutoff {
                        return true;
                    }
                    logger.close("udp", &name, p.conn, &addr.to_string(), "idle timeout");
                    false
                });

                // once the table drains, close out the overflow stream so a
                // later burst is reported again rather than folded into it
                if peers.len() < max_peers
                    && let Some(id) = overflow_conn.take()
                {
                    logger.close(
                        "udp",
                        &name,
                        id,
                        "overflow",
                        &format!("{overflow_count} untracked datagrams"),
                    );
                    overflow_count = 0;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn reply(
    sock: &UdpSocket,
    to: SocketAddr,
    action: &crate::profile::Action,
    received: &[u8],
    conn: u64,
    name: &str,
    peer: &str,
    rule: &str,
    logger: &Logger,
) {
    if action.is_silent() {
        return;
    }
    if action.delay_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(action.delay_ms)).await;
    }
    let payload: &[u8] = if action.echo {
        received
    } else {
        &action.payload
    };
    if payload.is_empty() {
        return;
    }
    match sock.send_to(payload, to).await {
        Ok(_) => logger.data("udp", name, conn, peer, Dir::Tx, payload, Some(rule)),
        Err(e) => logger.error("udp", name, Some(conn), &format!("send: {e}")),
    }
}
