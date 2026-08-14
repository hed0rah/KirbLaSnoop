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
) -> Result<()> {
    let sock = UdpSocket::bind(&bind)
        .await
        .with_context(|| format!("binding udp {bind}"))?;
    let local = sock.local_addr()?.to_string();
    logger.listening(
        "udp",
        &name,
        &local,
        profile.as_ref().map(|p| p.name.as_str()).unwrap_or("none"),
    );

    let mut peers: HashMap<SocketAddr, Peer> = HashMap::new();
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

                let data = &buf[..n];
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
