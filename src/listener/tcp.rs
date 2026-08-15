use crate::log::{Dir, Logger};
use crate::profile::{Action, Compiled};
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

const BUF: usize = 64 * 1024;

pub async fn run(
    name: String,
    bind: String,
    profile: Option<Arc<Compiled>>,
    logger: Arc<Logger>,
    iface: Option<String>,
    upstream: Option<String>,
) -> Result<()> {
    // pinning to a device has to happen before bind, so an interface-bound
    // listener is built from an unbound socket rather than TcpListener::bind
    let sock = match &iface {
        Some(dev) => {
            let addr: std::net::SocketAddr = bind
                .parse()
                .with_context(|| format!("parsing tcp bind address {bind}"))?;
            let s = if addr.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            }
            .context("creating tcp socket")?;
            crate::sockopt::bind_to_device(&s, dev)?;
            s.set_reuseaddr(true).ok();
            s.bind(addr)
                .with_context(|| format!("binding tcp {bind} on {dev}"))?;
            s.listen(1024).context("listening")?
        }
        None => TcpListener::bind(&bind)
            .await
            .with_context(|| format!("binding tcp {bind}"))?,
    };
    let local_addr = sock.local_addr().ok();
    let local = sock.local_addr()?.to_string();
    let mode = match (&upstream, &profile) {
        (Some(up), _) => format!("forward->{up}"),
        (None, Some(p)) => p.name.clone(),
        (None, None) => "none".to_string(),
    };
    logger.listening("tcp", &name, &local, &mode);

    // forwarding and answering are exclusive on the first pass. saying so at
    // startup beats a profile that silently never fires.
    if upstream.is_some() && profile.as_ref().is_some_and(|p| p.responds()) {
        logger.warn(
            "tcp",
            &name,
            "an upstream and a responding profile are both set; the upstream wins \
             and the profile's rules will not fire",
        );
    }

    loop {
        match sock.accept().await {
            Ok((stream, peer)) => {
                let conn = logger.next_conn_id();
                // ask conntrack where this was really headed before answering
                let orig = local_addr
                    .and_then(|l| crate::origdst::original_dst(&stream, l))
                    .map(|a| a.to_string());
                logger.open(
                    "tcp",
                    &name,
                    conn,
                    &local,
                    &peer.to_string(),
                    orig.as_deref(),
                );
                let (name, profile, logger) = (name.clone(), profile.clone(), logger.clone());
                let upstream = upstream.clone();
                tokio::spawn(async move {
                    let peer = peer.to_string();
                    let outcome = match &upstream {
                        Some(up) => forward(stream, up, conn, &name, &peer, &logger).await,
                        None => serve(stream, conn, &name, &peer, profile, &logger).await,
                    };
                    let why = match outcome {
                        Ok(w) => w,
                        Err(e) => {
                            logger.error("tcp", &name, Some(conn), &e.to_string());
                            "error"
                        }
                    };
                    logger.close("tcp", &name, conn, &peer, why);
                });
            }
            Err(e) => {
                logger.error("tcp", &name, None, &format!("accept: {e}"));
                // accept errors are usually transient (fd exhaustion, RST during
                // handshake); yield and keep the listener alive.
                tokio::task::yield_now().await;
            }
        }
    }
}

async fn serve(
    mut stream: TcpStream,
    conn: u64,
    name: &str,
    peer: &str,
    profile: Option<Arc<Compiled>>,
    logger: &Logger,
) -> Result<&'static str> {
    let _ = stream.set_nodelay(true);

    if let Some(p) = &profile
        && let Some(a) = &p.on_connect
        && send(&mut stream, a, &[], conn, name, peer, "on_connect", logger).await?
    {
        return Ok("profile close");
    }

    let mut buf = vec![0u8; BUF];
    let mut first = true;
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok("peer eof");
        }
        let data = &buf[..n];
        logger.data("tcp", name, conn, peer, Dir::Rx, data, None);

        if let Some(p) = &profile
            && let Some((rule, action)) = p.eval(data, first)
        {
            // rule name is copied out so the borrow on `p` ends before the await
            let rule = rule.to_string();
            if send(&mut stream, action, data, conn, name, peer, &rule, logger).await? {
                return Ok("profile close");
            }
        }
        first = false;
    }
}

/// returns true if the action asked us to hang up.
#[allow(clippy::too_many_arguments)]
async fn send(
    stream: &mut TcpStream,
    action: &Action,
    received: &[u8],
    conn: u64,
    name: &str,
    peer: &str,
    rule: &str,
    logger: &Logger,
) -> Result<bool> {
    if action.is_silent() {
        return Ok(action.close);
    }
    if action.delay_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(action.delay_ms)).await;
    }
    let built;
    let payload: &[u8] = if action.echo {
        received
    } else if let Some(ans) = &action.dns {
        match crate::dns::reply_tcp(received, ans) {
            Some(v) => {
                built = v;
                &built
            }
            None => return Ok(action.close),
        }
    } else {
        &action.payload
    };
    if !payload.is_empty() {
        stream.write_all(payload).await?;
        stream.flush().await?;
        logger.data("tcp", name, conn, peer, Dir::Tx, payload, Some(rule));
    }
    if action.close {
        let _ = stream.shutdown().await;
    }
    Ok(action.close)
}


/// splice a client to an upstream, logging both directions.
///
/// no bytes are rewritten, so the existing log model still holds: rx is what
/// the client sent, tx is what came back. that is also why forwarding needs no
/// framing layer, unlike the rule engine: a relay never has to know where one
/// message ends and the next begins.
async fn forward(
    client: TcpStream,
    upstream: &str,
    conn: u64,
    name: &str,
    peer: &str,
    logger: &Logger,
) -> Result<&'static str> {
    let up = match TcpStream::connect(upstream).await {
        Ok(s) => s,
        Err(e) => {
            // a failed upstream is reported, never silently swallowed, or the
            // capture would look like the peer simply hung up
            logger.error(
                "tcp",
                name,
                Some(conn),
                &format!("upstream {upstream}: {e}"),
            );
            return Ok("upstream unreachable");
        }
    };
    let _ = client.set_nodelay(true);
    let _ = up.set_nodelay(true);

    let (cr, cw) = client.into_split();
    let (ur, uw) = up.into_split();

    // each direction runs to its own EOF and half-closes the far side, so a
    // peer that shuts down writing still receives the rest of the response
    let to_upstream = pump(cr, uw, Dir::Rx, conn, name, peer, logger);
    let to_client = pump(ur, cw, Dir::Tx, conn, name, peer, logger);
    let (a, b) = tokio::join!(to_upstream, to_client);
    a?;
    b?;
    Ok("both directions closed")
}

async fn pump(
    mut from: OwnedReadHalf,
    mut to: OwnedWriteHalf,
    dir: Dir,
    conn: u64,
    name: &str,
    peer: &str,
    logger: &Logger,
) -> Result<()> {
    let mut buf = vec![0u8; BUF];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) => {
                let _ = to.shutdown().await;
                return Ok(());
            }
            Ok(n) => n,
            // a reset mid-stream is normal at the end of a session
            Err(_) => {
                let _ = to.shutdown().await;
                return Ok(());
            }
        };
        logger.data("tcp", name, conn, peer, dir, &buf[..n], Some("forward"));
        if to.write_all(&buf[..n]).await.is_err() {
            return Ok(());
        }
    }
}
