use crate::log::{Dir, Logger};
use crate::profile::{Action, Compiled};
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const BUF: usize = 64 * 1024;

pub async fn run(
    name: String,
    bind: String,
    profile: Option<Arc<Compiled>>,
    logger: Arc<Logger>,
) -> Result<()> {
    let sock = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding tcp {bind}"))?;
    let local_addr = sock.local_addr().ok();
    let local = sock.local_addr()?.to_string();
    logger.listening(
        "tcp",
        &name,
        &local,
        profile.as_ref().map(|p| p.name.as_str()).unwrap_or("none"),
    );

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
                tokio::spawn(async move {
                    let peer = peer.to_string();
                    let why = match serve(stream, conn, &name, &peer, profile, &logger).await {
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
    let payload: &[u8] = if action.echo {
        received
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
