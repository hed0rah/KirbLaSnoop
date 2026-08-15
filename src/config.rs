//! optional config file, and the terse CLI listener spec it mirrors.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn tag(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Listener {
    pub proto: Proto,
    pub bind: String,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    /// pin this listener to an interface by name
    #[serde(default)]
    pub iface: Option<String>,
    /// forward to this address instead of answering
    #[serde(default)]
    pub upstream: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(default, rename = "listen")]
    pub listeners: Vec<Listener>,
}

pub fn load(path: &Path) -> Result<ConfigFile> {
    let text =
        fs::read_to_string(path).with_context(|| format!("reading config {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
}

/// `tcp:9000`, `udp:0.0.0.0:9000`, `tcp:[::]:9000`, with an optional
/// `=profile` suffix: `tcp:9000=http`.
pub fn parse_spec(spec: &str) -> Result<Listener> {
    let (body, profile) = match spec.split_once('=') {
        Some((b, p)) if !p.is_empty() => (b, Some(p.to_string())),
        Some(_) => bail!("empty profile name in spec {spec:?}"),
        None => (spec, None),
    };

    let (proto_str, rest) = body
        .split_once(':')
        .with_context(|| format!("spec {spec:?} must look like proto:port"))?;

    let proto = match proto_str.to_ascii_lowercase().as_str() {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        other => bail!("unsupported protocol {other:?} (want tcp or udp)"),
    };

    // bare port means all interfaces; anything else is taken as addr:port
    let bind = if rest.chars().all(|c| c.is_ascii_digit()) && !rest.is_empty() {
        format!("0.0.0.0:{rest}")
    } else {
        rest.to_string()
    };

    Ok(Listener {
        proto,
        bind,
        profile,
        name: None,
        iface: None,
        upstream: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_port_binds_all_interfaces() {
        let l = parse_spec("tcp:9000").unwrap();
        assert_eq!(l.proto, Proto::Tcp);
        assert_eq!(l.bind, "0.0.0.0:9000");
        assert!(l.profile.is_none());
    }

    #[test]
    fn explicit_addr_is_preserved() {
        assert_eq!(parse_spec("udp:127.0.0.1:53").unwrap().bind, "127.0.0.1:53");
        assert_eq!(parse_spec("tcp:[::1]:8080").unwrap().bind, "[::1]:8080");
    }

    #[test]
    fn profile_suffix() {
        let l = parse_spec("tcp:80=http").unwrap();
        assert_eq!(l.bind, "0.0.0.0:80");
        assert_eq!(l.profile.as_deref(), Some("http"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_spec("9000").is_err());
        assert!(parse_spec("sctp:9000").is_err());
        assert!(parse_spec("tcp:9000=").is_err());
    }
}
