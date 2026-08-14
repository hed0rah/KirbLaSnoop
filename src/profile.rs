//! behaviour profiles: what the fake service says back.
//!
//! a profile is an optional connect-time banner plus an ordered rule list.
//! first matching rule wins. no match means say nothing, which is the
//! correct default for a pure vacuum.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Profile {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// sent as soon as a peer shows up, before reading anything.
    /// for udp this fires on the first datagram from a new peer.
    pub on_connect: Option<Respond>,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "when")]
    pub matcher: Match,
    pub respond: Option<Respond>,
}

/// every field that is present must hold (logical AND). an empty matcher
/// matches everything, same as `any = true`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    pub any: Option<bool>,
    pub starts_with: Option<String>,
    pub contains: Option<String>,
    pub ends_with: Option<String>,
    pub prefix_hex: Option<String>,
    pub contains_hex: Option<String>,
    pub min_len: Option<usize>,
    pub max_len: Option<usize>,
    pub len: Option<usize>,
    /// only match on the first message of a connection/peer
    pub first_only: Option<bool>,
    /// match regardless of ascii case (applies to the string matchers)
    #[serde(default)]
    pub ignore_case: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Respond {
    /// literal text, supports \n \r \t \0 \\ \" and \xNN
    pub text: Option<String>,
    /// hex bytes, whitespace and ':' separators ignored
    pub hex: Option<String>,
    /// contents of a file, resolved relative to the profile
    pub file: Option<PathBuf>,
    /// send back exactly what was received
    #[serde(default)]
    pub echo: bool,
    /// wait this long before sending
    #[serde(default)]
    pub delay_ms: u64,
    /// repeat the payload n times (default 1)
    pub repeat: Option<usize>,
    /// hang up after sending
    #[serde(default)]
    pub close: bool,
}

/// a Respond flattened into bytes, resolved once at load time so the hot
/// path never touches the filesystem.
#[derive(Debug, Clone, Default)]
pub struct Action {
    pub payload: Vec<u8>,
    pub echo: bool,
    pub delay_ms: u64,
    pub close: bool,
}

impl Action {
    pub fn is_silent(&self) -> bool {
        self.payload.is_empty() && !self.echo
    }
}

/// load-time compiled form of a profile.
#[derive(Debug)]
pub struct Compiled {
    pub name: String,
    pub description: String,
    pub on_connect: Option<Action>,
    pub rules: Vec<CompiledRule>,
}

#[derive(Debug)]
pub struct CompiledRule {
    pub name: String,
    pub matcher: Match,
    pub action: Action,
}

impl Compiled {
    /// walk rules in order, first match wins.
    pub fn eval(&self, data: &[u8], first: bool) -> Option<(&str, &Action)> {
        self.rules
            .iter()
            .find(|r| r.matcher.matches(data, first))
            .map(|r| (r.name.as_str(), &r.action))
    }
}

impl Match {
    pub fn matches(&self, data: &[u8], first: bool) -> bool {
        // `any = true` is the documented catch-all and is what an empty matcher
        // already does. `any = false` is almost certainly a mistake, so it
        // matches nothing rather than silently meaning the opposite.
        if self.any == Some(false) {
            return false;
        }
        if self.first_only == Some(true) && !first {
            return false;
        }
        if let Some(n) = self.len
            && data.len() != n
        {
            return false;
        }
        if let Some(n) = self.min_len
            && data.len() < n
        {
            return false;
        }
        if let Some(n) = self.max_len
            && data.len() > n
        {
            return false;
        }

        // string matchers are compared against raw bytes, so they work on
        // binary protocols too as long as the needle is ascii.
        let hay: Vec<u8> = if self.ignore_case {
            data.to_ascii_lowercase()
        } else {
            Vec::new()
        };
        let hay = if self.ignore_case { &hay[..] } else { data };
        let fold = |s: &str| -> Vec<u8> {
            if self.ignore_case {
                s.as_bytes().to_ascii_lowercase()
            } else {
                s.as_bytes().to_vec()
            }
        };

        if let Some(s) = &self.starts_with
            && !hay.starts_with(&fold(s))
        {
            return false;
        }
        if let Some(s) = &self.ends_with
            && !hay.ends_with(&fold(s))
        {
            return false;
        }
        if let Some(s) = &self.contains
            && find(hay, &fold(s)).is_none()
        {
            return false;
        }
        if let Some(h) = &self.prefix_hex {
            match parse_hex(h) {
                Ok(needle) if data.starts_with(&needle) => {}
                _ => return false,
            }
        }
        if let Some(h) = &self.contains_hex {
            match parse_hex(h) {
                Ok(needle) if find(data, &needle).is_some() => {}
                _ => return false,
            }
        }
        true
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

pub fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-' && *c != ',')
        .collect();
    let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);
    if !cleaned.len().is_multiple_of(2) {
        bail!("hex string has an odd number of digits: {s:?}");
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .with_context(|| format!("bad hex byte {:?} in {s:?}", &cleaned[i..i + 2]))
        })
        .collect()
}

/// \n \r \t \0 \\ \" \xNN
pub fn unescape(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        match it.next() {
            Some('n') => out.push(b'\n'),
            Some('r') => out.push(b'\r'),
            Some('t') => out.push(b'\t'),
            Some('0') => out.push(0),
            Some('\\') => out.push(b'\\'),
            Some('"') => out.push(b'"'),
            Some('x') => {
                let hi = it.next().context("truncated \\x escape")?;
                let lo = it.next().context("truncated \\x escape")?;
                let v = u8::from_str_radix(&format!("{hi}{lo}"), 16)
                    .with_context(|| format!("bad \\x escape: \\x{hi}{lo}"))?;
                out.push(v);
            }
            Some(other) => bail!("unknown escape: \\{other}"),
            None => bail!("trailing backslash"),
        }
    }
    Ok(out)
}

fn compile_respond(r: &Respond, base: &Path) -> Result<Action> {
    let mut payload = Vec::new();
    if let Some(t) = &r.text {
        payload.extend_from_slice(&unescape(t)?);
    }
    if let Some(h) = &r.hex {
        payload.extend_from_slice(&parse_hex(h)?);
    }
    if let Some(p) = &r.file {
        let path = if p.is_absolute() {
            p.clone()
        } else {
            base.join(p)
        };
        let bytes = fs::read(&path)
            .with_context(|| format!("reading respond file {}", path.display()))?;
        payload.extend_from_slice(&bytes);
    }
    if let Some(n) = r.repeat {
        payload = payload.repeat(n);
    }
    Ok(Action {
        payload,
        echo: r.echo,
        delay_ms: r.delay_ms,
        close: r.close,
    })
}

pub fn load(path: &Path) -> Result<Compiled> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading profile {}", path.display()))?;
    let p: Profile = toml::from_str(&text)
        .with_context(|| format!("parsing profile {}", path.display()))?;
    let base = path.parent().unwrap_or(Path::new("."));

    let on_connect = p
        .on_connect
        .as_ref()
        .map(|r| compile_respond(r, base))
        .transpose()?;

    let mut rules = Vec::with_capacity(p.rules.len());
    for (i, r) in p.rules.iter().enumerate() {
        let action = match &r.respond {
            Some(resp) => compile_respond(resp, base)?,
            None => Action::default(),
        };
        rules.push(CompiledRule {
            name: r.name.clone().unwrap_or_else(|| format!("rule[{i}]")),
            matcher: Match {
                any: r.matcher.any,
                starts_with: r.matcher.starts_with.clone(),
                contains: r.matcher.contains.clone(),
                ends_with: r.matcher.ends_with.clone(),
                prefix_hex: r.matcher.prefix_hex.clone(),
                contains_hex: r.matcher.contains_hex.clone(),
                min_len: r.matcher.min_len,
                max_len: r.matcher.max_len,
                len: r.matcher.len,
                first_only: r.matcher.first_only,
                ignore_case: r.matcher.ignore_case,
            },
            action,
        });
    }

    Ok(Compiled {
        name: p.name,
        description: p.description,
        on_connect,
        rules,
    })
}

/// resolve `spec` as a path, else as `<dir>/<spec>.toml`.
pub fn resolve(spec: &str, dir: &Path) -> Result<PathBuf> {
    let direct = Path::new(spec);
    if direct.is_file() {
        return Ok(direct.to_path_buf());
    }
    let named = dir.join(format!("{spec}.toml"));
    if named.is_file() {
        return Ok(named);
    }
    bail!(
        "profile {spec:?} not found (looked at {} and {})",
        direct.display(),
        named.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_parsing_tolerates_separators() {
        assert_eq!(parse_hex("de ad:be-ef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(parse_hex("0x0001").unwrap(), vec![0, 1]);
        assert!(parse_hex("abc").is_err());
    }

    #[test]
    fn escapes_round_trip() {
        assert_eq!(unescape("a\\r\\nb").unwrap(), b"a\r\nb");
        assert_eq!(unescape("\\x00\\xff").unwrap(), vec![0x00, 0xff]);
        assert!(unescape("\\q").is_err());
    }

    #[test]
    fn empty_matcher_matches_anything() {
        assert!(Match::default().matches(b"whatever", false));
        assert!(Match::default().matches(&[], true));
    }

    #[test]
    fn conditions_are_anded() {
        let m = Match {
            starts_with: Some("GET".into()),
            min_len: Some(10),
            ..Default::default()
        };
        assert!(!m.matches(b"GET /", false));
        assert!(m.matches(b"GET /index.html", false));
    }

    #[test]
    fn ignore_case_folds_both_sides() {
        let m = Match {
            contains: Some("EhLo".into()),
            ignore_case: true,
            ..Default::default()
        };
        assert!(m.matches(b"ehlo mail.example.com", false));
    }

    #[test]
    fn first_only_gates_on_first_message() {
        let m = Match {
            first_only: Some(true),
            ..Default::default()
        };
        assert!(m.matches(b"x", true));
        assert!(!m.matches(b"x", false));
    }

    #[test]
    fn any_false_matches_nothing_rather_than_everything() {
        let m = Match {
            any: Some(false),
            ..Default::default()
        };
        assert!(!m.matches(b"anything at all", true));
        // and the documented catch-all still works
        let yes = Match {
            any: Some(true),
            ..Default::default()
        };
        assert!(yes.matches(b"anything at all", false));
    }

    #[test]
    fn binary_prefix_matching() {
        let m = Match {
            prefix_hex: Some("cafe".into()),
            ..Default::default()
        };
        assert!(m.matches(&[0xca, 0xfe, 0x01], false));
        assert!(!m.matches(&[0xca, 0xff], false));
    }
}
