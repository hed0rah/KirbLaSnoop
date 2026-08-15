//! kirblasnoop -- bind ports, swallow whatever arrives, log it byte-exact,
//! and optionally answer back convincingly enough to keep the peer talking.

mod classify;
mod config;
mod dns;
mod hexdump;
mod listener;
mod log;
mod origdst;
mod profile;
mod sockopt;
mod stream;
mod ts;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "kls",
    about = "packet vacuum and fake-service rig for reverse engineering",
    long_about = "Binds one or more tcp/udp ports, logs everything that arrives \
                  (console hexdump, jsonl events, byte-exact raw dumps), and \
                  optionally replies according to a behaviour profile.\n\n\
                  SPEC is proto:port, proto:addr:port, with an optional =profile:\n  \
                  kls tcp:9000 udp:9000\n  \
                  kls tcp:80=http udp:53\n  \
                  kls udp:127.0.0.1:9000"
)]
struct Cli {
    /// listener specs, e.g. tcp:9000 udp:9000 tcp:80=http
    #[arg(value_name = "SPEC")]
    specs: Vec<String>,

    /// config file describing listeners
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// default profile for specs that do not name one
    #[arg(short, long, value_name = "NAME|PATH")]
    profile: Option<String>,

    /// where to look up profiles by name. defaults to the first of
    /// ./profiles, $XDG_DATA_HOME/kirblasnoop/profiles,
    /// ~/.local/share/kirblasnoop/profiles, /usr/local/share/kirblasnoop/profiles,
    /// /usr/share/kirblasnoop/profiles that exists
    #[arg(long, value_name = "DIR", global = true)]
    profile_dir: Option<PathBuf>,

    /// root for capture output; a timestamped run dir is created inside
    #[arg(short = 'd', long, default_value = "captures", value_name = "DIR")]
    log_dir: PathBuf,

    /// console rendering: hex, ascii, summary, none
    #[arg(long, default_value = "hex", value_name = "MODE")]
    console: log::ConsoleMode,

    /// truncate console output per message; 0 for unlimited
    #[arg(long, default_value_t = 0, value_name = "N")]
    max_bytes: usize,

    /// do not write raw per-stream .bin dumps
    #[arg(long)]
    no_raw: bool,

    /// do not write events.jsonl
    #[arg(long)]
    no_jsonl: bool,

    /// write nothing to disk; console only
    #[arg(long)]
    no_files: bool,

    /// payload bytes embedded per event in events.jsonl; 0 for all of it.
    /// the .bin files always hold the full stream, so this is an index size,
    /// not a fidelity setting
    #[arg(long, default_value_t = 256, value_name = "N")]
    jsonl_max_data: usize,

    /// keep only the first SIZE of each stream file (e.g. 8M); 0 for all
    #[arg(long, default_value = "0", value_name = "SIZE", value_parser = stream::parse_size)]
    stream_head: u64,

    /// also keep the last SIZE of each stream, in a .tail.bin beside it
    #[arg(long, default_value = "0", value_name = "SIZE", value_parser = stream::parse_size)]
    stream_tail: u64,

    /// shorthand for --stream-head SIZE --stream-tail SIZE
    #[arg(long, value_name = "SIZE", value_parser = stream::parse_size)]
    ring: Option<u64>,

    /// stop writing to disk after the run produces this much; 0 disables
    #[arg(long, default_value = "1G", value_name = "SIZE", value_parser = stream::parse_size)]
    max_run_bytes: u64,

    /// forward to this address instead of answering, e.g. 192.0.2.5:443.
    /// both directions are logged; a listener with an upstream ignores its
    /// profile. tcp only for now
    #[arg(long, value_name = "ADDR:PORT")]
    upstream: Option<String>,

    /// pin listeners to a network interface by name, e.g. eth0. an
    /// interface can carry several addresses and ipv6 privacy addresses
    /// rotate, so this is steadier than binding one address
    #[arg(long, value_name = "NAME")]
    iface: Option<String>,

    /// retire a silent udp peer after this many seconds
    #[arg(long, default_value_t = 60, value_name = "SECS")]
    udp_idle: u64,

    /// cap on tracked udp source addresses. past this, datagrams are still
    /// captured but sources are untracked and unanswered, which bounds memory
    /// and reflection under a flood of forged sources
    #[arg(long, default_value_t = 4096, value_name = "N")]
    udp_max_peers: usize,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// list profiles available in --profile-dir
    Profiles,

    /// print the netfilter rules for catch-all transparent capture.
    /// prints only: it never touches your firewall.
    Transparent {
        /// the port kls is listening on
        #[arg(long, default_value_t = 9999)]
        port: u16,

        /// only redirect traffic from this user (strongly recommended)
        #[arg(long, default_value = "snoop")]
        uid: String,

        /// only redirect these destination ports, e.g. 80,443. default: all
        #[arg(long, value_name = "LIST")]
        dport: Option<String>,

        /// also hijack the program's loopback traffic (usually unwanted)
        #[arg(long)]
        include_loopback: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let profile_dir = resolve_profile_dir(cli.profile_dir.as_deref());

    match &cli.cmd {
        Some(Cmd::Profiles) => return list_profiles(&profile_dir),
        Some(Cmd::Transparent {
            port,
            uid,
            dport,
            include_loopback,
        }) => {
            print_transparent(*port, uid, dport.as_deref(), *include_loopback);
            return Ok(());
        }
        None => {}
    }

    // listeners come from the config file, the CLI, or both
    let mut listeners = Vec::new();
    if let Some(path) = &cli.config {
        listeners.extend(config::load(path)?.listeners);
    }
    for spec in &cli.specs {
        listeners.push(config::parse_spec(spec)?);
    }
    if listeners.is_empty() {
        bail!("nothing to listen on. try: kls tcp:9000 udp:9000  (or --help)");
    }

    // one compiled profile per distinct name, shared across listeners
    let mut profiles: HashMap<String, Arc<profile::Compiled>> = HashMap::new();
    for l in &listeners {
        let Some(spec) = l.profile.as_ref().or(cli.profile.as_ref()) else {
            continue;
        };
        if profiles.contains_key(spec) {
            continue;
        }
        let path = profile::resolve(spec, &profile_dir)?;
        let compiled = profile::load(&path)?;
        eprintln!(
            "kls: loaded profile {:?} ({} rules) from {}",
            compiled.name,
            compiled.rules.len(),
            path.display()
        );
        profiles.insert(spec.clone(), Arc::new(compiled));
    }

    let logger = Arc::new(log::Logger::new(log::Options {
        dir: cli.log_dir.clone(),
        console: cli.console,
        jsonl: !cli.no_jsonl && !cli.no_files,
        raw: !cli.no_raw && !cli.no_files,
        max_console_bytes: cli.max_bytes,
        jsonl_max_data: cli.jsonl_max_data,
        stream_limits: stream::Limits {
            head: cli.ring.unwrap_or(cli.stream_head),
            tail: cli.ring.unwrap_or(cli.stream_tail) as usize,
        },
        max_run_bytes: cli.max_run_bytes,
    })?);
    if logger.writes_files() {
        eprintln!("kls: capture dir {}", logger.run_dir().display());
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting tokio runtime")?;

    rt.block_on(async move {
        let mut set = tokio::task::JoinSet::new();
        for (i, l) in listeners.into_iter().enumerate() {
            let name = l
                .name
                .clone()
                .unwrap_or_else(|| format!("{}:{}", l.proto.tag(), i));
            let prof = l
                .profile
                .as_ref()
                .or(cli.profile.as_ref())
                .and_then(|s| profiles.get(s))
                .cloned();
            let logger = logger.clone();
            let bind = l.bind.clone();
            let iface = l.iface.clone().or_else(|| cli.iface.clone());
            let upstream = l.upstream.clone().or_else(|| cli.upstream.clone());

            match l.proto {
                config::Proto::Tcp => {
                    set.spawn(listener::tcp::run(
                        name, bind, prof, logger, iface, upstream,
                    ));
                }
                config::Proto::Udp => {
                    set.spawn(listener::udp::run(
                        name,
                        bind,
                        prof,
                        logger,
                        cli.udp_idle,
                        cli.udp_max_peers,
                        iface,
                    ));
                    if upstream.is_some() {
                        eprintln!(
                            "kls: --upstream is tcp only; the udp listener on {} will \
                             capture but not forward",
                            l.bind
                        );
                    }
                }
            }
        }

        // a listener task only returns early on a bind failure. report it, but
        // keep running for the listeners that did come up.
        let mut failed = 0usize;
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!();
                    break;
                }
                Some(res) = set.join_next() => {
                    match res {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => { eprintln!("kls: {e:#}"); failed += 1; }
                        Err(e) => eprintln!("kls: listener task panicked: {e}"),
                    }
                    if set.is_empty() {
                        break;
                    }
                }
            }
        }

        logger.flush();
        logger.summary();
        if failed > 0 && set.is_empty() {
            bail!("every listener failed to start");
        }
        Ok(())
    })
}

/// an installed kls is run from wherever the investigation lives, so a
/// relative default would find nothing. the repo checkout still wins when
/// present, which keeps development working without a flag.
fn resolve_profile_dir(explicit: Option<&std::path::Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    let mut candidates = vec![PathBuf::from("profiles")];
    if let Some(x) = std::env::var_os("XDG_DATA_HOME") {
        candidates.push(PathBuf::from(x).join("kirblasnoop/profiles"));
    }
    if let Some(h) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(h).join(".local/share/kirblasnoop/profiles"));
    }
    candidates.push(PathBuf::from("/usr/local/share/kirblasnoop/profiles"));
    candidates.push(PathBuf::from("/usr/share/kirblasnoop/profiles"));

    candidates
        .iter()
        .find(|p| p.is_dir())
        .cloned()
        .unwrap_or_else(|| candidates.remove(0))
}

/// print, never apply. the user asked for copy-paste rules so the tool stays
/// the same on every box and a hard kill can never strand a firewall rule.
fn print_transparent(port: u16, uid: &str, dport: Option<&str>, include_loopback: bool) {
    let mut m = format!("-p tcp -m owner --uid-owner {uid}");
    if let Some(ports) = dport {
        let _ = write!(m, " -m multiport --dports {ports}");
    }
    let jump = format!("-j REDIRECT --to-ports {port}");

    let v4_skip = if include_loopback {
        String::new()
    } else {
        " ! -d 127.0.0.0/8".to_string()
    };
    let v6_skip = if include_loopback {
        String::new()
    } else {
        " ! -d ::1/128".to_string()
    };

    println!(
        "\
# transparent catch-all: every tcp connection made by uid '{uid}' lands in kls,
# which recovers the real destination from conntrack via SO_ORIGINAL_DST.
# nothing below is executed for you. read it, then run what you want.

# 1. a throwaway user to scope the redirect (once):
sudo useradd --no-create-home --shell /usr/sbin/nologin {uid}

# 2. start the vacuum on the catch-all port:
kls tcp:{port}

# 3. install the redirect:
sudo iptables  -t nat -A OUTPUT {m}{v4_skip} {jump}
sudo ip6tables -t nat -A OUTPUT {m}{v6_skip} {jump}

# 4. run the program under test as that user:
sudo -u {uid} ./the-unknown-binary

# 5. tear down (identical rules, -D instead of -A):
sudo iptables  -t nat -D OUTPUT {m}{v4_skip} {jump}
sudo ip6tables -t nat -D OUTPUT {m}{v6_skip} {jump}

# notes
#   - scoping by --uid-owner is what keeps this off your own traffic. dropping
#     it redirects every outbound tcp connection on the box, including this
#     shell's. do not.
#   - only affects locally-originated traffic (OUTPUT). to catch another host,
#     put the rule in PREROUTING on the box that routes for it.
#   - udp is not covered: REDIRECT does not carry the original destination for
#     datagrams, that needs TPROXY. udp listeners still capture, just without
#     the WANTED line.
#   - conntrack must be loaded; the nat table pulls it in automatically."
    );
}

fn list_profiles(dir: &std::path::Path) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading profile dir {}", dir.display()))?;
    let mut found = Vec::new();
    for e in entries.flatten() {
        let path = e.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        match profile::load(&path) {
            Ok(p) => found.push((p.name, p.description, p.rules.len())),
            Err(err) => eprintln!("kls: skipping {}: {err:#}", path.display()),
        }
    }
    found.sort();
    if found.is_empty() {
        println!("no profiles in {}", dir.display());
    }
    for (name, desc, rules) in found {
        println!("{name:<14} {rules:>3} rules  {desc}");
    }
    Ok(())
}
