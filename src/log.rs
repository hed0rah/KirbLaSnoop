//! three independent sinks: console, jsonl event log, raw per-stream dumps.
//!
//! the raw dumps are the point of the whole tool -- byte-exact streams you
//! can diff, replay, or feed to a parser later. json is for querying, the
//! console is for watching it happen live.

use crate::{hexdump, stream, ts};
use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Serialize;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConsoleMode {
    Hex,
    Ascii,
    Summary,
    None,
}

impl std::str::FromStr for ConsoleMode {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "hex" => Ok(Self::Hex),
            "ascii" => Ok(Self::Ascii),
            "summary" => Ok(Self::Summary),
            "none" | "off" => Ok(Self::None),
            other => Err(format!("unknown console mode {other:?}")),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Rx,
    Tx,
}

impl Dir {
    fn tag(self) -> &'static str {
        match self {
            Dir::Rx => "rx",
            Dir::Tx => "tx",
        }
    }
    fn arrow(self) -> &'static str {
        match self {
            Dir::Rx => "-->",
            Dir::Tx => "<--",
        }
    }
}

#[derive(Serialize)]
struct Event<'a> {
    ts: String,
    ts_ms: u64,
    event: &'a str,
    proto: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    listener: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conn: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer: Option<&'a str>,
    /// pre-NAT destination the peer actually asked for, when redirected
    #[serde(skip_serializing_if = "Option::is_none")]
    orig_dst: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dir: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    len: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    /// set when `data` holds only the first slice of the payload. `len` is
    /// always the true length, and the .bin files hold the full bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    data_truncated: Option<bool>,
}

pub struct Options {
    pub dir: PathBuf,
    pub console: ConsoleMode,
    pub jsonl: bool,
    pub raw: bool,
    /// per-message console truncation, 0 = unlimited
    pub max_console_bytes: usize,
    /// how much payload to embed in each jsonl event, 0 = all of it.
    /// this is an index, not a second copy of the capture: base64 costs 4/3
    /// of the raw bytes, so embedding everything made events.jsonl larger
    /// than the .bin files it duplicates.
    pub jsonl_max_data: usize,
    /// head/tail limits applied to every raw stream file
    pub stream_limits: stream::Limits,
    /// stop writing to disk once the run has produced this many bytes,
    /// 0 = no cap
    pub max_run_bytes: u64,
}

#[derive(Default)]
pub struct Stats {
    pub conns: AtomicU64,
    pub rx_msgs: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_msgs: AtomicU64,
    pub tx_bytes: AtomicU64,
}

struct Sinks {
    jsonl: Option<BufWriter<File>>,
    raw: HashMap<(u64, &'static str), stream::Stream>,
}

pub struct Logger {
    opts: Options,
    run_dir: PathBuf,
    sinks: Mutex<Sinks>,
    next_conn: AtomicU64,
    disk_used: AtomicU64,
    disk_stopped: AtomicBool,
    pub stats: Stats,
}

impl Logger {
    pub fn new(opts: Options) -> Result<Self> {
        let run_dir = opts.dir.join(ts::stamp(ts::now_millis()));
        let needs_dir = opts.jsonl || opts.raw;
        if needs_dir {
            fs::create_dir_all(&run_dir)
                .with_context(|| format!("creating capture dir {}", run_dir.display()))?;
        }

        let jsonl = if opts.jsonl {
            let p = run_dir.join("events.jsonl");
            Some(BufWriter::new(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&p)
                    .with_context(|| format!("opening {}", p.display()))?,
            ))
        } else {
            None
        };

        Ok(Self {
            opts,
            run_dir,
            sinks: Mutex::new(Sinks {
                jsonl,
                raw: HashMap::new(),
            }),
            next_conn: AtomicU64::new(1),
            disk_used: AtomicU64::new(0),
            disk_stopped: AtomicBool::new(false),
            stats: Stats::default(),
        })
    }

    /// charge bytes against the run's disk budget. returns false once the cap
    /// is hit, at which point disk writes stop but the console keeps going, so
    /// a long unattended run degrades instead of filling the filesystem.
    fn charge(&self, n: u64) -> bool {
        if self.opts.max_run_bytes == 0 {
            return true;
        }
        if self.disk_stopped.load(Ordering::Acquire) {
            return false;
        }
        let used = self.disk_used.fetch_add(n, Ordering::Relaxed) + n;
        if used > self.opts.max_run_bytes {
            // give the bytes back: this write is being refused, so counting it
            // would make the summary claim more was captured than really was
            self.disk_used.fetch_sub(n, Ordering::Relaxed);
            if !self.disk_stopped.swap(true, Ordering::AcqRel) {
                eprintln!(
                    "[{}] LIMIT   run cap of {} reached: disk writes stopped, console continues. \
                     raise it with --max-run-bytes (0 disables)",
                    ts::clock(ts::now_millis()),
                    stream::human(self.opts.max_run_bytes)
                );
            }
            return false;
        }
        true
    }

    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    pub fn writes_files(&self) -> bool {
        self.opts.jsonl || self.opts.raw
    }

    pub fn next_conn_id(&self) -> u64 {
        self.next_conn.fetch_add(1, Ordering::Relaxed)
    }

    fn emit(&self, ev: &Event<'_>) {
        if !self.opts.jsonl {
            return;
        }
        let Ok(line) = serde_json::to_string(ev) else {
            return;
        };
        if !self.charge(line.len() as u64 + 1) {
            return;
        }
        let Ok(mut s) = self.sinks.lock() else { return };
        if let Some(w) = s.jsonl.as_mut() {
            let _ = writeln!(w, "{line}");
            // flushed per event: a capture that dies mid-run is still readable
            let _ = w.flush();
        }
    }

    fn raw_write(&self, conn: u64, proto: &str, peer: &str, dir: Dir, data: &[u8]) {
        if !self.opts.raw || data.is_empty() || !self.charge(data.len() as u64) {
            return;
        }
        let Ok(mut s) = self.sinks.lock() else { return };
        let key = (conn, dir.tag());
        if let Entry::Vacant(slot) = s.raw.entry(key) {
            let safe: String = peer
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect();
            let stem = format!("{conn:04}-{proto}-{safe}.{}", dir.tag());
            let head = self.run_dir.join(format!("{stem}.bin"));
            let tail = self.run_dir.join(format!("{stem}.tail.bin"));
            match stream::Stream::create(head, tail, self.opts.stream_limits) {
                Ok(st) => {
                    slot.insert(st);
                }
                Err(e) => {
                    eprintln!("kls: cannot open raw dump {stem}.bin: {e}");
                    return;
                }
            }
        }
        if let Some(st) = s.raw.get_mut(&key)
            && st.write(data)
        {
            // announced once per stream, the moment bytes start being dropped
            drop(s);
            let head = stream::human(self.opts.stream_limits.head);
            let tail = self.opts.stream_limits.tail;
            let policy = if tail == 0 {
                format!("keeping the first {head}")
            } else {
                format!("keeping the first {head} and last {}", stream::human(tail as u64))
            };
            println!(
                "[{}] TRUNC   #{conn} {} exceeded the stream cap, {policy}",
                ts::clock(ts::now_millis()),
                dir.tag(),
            );
        }
    }

    fn close_raw(&self, conn: u64, proto: &str, name: &str, peer: &str) {
        if !self.opts.raw {
            return;
        }
        let mut finished = Vec::new();
        {
            let Ok(mut s) = self.sinks.lock() else { return };
            for dir in ["rx", "tx"] {
                if let Some(st) = s.raw.remove(&(conn, dir)) {
                    finished.push((dir, st.finish()));
                }
            }
        }
        // report the gap outside the lock: a truncated capture that does not
        // say so is worse than no capture, because it reads as complete.
        for (dir, sum) in finished {
            if sum.dropped == 0 {
                continue;
            }
            let where_tail = sum
                .tail_path
                .as_ref()
                .and_then(|p| p.file_name())
                .map(|n| format!(", tail in {}", n.to_string_lossy()))
                .unwrap_or_default();
            let note = format!(
                "{dir} truncated: {} of {} kept ({} head + {} tail), {} dropped{where_tail}",
                stream::human(sum.head + sum.tail as u64),
                stream::human(sum.total),
                stream::human(sum.head),
                stream::human(sum.tail as u64),
                stream::human(sum.dropped),
            );
            println!("[{}] TRUNC   #{conn} {note}", ts::clock(ts::now_millis()));
            let now = ts::now_millis();
            self.emit(&Event {
                ts: ts::iso8601(now),
                ts_ms: now,
                event: "truncated",
                proto,
                listener: Some(name),
                conn: Some(conn),
                local: None,
                peer: Some(peer),
                orig_dst: None,
                dir: Some(dir),
                hint: None,
                len: Some(sum.total as usize),
                rule: None,
                note: Some(&note),
                data: None,
                data_truncated: None,
            });
        }
    }

    pub fn listening(&self, proto: &str, name: &str, local: &str, profile: &str) {
        let now = ts::now_millis();
        println!(
            "[{}] listen  {proto}/{local}  listener={name} profile={profile}",
            ts::clock(now)
        );
        self.emit(&Event {
            ts: ts::iso8601(now),
            ts_ms: now,
            event: "listen",
            proto,
            listener: Some(name),
            conn: None,
            local: Some(local),
            peer: None,
            orig_dst: None,
            dir: None,
            hint: None,
            len: None,
            rule: None,
            note: Some(profile),
            data: None,
            data_truncated: None,
        });
    }

    /// `orig` is the pre-NAT destination when the connection was redirected
    /// into us; it is the whole point of transparent mode, so it leads the
    /// console line rather than trailing it.
    pub fn open(
        &self,
        proto: &str,
        name: &str,
        conn: u64,
        local: &str,
        peer: &str,
        orig: Option<&str>,
    ) {
        self.stats.conns.fetch_add(1, Ordering::Relaxed);
        let now = ts::now_millis();
        if self.opts.console != ConsoleMode::None {
            match orig {
                Some(o) => println!(
                    "[{}] open    #{conn} {proto} {peer} WANTED {o}",
                    ts::clock(now)
                ),
                None => println!(
                    "[{}] open    #{conn} {proto} {peer} -> {local}",
                    ts::clock(now)
                ),
            }
        }
        self.emit(&Event {
            ts: ts::iso8601(now),
            ts_ms: now,
            event: "open",
            proto,
            listener: Some(name),
            conn: Some(conn),
            local: Some(local),
            peer: Some(peer),
            orig_dst: orig,
            dir: None,
            hint: None,
            len: None,
            rule: None,
            note: None,
            data: None,
            data_truncated: None,
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn data(
        &self,
        proto: &str,
        name: &str,
        conn: u64,
        peer: &str,
        dir: Dir,
        data: &[u8],
        rule: Option<&str>,
    ) {
        match dir {
            Dir::Rx => {
                self.stats.rx_msgs.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .rx_bytes
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
            }
            Dir::Tx => {
                self.stats.tx_msgs.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .tx_bytes
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        }

        // both directions are classified: once forwarding exists, outbound
        // bytes are the upstream's, not ours, and a ServerHello is as worth
        // naming as a ClientHello
        let hint = crate::classify::classify(data);

        let now = ts::now_millis();
        let tags = format!(
            "{}{}",
            rule.map(|r| format!(" [{r}]")).unwrap_or_default(),
            hint.as_deref().map(|h| format!("  {h}")).unwrap_or_default(),
        );
        // one write, not two: a header and its hexdump printed separately can
        // interleave with another connection's output and produce a dump whose
        // rows belong to two different streams.
        if self.opts.console != ConsoleMode::None {
            let head = format!(
                "[{}] {} #{conn} {proto} {peer} {} bytes{tags}",
                ts::clock(now),
                dir.arrow(),
                data.len(),
            );
            let body = match self.opts.console {
                ConsoleMode::Summary | ConsoleMode::None => String::new(),
                ConsoleMode::Ascii => {
                    format!("\n  {}", hexdump::ascii_line(data, self.opts.max_console_bytes))
                }
                ConsoleMode::Hex => {
                    let d = hexdump::render(data, self.opts.max_console_bytes, "  ");
                    format!("\n{}", d.trim_end_matches('\n'))
                }
            };
            println!("{head}{body}");
        }

        self.raw_write(conn, proto, peer, dir, data);

        // events.jsonl is the index; the .bin files are the full-fidelity copy
        let clipped = self.opts.jsonl_max_data > 0 && data.len() > self.opts.jsonl_max_data;
        let payload = if clipped { &data[..self.opts.jsonl_max_data] } else { data };

        self.emit(&Event {
            ts: ts::iso8601(now),
            ts_ms: now,
            event: "data",
            proto,
            listener: Some(name),
            conn: Some(conn),
            local: None,
            peer: Some(peer),
            orig_dst: None,
            dir: Some(dir.tag()),
            hint: hint.as_deref(),
            len: Some(data.len()),
            rule,
            note: None,
            data: Some(B64.encode(payload)),
            data_truncated: clipped.then_some(true),
        });
    }

    pub fn close(&self, proto: &str, name: &str, conn: u64, peer: &str, why: &str) {
        let now = ts::now_millis();
        if self.opts.console != ConsoleMode::None {
            println!("[{}] close   #{conn} {proto} {peer} ({why})", ts::clock(now));
        }
        self.close_raw(conn, proto, name, peer);
        self.emit(&Event {
            ts: ts::iso8601(now),
            ts_ms: now,
            event: "close",
            proto,
            listener: Some(name),
            conn: Some(conn),
            local: None,
            peer: Some(peer),
            orig_dst: None,
            dir: None,
            hint: None,
            len: None,
            rule: None,
            note: Some(why),
            data: None,
            data_truncated: None,
        });
    }

    /// operational warning: printed and recorded, but nothing stops.
    pub fn warn(&self, proto: &str, name: &str, msg: &str) {
        let now = ts::now_millis();
        // the default listener name already carries the proto, e.g. "udp:0"
        eprintln!("[{}] WARNING {name}: {msg}", ts::clock(now));
        self.emit(&Event {
            ts: ts::iso8601(now),
            ts_ms: now,
            event: "warning",
            proto,
            listener: Some(name),
            conn: None,
            local: None,
            peer: None,
            orig_dst: None,
            dir: None,
            hint: None,
            len: None,
            rule: None,
            note: Some(msg),
            data: None,
            data_truncated: None,
        });
    }

    pub fn error(&self, proto: &str, name: &str, conn: Option<u64>, msg: &str) {
        let now = ts::now_millis();
        eprintln!("[{}] error   {proto} {name} {msg}", ts::clock(now));
        self.emit(&Event {
            ts: ts::iso8601(now),
            ts_ms: now,
            event: "error",
            proto,
            listener: Some(name),
            conn,
            local: None,
            peer: None,
            orig_dst: None,
            dir: None,
            hint: None,
            len: None,
            rule: None,
            note: Some(msg),
            data: None,
            data_truncated: None,
        });
    }

    /// finish every stream still open at shutdown. connections live at ctrl-c
    /// would otherwise lose their buffered head bytes and never get a tail file.
    pub fn flush(&self) {
        let open: Vec<_> = {
            let Ok(mut s) = self.sinks.lock() else { return };
            let drained: Vec<_> = s.raw.drain().collect();
            if let Some(w) = s.jsonl.as_mut() {
                let _ = w.flush();
            }
            drained
        };
        // a connection still live at ctrl-c must report its gap too, otherwise
        // the loudest truncations (long-running streams) are the quietest
        for ((conn, dir), st) in open {
            let sum = st.finish();
            if sum.dropped > 0 {
                println!(
                    "[{}] TRUNC   #{conn} {dir} truncated: {} of {} kept, {} dropped",
                    ts::clock(ts::now_millis()),
                    stream::human(sum.head + sum.tail as u64),
                    stream::human(sum.total),
                    stream::human(sum.dropped),
                );
            }
        }
    }

    pub fn summary(&self) {
        let s = &self.stats;
        println!(
            "\nconns {}  rx {} msgs / {} bytes  tx {} msgs / {} bytes",
            s.conns.load(Ordering::Relaxed),
            s.rx_msgs.load(Ordering::Relaxed),
            s.rx_bytes.load(Ordering::Relaxed),
            s.tx_msgs.load(Ordering::Relaxed),
            s.tx_bytes.load(Ordering::Relaxed),
        );
        if self.writes_files() {
            println!(
                "capture: {} ({} written)",
                self.run_dir.display(),
                stream::human(self.disk_used.load(Ordering::Relaxed))
            );
        }
        if self.disk_stopped.load(Ordering::Relaxed) {
            println!(
                "WARNING: the {} run cap was hit, so this capture is incomplete on disk",
                stream::human(self.opts.max_run_bytes)
            );
        }
    }
}
