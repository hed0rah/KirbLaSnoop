//! head-plus-tail capture files.
//!
//! a pure ring buffer keeps the newest bytes, which is the wrong half for
//! reverse engineering: banners, handshakes and framing headers all live at
//! the front of a stream. a pure head cap keeps those but loses whatever was
//! happening most recently. so we keep both ends and drop the middle.
//!
//! the two ends go to two files, never concatenated. a single .bin with a
//! silent hole in it would be parsed as contiguous and would invent a protocol
//! layout out of bytes that were never adjacent.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Default)]
pub struct Limits {
    /// bytes kept at the front of the stream; 0 means unlimited
    pub head: u64,
    /// bytes kept at the end of the stream; 0 disables the tail file
    pub tail: usize,
}

impl Limits {
    pub fn unlimited(&self) -> bool {
        self.head == 0
    }
}

pub struct Stream {
    head: Option<BufWriter<File>>,
    tail_path: PathBuf,
    head_written: u64,
    tail: VecDeque<u8>,
    limits: Limits,
    total: u64,
    dropped: u64,
    truncating: bool,
}

/// what actually landed on disk for one direction of one connection.
pub struct Summary {
    pub total: u64,
    pub head: u64,
    pub tail: usize,
    pub dropped: u64,
    /// present only when bytes actually landed in the tail file
    pub tail_path: Option<PathBuf>,
}

impl Stream {
    pub fn create(head_path: PathBuf, tail_path: PathBuf, limits: Limits) -> std::io::Result<Self> {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(head_path)?;
        Ok(Self {
            head: Some(BufWriter::new(f)),
            tail_path,
            head_written: 0,
            tail: VecDeque::new(),
            limits,
            total: 0,
            dropped: 0,
            truncating: false,
        })
    }

    /// returns true exactly once: on the write that first exceeds the head cap.
    /// the caller uses that to announce the truncation rather than let it pass
    /// silently.
    pub fn write(&mut self, data: &[u8]) -> bool {
        self.total += data.len() as u64;
        let mut rest = data;

        if self.limits.unlimited() {
            if let Some(w) = self.head.as_mut() {
                let _ = w.write_all(rest);
            }
            self.head_written += rest.len() as u64;
            return false;
        }

        let room = self.limits.head.saturating_sub(self.head_written);
        if room > 0 {
            let n = (room as usize).min(rest.len());
            if let Some(w) = self.head.as_mut() {
                let _ = w.write_all(&rest[..n]);
            }
            self.head_written += n as u64;
            rest = &rest[n..];
        }
        if rest.is_empty() {
            return false;
        }

        let first = !self.truncating;
        self.truncating = true;

        let cap = self.limits.tail;
        if cap == 0 {
            self.dropped += rest.len() as u64;
            return first;
        }
        if rest.len() >= cap {
            // this write alone overruns the ring; keep only its last `cap` bytes
            self.dropped += self.tail.len() as u64 + (rest.len() - cap) as u64;
            self.tail.clear();
            self.tail.extend(&rest[rest.len() - cap..]);
        } else {
            let overflow = (self.tail.len() + rest.len()).saturating_sub(cap);
            self.tail.drain(..overflow);
            self.dropped += overflow as u64;
            self.tail.extend(rest);
        }
        first
    }

    pub fn finish(mut self) -> Summary {
        if let Some(mut w) = self.head.take() {
            let _ = w.flush();
        }
        let mut tail_path = None;
        if !self.tail.is_empty()
            && let Ok(f) = File::create(&self.tail_path)
        {
            let mut w = BufWriter::new(f);
            let (a, b) = self.tail.as_slices();
            let _ = w.write_all(a);
            let _ = w.write_all(b);
            let _ = w.flush();
            tail_path = Some(self.tail_path.clone());
        }
        Summary {
            total: self.total,
            head: self.head_written,
            tail: self.tail.len(),
            dropped: self.dropped,
            tail_path,
        }
    }
}

/// 1536 -> "1.5K". used in log lines, so it stays short.
pub fn human(n: u64) -> String {
    const UNITS: [(u64, &str); 4] = [
        (1 << 30, "G"),
        (1 << 20, "M"),
        (1 << 10, "K"),
        (1, "B"),
    ];
    for (scale, suffix) in UNITS {
        if n >= scale {
            if scale == 1 {
                return format!("{n}B");
            }
            let whole = n / scale;
            let frac = (n % scale) * 10 / scale;
            return if frac == 0 {
                format!("{whole}{suffix}")
            } else {
                format!("{whole}.{frac}{suffix}")
            };
        }
    }
    "0B".into()
}

/// "8M", "512K", "1G", "4096". case-insensitive, optional trailing B.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("empty size".into());
    }
    let t = t.strip_suffix(['b', 'B']).unwrap_or(t);
    let (digits, mult) = match t.chars().last() {
        Some(c @ ('k' | 'K')) => (&t[..t.len() - c.len_utf8()], 1u64 << 10),
        Some(c @ ('m' | 'M')) => (&t[..t.len() - c.len_utf8()], 1u64 << 20),
        Some(c @ ('g' | 'G')) => (&t[..t.len() - c.len_utf8()], 1u64 << 30),
        _ => (t, 1),
    };
    digits
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("bad size {s:?}, want something like 8M or 512K"))?
        .checked_mul(mult)
        .ok_or_else(|| format!("size {s:?} overflows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("kls-test-{}-{name}", std::process::id()));
        p
    }

    #[test]
    fn sizes_round_trip() {
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert_eq!(parse_size("8M").unwrap(), 8 << 20);
        assert_eq!(parse_size("512k").unwrap(), 512 << 10);
        assert_eq!(parse_size("1GB").unwrap(), 1 << 30);
        assert!(parse_size("").is_err());
        assert!(parse_size("banana").is_err());
    }

    #[test]
    fn human_is_short() {
        assert_eq!(human(0), "0B");
        assert_eq!(human(512), "512B");
        assert_eq!(human(1536), "1.5K");
        assert_eq!(human(1 << 20), "1M");
    }

    #[test]
    fn unlimited_keeps_everything() {
        let h = tmp("unlim.bin");
        let mut s = Stream::create(h.clone(), tmp("unlim.tail.bin"), Limits::default()).unwrap();
        assert!(!s.write(&[7u8; 5000]));
        let sum = s.finish();
        assert_eq!(sum.total, 5000);
        assert_eq!(sum.dropped, 0);
        assert_eq!(std::fs::read(&h).unwrap().len(), 5000);
        let _ = std::fs::remove_file(h);
    }

    #[test]
    fn head_cap_keeps_the_front_and_reports_once() {
        let h = tmp("head.bin");
        let limits = Limits { head: 100, tail: 0 };
        let mut s = Stream::create(h.clone(), tmp("head.tail.bin"), limits).unwrap();
        // first write fits entirely, no announcement
        assert!(!s.write(&[1u8; 60]));
        // this one overruns: announced exactly once
        assert!(s.write(&[2u8; 60]));
        assert!(!s.write(&[3u8; 60]));
        let sum = s.finish();
        assert_eq!(sum.head, 100);
        assert_eq!(sum.dropped, 80);
        assert_eq!(sum.total, 180);
        let got = std::fs::read(&h).unwrap();
        assert_eq!(got.len(), 100);
        assert_eq!(&got[..60], &[1u8; 60]); // the front survived
        let _ = std::fs::remove_file(h);
    }

    #[test]
    fn tail_keeps_the_most_recent_bytes() {
        let h = tmp("tail.bin");
        let t = tmp("tail.tail.bin");
        let limits = Limits { head: 10, tail: 16 };
        let mut s = Stream::create(h.clone(), t.clone(), limits).unwrap();
        // 0..=255 in one go
        let data: Vec<u8> = (0..=255u8).collect();
        s.write(&data);
        let sum = s.finish();
        assert_eq!(sum.head, 10);
        assert_eq!(sum.tail, 16);
        assert_eq!(sum.dropped, 256 - 10 - 16);
        assert_eq!(std::fs::read(&h).unwrap(), (0..10u8).collect::<Vec<_>>());
        // the tail file holds the final 16 bytes, contiguous and in order
        assert_eq!(std::fs::read(&t).unwrap(), (240..=255u8).collect::<Vec<_>>());
        let _ = std::fs::remove_file(h);
        let _ = std::fs::remove_file(t);
    }

    #[test]
    fn tail_ring_evicts_across_many_small_writes() {
        let h = tmp("ring.bin");
        let t = tmp("ring.tail.bin");
        let limits = Limits { head: 4, tail: 8 };
        let mut s = Stream::create(h.clone(), t.clone(), limits).unwrap();
        for i in 0..20u8 {
            s.write(&[i]);
        }
        let sum = s.finish();
        assert_eq!(sum.total, 20);
        assert_eq!(sum.head, 4);
        assert_eq!(sum.tail, 8);
        assert_eq!(sum.dropped, 8);
        assert_eq!(std::fs::read(&t).unwrap(), (12..20u8).collect::<Vec<_>>());
        let _ = std::fs::remove_file(h);
        let _ = std::fs::remove_file(t);
    }

    #[test]
    fn no_tail_file_when_nothing_was_truncated() {
        let h = tmp("clean.bin");
        let t = tmp("clean.tail.bin");
        let _ = std::fs::remove_file(&t);
        let limits = Limits { head: 1000, tail: 16 };
        let mut s = Stream::create(h.clone(), t.clone(), limits).unwrap();
        s.write(b"short");
        let sum = s.finish();
        assert!(sum.tail_path.is_none());
        assert!(!t.exists());
        let _ = std::fs::remove_file(h);
    }
}
