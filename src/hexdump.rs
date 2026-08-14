//! classic offset / hex / ascii dump.

use std::fmt::Write as _;

/// render `data`, stopping after `max` bytes (0 = unlimited).
pub fn render(data: &[u8], max: usize, indent: &str) -> String {
    let limit = if max == 0 { data.len() } else { data.len().min(max) };
    let mut out = String::with_capacity(limit / 16 * 80 + 32);

    for (row, chunk) in data[..limit].chunks(16).enumerate() {
        let _ = write!(out, "{indent}{:08x}  ", row * 16);
        for i in 0..16 {
            match chunk.get(i) {
                Some(b) => {
                    let _ = write!(out, "{b:02x} ");
                }
                None => out.push_str("   "),
            }
            if i == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        for b in chunk {
            out.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        out.push_str("|\n");
    }

    if limit < data.len() {
        let _ = writeln!(out, "{indent}... {} more bytes", data.len() - limit);
    }
    out
}

/// printable-only single line, control bytes escaped. for `--console ascii`.
pub fn ascii_line(data: &[u8], max: usize) -> String {
    let limit = if max == 0 { data.len() } else { data.len().min(max) };
    let mut out = String::with_capacity(limit + 8);
    for b in &data[..limit] {
        match b {
            b'\r' => out.push_str("\\r"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(*b as char),
            _ => {
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    if limit < data.len() {
        let _ = write!(out, " ...(+{})", data.len() - limit);
    }
    out
}
