//! wall-clock timestamps without pulling in a date crate.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// howard hinnant's civil_from_days: days since 1970-01-01 -> (y, m, d)
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn parts(ms: u64) -> (i64, u32, u32, u32, u32, u32, u32) {
    let secs = (ms / 1000) as i64;
    let sub = (ms % 1000) as u32;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400) as u32;
    let (y, mo, d) = civil_from_days(days);
    (y, mo, d, rem / 3600, (rem % 3600) / 60, rem % 60, sub)
}

/// 2026-08-13T18:40:12.345Z
pub fn iso8601(ms: u64) -> String {
    let (y, mo, d, h, mi, s, sub) = parts(ms);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{sub:03}Z")
}

/// 18:40:12.345 -- console gutter
pub fn clock(ms: u64) -> String {
    let (_, _, _, h, mi, s, sub) = parts(ms);
    format!("{h:02}:{mi:02}:{s:02}.{sub:03}")
}

/// 20260813-184012 -- filename safe
pub fn stamp(ms: u64) -> String {
    let (y, mo, d, h, mi, s, _) = parts(ms);
    format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}")
}
