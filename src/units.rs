//! Formatting counts, sizes, durations, times and tables for the terminal.

use crate::capture::Timestamp;

/// 1234567 → "1,234,567"
pub fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Decimal units, as Wireshark uses them: 1500 → "1.5 kB".
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["kB", "MB", "GB", "TB"];
    if n < 1000 {
        return format!("{n} B");
    }
    let mut value = n as f64 / 1000.0;
    let mut unit = 0;
    while value >= 999.95 && unit + 1 < UNITS.len() {
        value /= 1000.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Bits per second: 8000.0 → "8.0 kbit/s".
pub fn bitrate(bits_per_sec: f64) -> String {
    const UNITS: [&str; 4] = ["kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"];
    if bits_per_sec < 1000.0 {
        return format!("{bits_per_sec:.0} bit/s");
    }
    let mut value = bits_per_sec / 1000.0;
    let mut unit = 0;
    while value >= 999.95 && unit + 1 < UNITS.len() {
        value /= 1000.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

pub fn duration(secs: f64) -> String {
    let secs = secs.max(0.0);
    if secs < 0.001 {
        format!("{:.0} µs", secs * 1e6)
    } else if secs < 1.0 {
        format!("{:.1} ms", secs * 1e3)
    } else if secs < 60.0 {
        format!("{secs:.2} s")
    } else if secs < 3600.0 {
        let whole = secs as u64;
        format!("{}m {:02}s", whole / 60, whole % 60)
    } else {
        let whole = secs as u64;
        format!("{}h {:02}m", whole / 3600, whole % 3600 / 60)
    }
}

/// "30s", "500ms", "2m", "1.5h", or a number of seconds.
pub fn parse_duration(s: &str) -> Option<std::time::Duration> {
    let s = s.trim();
    let end = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let (number, unit) = s.split_at(end);
    let scale = match unit.trim() {
        "" | "s" | "sec" => 1.0,
        "ms" => 1e-3,
        "m" | "min" => 60.0,
        "h" => 3600.0,
        _ => return None,
    };
    let secs = number.parse::<f64>().ok()? * scale;
    (secs > 0.0 && secs < 1e9).then(|| std::time::Duration::from_secs_f64(secs))
}

pub fn percent(part: u64, whole: u64) -> String {
    if whole == 0 {
        return "-".to_string();
    }
    format!("{:.1}%", part as f64 * 100.0 / whole as f64)
}

/// "2026-10-13 09:41:07.250 UTC"
pub fn utc(ts: Timestamp) -> String {
    let secs = ts.0 / 1_000_000_000;
    let millis = ts.0 % 1_000_000_000 / 1_000_000;
    let (year, month, day) = civil_from_days(secs / 86_400);
    let rem = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}.{millis:03} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// "2026-10-13T09:41:07.250000Z"
pub fn rfc3339(ts: Timestamp) -> String {
    let secs = ts.0 / 1_000_000_000;
    let micros = ts.0 % 1_000_000_000 / 1_000;
    let (year, month, day) = civil_from_days(secs / 86_400);
    let rem = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to (year, month, day), from Howard Hinnant's
/// `civil_from_days`: <https://howardhinnant.github.io/date_algorithms.html>
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// The reverse: (year, month, day) to days since 1970-01-01, negative
/// before it. Hinnant's `days_from_civil`.
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = i64::from((month + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// "2026-10-13" for seconds since the Unix epoch.
pub fn date(secs: i64) -> String {
    if secs < 0 {
        return "before 1970".to_string();
    }
    let (year, month, day) = civil_from_days(secs as u64 / 86_400);
    format!("{year:04}-{month:02}-{day:02}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
}

/// A plain-text table with columns sized to fit their contents.
pub struct Table {
    columns: Vec<(String, Align)>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(columns: &[(&str, Align)]) -> Self {
        Table {
            columns: columns
                .iter()
                .map(|(name, align)| (name.to_string(), *align))
                .collect(),
            rows: Vec::new(),
        }
    }

    pub fn row(&mut self, cells: Vec<String>) {
        debug_assert_eq!(cells.len(), self.columns.len());
        self.rows.push(cells);
    }

    pub fn render(&self) -> String {
        let width = |s: &str| s.chars().count();
        let widths: Vec<usize> = (0..self.columns.len())
            .map(|i| {
                let cells = self.rows.iter().map(|r| width(&r[i]));
                cells.chain([width(&self.columns[i].0)]).max().unwrap_or(0)
            })
            .collect();
        let mut out = String::new();
        let header: Vec<&str> = self.columns.iter().map(|(name, _)| name.as_str()).collect();
        for cells in std::iter::once(header).chain(
            self.rows
                .iter()
                .map(|r| r.iter().map(String::as_str).collect()),
        ) {
            let mut line = String::new();
            for (i, cell) in cells.iter().enumerate() {
                if i > 0 {
                    line.push_str("  ");
                }
                let pad = " ".repeat(widths[i] - width(cell));
                match self.columns[i].1 {
                    Align::Left => {
                        line.push_str(cell);
                        line.push_str(&pad);
                    }
                    Align::Right => {
                        line.push_str(&pad);
                        line.push_str(cell);
                    }
                }
            }
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_get_separators() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1000), "1,000");
        assert_eq!(count(1_234_567), "1,234,567");
    }

    #[test]
    fn sizes_and_rates() {
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(1500), "1.5 kB");
        assert_eq!(bytes(999_999), "1.0 MB");
        assert_eq!(bytes(2_500_000_000), "2.5 GB");
        assert_eq!(bitrate(136.4), "136 bit/s");
        assert_eq!(bitrate(8_000_000.0), "8.0 Mbit/s");
    }

    #[test]
    fn durations() {
        assert_eq!(duration(0.000_25), "250 µs");
        assert_eq!(duration(0.0123), "12.3 ms");
        assert_eq!(duration(4.5), "4.50 s");
        assert_eq!(duration(265.0), "4m 25s");
        assert_eq!(duration(7380.0), "2h 03m");
    }

    #[test]
    fn parses_durations() {
        use std::time::Duration;
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("30"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("2m"), Some(Duration::from_secs(120)));
        assert_eq!(parse_duration("1.5h"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_duration("0"), None);
        assert_eq!(parse_duration("10 parsecs"), None);
        assert_eq!(parse_duration("s"), None);
        assert_eq!(parse_duration(""), None);
    }

    #[test]
    fn utc_dates() {
        assert_eq!(utc(Timestamp(0)), "1970-01-01 00:00:00.000 UTC");
        assert_eq!(
            utc(Timestamp(1_700_000_000_123_456_789)),
            "2023-11-14 22:13:20.123 UTC"
        );
        // Leap day.
        assert_eq!(
            utc(Timestamp(1_709_164_800_000_000_000)),
            "2024-02-29 00:00:00.000 UTC"
        );
    }

    #[test]
    fn days_both_ways() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2024, 2, 29), 19_782);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        assert_eq!(date(19_782 * 86_400 + 5), "2024-02-29");
        assert_eq!(date(-5), "before 1970");
    }

    #[test]
    fn table_aligns_columns() {
        let mut t = Table::new(&[("Name", Align::Left), ("Packets", Align::Right)]);
        t.row(vec!["TCP".into(), "1,200".into()]);
        t.row(vec!["UDP → x".into(), "3".into()]);
        assert_eq!(
            t.render(),
            "Name     Packets\nTCP        1,200\nUDP → x        3\n"
        );
    }
}
