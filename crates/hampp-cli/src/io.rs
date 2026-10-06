use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub type Res<T> = Result<T, Box<dyn std::error::Error>>;

pub fn read_input(file: &Option<PathBuf>) -> Res<String> {
    let mut s = String::new();
    match file {
        Some(p) => s = read_file(p)?,
        None => {
            std::io::stdin().read_to_string(&mut s)?;
        }
    }
    Ok(s)
}

/// Reads a text file; errors name the path.
pub fn read_file(p: &Path) -> Res<String> {
    Ok(std::fs::read_to_string(p).map_err(hampp_core::io_ctx(p))?)
}

/// Writes a state file atomically; errors name the path.
pub fn write_state(p: &Path, content: &str) -> Res<()> {
    hampp_core::write_atomic(p, content.as_bytes()).map_err(hampp_core::io_ctx(p))?;
    Ok(())
}

/// Unix seconds; `HAMPP_NOW` overrides it for deterministic tests.
pub fn now() -> u64 {
    if let Ok(v) = std::env::var("HAMPP_NOW") {
        if let Ok(n) = v.parse() {
            return n;
        }
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn iso8601_known_values() {
        assert_eq!(super::iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::iso8601(1_791_000_000), "2026-10-03T04:00:00Z");
    }
}
