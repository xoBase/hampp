use hampp_envelope::{strip_all, DEFAULT};
use unicode_normalization::UnicodeNormalization;

fn is_invisible(c: char) -> bool {
    matches!(c as u32, 0x00AD | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0xFEFF)
}

fn html_roundtrip(t: &str) -> String {
    let esc = t
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;");
    esc.replace("&#39;", "'")
        .replace("&quot;", "\"")
        .replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&amp;", "&")
}

fn markdown_text(t: &str) -> String {
    use pulldown_cmark::{Event, Parser, TagEnd};
    let mut out = String::new();
    for ev in Parser::new(t) {
        match ev {
            Event::Text(s) | Event::Code(s) => out.push_str(&s),
            Event::SoftBreak | Event::HardBreak => out.push('\n'),
            Event::End(TagEnd::Paragraph) => out.push_str("\n\n"),
            _ => {}
        }
    }
    out
}

/// Applies one named transport transformation: `name` or `name:arg`.
/// Names: none, strip_zw, sanitize_invisible, nfc, nfd, nfkc, nfkd, json, html,
/// markdown, trim, crlf, truncate_tail:N, drop_zw:N, replace:old=new.
pub fn apply(spec: &str, text: &str) -> Result<String, String> {
    let (name, arg) = match spec.split_once(':') {
        Some((n, a)) => (n, Some(a)),
        None => (spec, None),
    };
    let num = |a: Option<&str>| -> Result<usize, String> {
        a.ok_or_else(|| format!("{name} needs :N"))?
            .parse::<usize>()
            .map_err(|e| e.to_string())
    };
    match name {
        "none" => Ok(text.to_string()),
        "strip_zw" => Ok(strip_all(&DEFAULT, text)),
        "sanitize_invisible" => Ok(text.chars().filter(|c| !is_invisible(*c)).collect()),
        "nfc" => Ok(text.nfc().collect()),
        "nfd" => Ok(text.nfd().collect()),
        "nfkc" => Ok(text.nfkc().collect()),
        "nfkd" => Ok(text.nfkd().collect()),
        "json" => {
            let s = serde_json::to_string(text).map_err(|e| e.to_string())?;
            serde_json::from_str(&s).map_err(|e| e.to_string())
        }
        "html" => Ok(html_roundtrip(text)),
        "markdown" => Ok(markdown_text(text)),
        "trim" => Ok(format!("{text}\n")),
        "crlf" => Ok(format!("{}\r\n", text.replace('\n', "\r\n"))),
        "truncate_tail" => {
            let n = num(arg)?;
            let count = text.chars().count();
            Ok(text.chars().take(count.saturating_sub(n)).collect())
        }
        "drop_zw" => {
            let n = num(arg)?;
            let mut seen = 0usize;
            Ok(text
                .chars()
                .filter(|c| {
                    if DEFAULT.is_member(*c) {
                        let keep = seen != n;
                        seen += 1;
                        keep
                    } else {
                        true
                    }
                })
                .collect())
        }
        "replace" => {
            let (old, new) = arg
                .and_then(|a| a.split_once('='))
                .ok_or_else(|| "replace needs :old=new".to_string())?;
            Ok(text.replace(old, new))
        }
        other => Err(format!("unknown transport '{other}'")),
    }
}
