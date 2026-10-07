use crate::io::iso8601;
use hampp_core::{Status, Verdict};
use std::process::ExitCode;

pub fn exit_for(v: &Verdict) -> ExitCode {
    ExitCode::from(match v.status {
        Status::Authenticated => 0,
        Status::Unverified => 10,
        Status::Invalid => 20,
    })
}

pub fn print_human(v: &Verdict) {
    let result = match v.status {
        Status::Authenticated => format!(
            "AUTHENTICATED ({})",
            v.level.map(|l| l.as_str()).unwrap_or("none")
        ),
        Status::Unverified => format!(
            "UNVERIFIED ({})",
            v.reason.map(|r| r.code()).unwrap_or("unknown")
        ),
        Status::Invalid => format!(
            "INVALID ({})",
            v.reason.map(|r| r.code()).unwrap_or("unknown")
        ),
    };
    println!("Result:       {result}");
    if let Some(h) = &v.header {
        println!("Protocol:     HAMPP/1");
        println!("Key ID:       {}", hex::encode(h.key_id));
        if let Some(a) = v.key.as_ref().and_then(|k| k.agent_id.as_ref()) {
            println!("Agent:        {a} (from registry)");
        }
        if let Some(t) = v.key.as_ref().and_then(|k| k.trust) {
            println!("Trust:        {t:?}");
        }
        if h.session_id == [0; 8] {
            println!("Session:      none (lite)");
        } else {
            println!("Session:      {}", hex::encode(h.session_id));
            println!("Sequence:     {}", h.seq);
        }
        println!("Timestamp:    {} ({})", h.timestamp, iso8601(h.timestamp));
    }
    match v.protection {
        Some(p) => println!(
            "Protection:   {}{}",
            p.level.label(),
            if p.claimed && p.level > hampp_core::Protection::Software {
                " (claimed, not verified)"
            } else {
                ""
            }
        ),
        None => println!("Protection:   unknown (no authenticated message)"),
    }
    for n in &v.notes {
        println!("Note:         {n}");
    }
}
