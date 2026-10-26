use credential_exchange_protocol::{ExportRequest, ExportResponse};
use serde_json::{json, Value};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixture_path = std::env::args().nth(1).ok_or("fixture path required")?;
    let fixture: Value = serde_json::from_slice(&fs::read(fixture_path)?)?;
    let request_input = fixture["request"].clone();
    let response_input = fixture["response"].clone();
    // B64Url's deserializer borrows from the JSON input; from_value cannot
    // provide that borrowed representation.
    let request_json = request_input.to_string();
    let response_json = response_input.to_string();
    let request: ExportRequest = serde_json::from_str(&request_json)?;
    let response: ExportResponse = serde_json::from_str(&response_json)?;
    let request_output = serde_json::to_value(request)?;
    let response_output = serde_json::to_value(response)?;

    let request_dropped: Vec<&str> = ["archive", "mode"]
        .into_iter()
        .filter(|field| request_input.get(field).is_some() && request_output.get(field).is_none())
        .collect();
    let response_dropped: Vec<&str> = ["archive"]
        .into_iter()
        .filter(|field| response_input.get(field).is_some() && response_output.get(field).is_none())
        .collect();
    let mut wide_version = request_input.clone();
    wide_version["version"] = json!(256);
    let version_256_rejected = serde_json::from_str::<ExportRequest>(&wide_version.to_string()).is_err();

    println!("{}", serde_json::to_string_pretty(&json!({
        "source_commit": "32da4c8b0a4abdd0b46fae79c31e0fdb50150396",
        "scope": "Bitwarden open Rust CXP type deserialization and serialization only",
        "request_parse": "PASS",
        "response_parse": "PASS",
        "request_fields_dropped_on_roundtrip": request_dropped,
        "response_fields_dropped_on_roundtrip": response_dropped,
        "draft_valid_version_256_rejected": version_256_rejected,
        "hpke_jwe_decryption": "NOT_EVALUABLE",
        "provider_interoperability": "NOT_EVALUABLE"
    }))?);
    Ok(())
}
