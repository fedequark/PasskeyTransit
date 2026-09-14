use credential_exchange_format::Header;
use serde_json::{json, Value};
use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("read stdin");
    let request: Value = serde_json::from_str(&input).expect("parse adapter request");
    if request["adapter_protocol_version"] != 1 || request["operation"] != "cxf-round-trip" {
        println!("{}", json!({"adapter_protocol_version": 1, "status": "FAIL", "error": "unsupported request"}));
        std::process::exit(2);
    }
    // B64Url intentionally borrows during deserialization, so parse from text
    // rather than serde_json::Value's owned-value deserializer.
    let document_text = serde_json::to_string(&request["document"]).expect("serialize embedded CXF");
    let header: Header = serde_json::from_str(&document_text).expect("Bitwarden CXF parse");
    let account_count = header.accounts.len();
    let item_count: usize = header.accounts.iter().map(|account| account.items.len()).sum();
    let credential_count: usize = header.accounts.iter().flat_map(|account| &account.items).map(|item| item.credentials.len()).sum();
    let document = serde_json::to_value(&header).expect("Bitwarden CXF serialize");
    println!("{}", json!({
        "adapter_protocol_version": 1,
        "status": "PASS",
        "document": document,
        "metadata": {
            "implementation": "bitwarden/credential-exchange",
            "crate": "credential-exchange-format",
            "version": "0.4.0",
            "revision": "0ee5516e4c0481ab6b0a68f8541fc39c3c3379b1",
            "accounts": account_count,
            "items": item_count,
            "credentials": credential_count
        }
    }));
}
