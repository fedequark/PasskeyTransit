//! Independent Proton Pass common 2.0.0 exporter boundary for a synthetic CXP wire test.
//! Reads an export request from stdin and emits its encrypted response on stdout.

use std::io::{self, Read, Write};

use proton_pass_common::cxf::{CxfExportInput, CxfVaultWithItems, ItemMetadata, ItemWithMetadata};
use proton_pass_common::cxp::CxpExportHandler;
use proton_pass_types::{ItemContent, ItemData, LoginItem, VaultData, VaultDisplayPreferences};

fn synthetic_export() -> CxfExportInput {
    let login = LoginItem {
        email: "cxp-synthetic@example.test".to_string(),
        username: String::new(),
        password: "synthetic-password-1".to_string(),
        urls: Vec::new(),
        totp_uri: String::new(),
        passkeys: Vec::new(),
        autofill_urls: Vec::new(),
    };
    let item = ItemData::new(
        "Synthetic login".to_string(),
        String::new(),
        String::new(),
        ItemContent::Login(login),
        Vec::new(),
    )
    .expect("synthetic item");
    let vault = VaultData::new(
        "Synthetic vault".to_string(),
        String::new(),
        VaultDisplayPreferences::default(),
    )
    .expect("synthetic vault");
    CxfExportInput {
        vaults: vec![CxfVaultWithItems {
            vault,
            items: vec![ItemWithMetadata {
                item,
                metadata: ItemMetadata {
                    created_at: 0,
                    modified_at: 0,
                    pinned: false,
                },
            }],
        }],
        exporter_rp_id: "other-app.example".to_string(),
        exporter_display_name: "Proton Pass synthetic exporter".to_string(),
        timestamp: 1_700_000_000,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut request = String::new();
    io::stdin().read_to_string(&mut request)?;
    let response = CxpExportHandler::new()
        .create_export_response(&request, synthetic_export())
        .map_err(|e| format!("Proton CXP export: {e:?}"))?;
    io::stdout().write_all(&response.response)?;
    Ok(())
}
