//! Independent Proton Pass common 2.0.0 exporter boundary for a synthetic CXP wire test.
//! Reads an export request from stdin and emits its encrypted response on stdout.

use std::io::{self, Read, Write};

use proton_pass_common::cxf::{CxfExportInput, CxfVaultWithItems, ItemMetadata, ItemWithMetadata};
use proton_pass_common::cxp::{CxpCredentialType, CxpExportHandler, CxpExportRequest, CxpImportHandler};
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
    if std::env::args().any(|arg| arg == "--import") {
        let importer = CxpImportHandler::new();
        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "PasskeyTransit synthetic importer".to_string(),
                supported_credential_types: vec![CxpCredentialType::Passkey],
            })
            .map_err(|e| format!("Proton CXP request: {e:?}"))?;
        writeln!(io::stdout(), "{request}")?;
        io::stdout().flush()?;
        let mut response = Vec::new();
        io::stdin().read_to_end(&mut response)?;
        let imported = importer
            .process_export_response(&response)
            .map_err(|e| format!("Proton CXP import: {e:?}"))?;
        let passkey_count: usize = imported
            .vaults
            .iter()
            .flat_map(|vault| &vault.items)
            .map(|item| match &item.content {
                ItemContent::Login(login) => login.passkeys.len(),
                _ => 0,
            })
            .sum();
        let summary = serde_json::json!({
            "vault_count": imported.vaults.len(),
            "passkey_count": passkey_count,
            "warning_count": imported.warnings.len(),
        });
        writeln!(io::stdout(), "{summary}")?;
        return Ok(());
    }
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let (request, export) = if input.trim_start().starts_with("{\"cxp_request\":") {
        let wrapper: serde_json::Value = serde_json::from_str(&input)?;
        let request = wrapper["cxp_request"].as_str().ok_or("missing cxp_request")?.to_string();
        let cxf = wrapper["cxf"].as_str().ok_or("missing cxf")?;
        let imported = proton_pass_common::cxf::import_cxf(cxf)
            .map_err(|e| format!("Proton CXF import: {e:?}"))?;
        let vaults = imported
            .vaults
            .into_iter()
            .map(|entry| CxfVaultWithItems {
                vault: entry.vault.unwrap_or_else(|| {
                    VaultData::new(
                        "Synthetic vault".to_string(),
                        String::new(),
                        VaultDisplayPreferences::default(),
                    )
                    .expect("synthetic vault")
                }),
                items: entry
                    .items
                    .into_iter()
                    .map(|item| ItemWithMetadata {
                        item,
                        metadata: ItemMetadata {
                            created_at: 0,
                            modified_at: 0,
                            pinned: false,
                        },
                    })
                    .collect(),
            })
            .collect();
        (
            request,
            CxfExportInput {
                vaults,
                exporter_rp_id: "passkeytransit.example.test".to_string(),
                exporter_display_name: "Proton Pass synthetic exporter".to_string(),
                timestamp: 1_700_000_000,
            },
        )
    } else {
        (input, synthetic_export())
    };
    let response = CxpExportHandler::new()
        .create_export_response(&request, export)
        .map_err(|e| format!("Proton CXP export: {e:?}"))?;
    io::stdout().write_all(&response.response)?;
    Ok(())
}
