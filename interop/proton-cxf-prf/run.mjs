import fs from 'node:fs';
import * as proton from '@protontech/pass-rust-core/worker/proton_pass_web.js';

const b64 = bytes => Buffer.from(bytes).toString('base64url');

function firstPasskey(vaults) {
  for (const vault of vaults) {
    for (const item of vault.items) {
      const passkey = item.content?.Login?.passkeys?.[0];
      if (passkey) return passkey;
    }
  }
  throw new Error('no imported passkey');
}

function exportInput(imported) {
  return {
    vaults: imported.vaults.map(vault => ({
      vault: vault.vault ?? {
        name: 'Synthetic', description: '',
        display_preferences: { icon: 'Unspecified', color: 'Unspecified' },
      },
      items: vault.items.map(item => ({
        item,
        metadata: { created_at: 0, modified_at: 0, pinned: false },
      })),
    })),
    exporter_rp_id: 'proton-pass.example.test',
    exporter_display_name: 'Proton Pass',
    timestamp: 1790899200,
  };
}

async function observe(passkey, origin, rpId, credentialId, salt, challenge) {
  const request = {
    challenge,
    rpId,
    allowCredentials: [{ type: 'public-key', id: credentialId }],
    userVerification: 'required',
    extensions: { prf: { eval: { first: salt } } },
  };
  const result = await proton.resolve_passkey_challenge(
    origin, Uint8Array.from(passkey.content), JSON.stringify(request), false,
  );
  const assertion = result.credential;
  return {
    raw_id: b64(assertion.raw_id),
    client_data_json: b64(assertion.response.client_data_json),
    authenticator_data: b64(assertion.response.authenticator_data),
    signature: b64(assertion.response.signature),
    prf_first: b64(assertion.client_extension_results?.prf?.results?.first ?? []),
  };
}

async function main() {
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  if (input.salts.length * 2 !== input.challenges.length) throw new Error('challenge count mismatch');
  const sourceDoc = JSON.parse(input.document);
  const sourceCredential = sourceDoc.accounts.flatMap(a => a.items.flatMap(i => i.credentials))
    .find(c => c.type === 'passkey');
  if (!sourceCredential) throw new Error('source passkey missing');
  const imported = proton.cxf_import(input.document);
  const sourceKey = firstPasskey(imported.vaults);
  const exported = proton.cxf_export(exportInput(imported));
  const reimported = proton.cxf_import(exported.payload);
  const destinationKey = firstPasskey(reimported.vaults);
  const observations = [];
  for (let i = 0; i < input.salts.length; i++) {
    observations.push({
      source: await observe(sourceKey, input.origin, sourceCredential.rpId,
        sourceCredential.credentialId, input.salts[i], input.challenges[2 * i]),
      destination: await observe(destinationKey, input.origin, sourceCredential.rpId,
        sourceCredential.credentialId, input.salts[i], input.challenges[2 * i + 1]),
    });
  }
  process.stdout.write(JSON.stringify({
    version: proton.library_version(),
    import_warnings: imported.warnings.map(w => w.kind),
    export_warnings: exported.warnings.map(w => w.kind),
    reimport_warnings: reimported.warnings.map(w => w.kind),
    exported_cxf: exported.payload,
    observations,
  }));
}

main().catch(() => {
  process.stderr.write('Proton CXF/PRF adapter failed\n');
  process.exitCode = 1;
});
