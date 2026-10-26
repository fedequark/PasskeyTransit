/** Project adapter: cxporter ciphertext -> project Python decryptor -> PoC vault/RP. */
import assert from "node:assert/strict";
import { createPrivateKey } from "node:crypto";
import { execFileSync } from "node:child_process";
import { encodeB64url, decodeB64url, isPasskey, parseCxfHeader } from "../cxf/index.js";
import { getPolicy } from "../policy/index.js";
import { ExportingProvider } from "../provider/exporter.js";
import { createWorld } from "../scenario/world.js";

const [python, helper, binary] = process.argv.slice(2);
assert.ok(python && helper && binary);
const world = await createWorld(getPolicy("spec-minimal"));
try {
  const registration = await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
  assert.equal(registration.body.verified, true);
  const sourceLogin = await world.rpClient.login(world.providerA.authenticator, "alice");
  assert.equal(sourceLogin.body.verified, true);
  const record = world.providerA.vault.list()[0];
  assert.ok(record);
  const source = parseCxfHeader({
    version: { major: 1, minor: 0 },
    exporterRpId: "provider-a.example", exporterDisplayName: "Provider A",
    timestamp: Math.floor(Date.now() / 1000),
    accounts: [{ id: world.providerA.exporter.accountId, username: "alice",
      email: "alice@example.test", collections: [], items: [{
        id: record.itemId, title: record.rpId,
        credentials: [ExportingProvider.toCxfPasskey(record)],
      }] }],
  }, getPolicy("spec-minimal"));
  const raw = execFileSync(python, [helper, binary], {
    input: JSON.stringify(source), maxBuffer: 2 << 20,
  });
  const imported = JSON.parse(raw.toString("utf8"));
  assert.equal(imported.response_has_archive, false);
  const recovered = parseCxfHeader(imported.recovered, getPolicy("spec-minimal"));
  const passkey = recovered.accounts[0]?.items[0]?.credentials[0];
  assert.ok(passkey && isPasskey(passkey));
  const sourcePasskey = source.accounts[0]?.items[0]?.credentials[0];
  assert.ok(sourcePasskey && isPasskey(sourcePasskey));
  for (const field of ["credentialId", "rpId", "userHandle", "key"] as const) {
    assert.equal(passkey[field], sourcePasskey[field]);
  }
  // This line is the project-authored import adapter, not PoC importResponse.
  world.providerB.vault.add({
    itemId: record.itemId,
    credentialId: decodeB64url(passkey.credentialId), rpId: passkey.rpId,
    userHandle: decodeB64url(passkey.userHandle), username: passkey.username,
    userDisplayName: passkey.userDisplayName,
    privateKey: createPrivateKey({ key: Buffer.from(passkey.key, "base64url"), format: "der", type: "pkcs8" }),
    signCount: 0, backupEligible: true, backupState: true,
    createdAt: record.createdAt,
  });
  const targetLogin = await world.rpClient.login(world.providerB.authenticator, "alice");
  assert.equal(targetLogin.body.verified, true);
  assert.equal(targetLogin.body.credentialId, sourceLogin.body.credentialId);
  assert.equal(encodeB64url(record.credentialId), targetLogin.body.credentialId);
  console.log(JSON.stringify({
    status: "ADAPTER_RP_CONTROL_PASS", archive_sha256: imported.archive_sha256,
    response_has_archive: false, project_adapter_inserted_records: world.providerB.vault.size,
    rp_verified_before_and_after: true, same_credential_id: true,
    limitation: "project Python decryptor and direct vault insertion; PoC CXP importer not called",
  }));
} finally {
  await world.close();
}
