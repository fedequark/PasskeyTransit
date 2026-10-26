/** Same-codebase positive control: PoC Provider A -> PoC Provider B -> demo RP. */
import assert from "node:assert/strict";
import { getPolicy, type ProfileName } from "../policy/index.js";
import { createWorld, migrate, type MigrationMode } from "../scenario/world.js";

const mode = process.argv[2] as MigrationMode;
const profile = process.argv[3] as ProfileName;
assert.ok(mode === "direct" || mode === "indirect");
assert.ok(profile === "spec-minimal" || profile === "hardened");

const world = await createWorld(getPolicy(profile));
try {
  const registered = await world.rpClient.register(world.providerA.authenticator, "alice", "Alice");
  assert.equal(registered.body.verified, true);
  const before = await world.rpClient.login(world.providerA.authenticator, "alice");
  assert.equal(before.body.verified, true);
  const importReport = await migrate(world, mode);
  assert.equal(importReport.imported.length, 1);
  assert.equal(importReport.skipped.length, 0);
  const after = await world.rpClient.login(world.providerB.authenticator, "alice");
  assert.equal(after.body.verified, true);
  const sourceAgain = await world.rpClient.login(world.providerA.authenticator, "alice");
  assert.equal(sourceAgain.body.verified, true);
  assert.equal(before.body.credentialId, after.body.credentialId);
  assert.equal(sourceAgain.body.credentialId, after.body.credentialId);
  const rpCredentials = world.rp.rp.getUser("alice")?.credentials ?? [];
  assert.equal(rpCredentials.length, 1);
  console.log(JSON.stringify({
    profile, mode, registered: true, source_login_before: true,
    imported_passkeys: importReport.imported.length, skipped: importReport.skipped.length,
    target_login_after: true, source_login_after: true,
    same_credential_id: true, rp_registered_credentials: rpCredentials.length,
    scope: "same-codebase synthetic software authenticators and local demo RP",
  }));
} finally {
  await world.close();
}
