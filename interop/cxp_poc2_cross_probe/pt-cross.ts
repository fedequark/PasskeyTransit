// Copy into pinned cxp_poc2/src/cli and run with its pinned tsx installation.
// The second importer is executed unchanged; this adapter only supplies a
// synthetic source, its recipient key, and cxporter output.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { readZip } from "../crypto/archive.js";
import { generateKeyPair, MTI_SUITE, serializePublicKey } from "../crypto/hpke.js";
import { openPayload, sealPayload, INDEX_PATH } from "../cxp/payload.js";
import { parseExportResponseJson } from "../cxp/schema.js";
import { encodeB64url, decodeB64url, isPasskey, parseCxfHeader } from "../cxf/index.js";
import { getPolicy } from "../policy/index.js";

const binary = process.argv[2];
if (!binary) throw new Error("cxporter probe binary path required");
const input = JSON.parse(readFileSync(0, "utf8"));
const policy = getPolicy("spec-minimal");
const document = parseCxfHeader(input, policy);
const recipientKey = await generateKeyPair(MTI_SUITE.kem);
const recipientPublicKey = new Uint8Array(await serializePublicKey(MTI_SUITE.kem, recipientKey.publicKey));
const binding = { policy, info: new Uint8Array(0), requestDigest: new Uint8Array(32) };
const own = await sealPayload({ header: document, suite: MTI_SUITE, recipientPublicKey: recipientKey.publicKey, binding });
const ownOpened = await openPayload({
  archive: own.archive, suite: MTI_SUITE, recipientKey, enc: own.enc, binding,
});
if (ownOpened.accounts.flatMap((account) => account.items).length !==
    document.accounts.flatMap((account) => account.items).length) {
  throw new Error("second implementation's own positive control failed");
}
const sourcePasskey = document.accounts.flatMap((account) => account.items)
  .flatMap((item) => item.credentials).find(isPasskey);
const ownPasskey = ownOpened.accounts.flatMap((account) => account.items)
  .flatMap((item) => item.credentials).find(isPasskey);
if (!sourcePasskey || !ownPasskey ||
    ["credentialId", "rpId", "key", "userHandle", "fido2Extensions"].some(
      (field) => JSON.stringify(sourcePasskey[field as keyof typeof sourcePasskey]) !==
        JSON.stringify(ownPasskey[field as keyof typeof ownPasskey]),
    )) {
  throw new Error("second implementation's self-import changed passkey state");
}

const output = execFileSync(binary, [], {
  input: JSON.stringify({ recipientPublicKey: encodeB64url(recipientPublicKey), cxf: document }),
  maxBuffer: 2 << 20,
});
const response = JSON.parse(output.toString("utf8"));
let responseSchemaRejected = false;
let responseSchemaError = "";
try {
  parseExportResponseJson(JSON.stringify(response));
} catch (error) {
  responseSchemaRejected = true;
  responseSchemaError = error instanceof Error ? error.name + ": " + error.message : String(error);
}
const archive = decodeB64url(response.payload);
const index = readZip(archive).get(INDEX_PATH);
if (!index) throw new Error("cxporter archive index absent");
const protectedPart = new TextDecoder().decode(index).split(".")[0];
if (!protectedPart) throw new Error("cxporter index JWE header absent");
const header = JSON.parse(new TextDecoder().decode(decodeB64url(protectedPart)));
const enc = decodeB64url(header.epk.x);
let rejected = false;
let rejection = "";
try {
  await openPayload({ archive, suite: MTI_SUITE, recipientKey, enc, binding });
} catch (error) {
  rejected = true;
  rejection = error instanceof Error ? error.name + ": " + error.message : String(error);
}
console.log(JSON.stringify({
  second_source_commit: "fee19d9ac392ffe0153bea8b917aa0a66f12b272",
  self_import_items: ownOpened.accounts.flatMap((account) => account.items).length,
  self_import_passkey_state_preserved: true,
  cross_import_rejected: rejected,
  cross_import_error: rejection,
  cxporter_jwe_alg: header.alg,
  response_archive_field_present: "archive" in response,
  response_schema_rejected: responseSchemaRejected,
  response_schema_error: responseSchemaError,
  cxporter_archive_sha256: createHash("sha256").update(archive).digest("hex"),
}));
if (!rejected) throw new Error("cross importer unexpectedly accepted cxporter export");
