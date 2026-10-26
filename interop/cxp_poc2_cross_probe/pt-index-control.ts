// Copy into pinned cxp_poc2/src/cli. This is an ISOLATED LAYOUT CONTROL:
// seal a valid PoC archive, replace only its index plaintext with the
// decrypted synthetic cxporter index, then call PoC's unchanged openPayload.
// The transformed ZIP is not a cxporter export or an interoperability result.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createZip, readZip } from "../crypto/archive.js";
import { deriveKeyPair, exportSecret, MTI_SUITE, setupRecipient } from "../crypto/hpke.js";
import { encryptJwe } from "../crypto/jwe.js";
import { INDEX_PATH, openPayload, PAYLOAD_KEY_CONTEXT, sealPayload } from "../cxp/payload.js";
import { parseCxfHeader } from "../cxf/index.js";
import { getPolicy } from "../policy/index.js";

const [vectorPath, indexPath] = process.argv.slice(2);
if (!vectorPath || !indexPath) throw new Error("usage: pt-index-control.ts <vector.json> <index.json>");
const vector = JSON.parse(readFileSync(vectorPath, "utf8"));
const extracted = JSON.parse(readFileSync(indexPath, "utf8"));
if (vector.vector_version !== 1 || extracted.vector_version !== 1 ||
    extracted.source_archive_sha256 !== vector.archive_sha256) {
  throw new Error("decrypted index does not match retained ciphertext vector");
}
if (!Array.isArray(extracted.index.accounts) ||
    "header" in extracted.index || "documents" in extracted.index) {
  throw new Error("source index no longer has the expected contrasting layout");
}
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const ikm = new Uint8Array(createHash("sha256").update("PasskeyTransit public CXP vector v1").digest());
const recipientKey = await deriveKeyPair(MTI_SUITE.kem, ikm);
const policy = getPolicy("spec-minimal");
const binding = { policy, info: new Uint8Array(0), requestDigest: new Uint8Array(32) };
const document = parseCxfHeader(vector.cxf, policy);
const own = await sealPayload({
  header: document, suite: MTI_SUITE,
  recipientPublicKey: recipientKey.publicKey, binding,
});
const ownOpened = await openPayload({
  archive: own.archive, suite: MTI_SUITE, recipientKey, enc: own.enc, binding,
});
const sourceItems = document.accounts.flatMap((account) => account.items);
const ownItems = ownOpened.accounts.flatMap((account) => account.items);
if (sourceItems.length !== 1 || ownItems.length !== 1 ||
    JSON.stringify(sourceItems[0]) !== JSON.stringify(ownItems[0])) {
  throw new Error("positive self-import control changed the synthetic item");
}
const context = await setupRecipient({
  suite: MTI_SUITE, recipientKey, enc: own.enc, info: binding.info,
});
const cek = await exportSecret(context, PAYLOAD_KEY_CONTEXT, 32);
const replacement = new TextEncoder().encode(await encryptJwe(
  new TextEncoder().encode(JSON.stringify(extracted.index)), cek, "A256GCM",
));
const files = new Map([...readZip(own.archive)].filter(([name]) => !name.endsWith("/")));
files.set(INDEX_PATH, replacement);
const transformed = createZip(files);
let rejection = "";
try {
  await openPayload({
    archive: transformed, suite: MTI_SUITE, recipientKey, enc: own.enc, binding,
  });
} catch (error) {
  rejection = error instanceof Error ? error.name + ": " + error.message : String(error);
}
console.log(JSON.stringify({
  control: "PoC self-import positive; PoC encrypted index replaced by cxporter index plaintext",
  source_archive_sha256: vector.archive_sha256,
  positive_self_import_items: ownItems.length,
  replacement_index_jwe_alg: "dir",
  transformed_archive_sha256: sha256(transformed),
  importer_error: rejection,
}));
if (!rejection) throw new Error("transformed archive unexpectedly imported");
