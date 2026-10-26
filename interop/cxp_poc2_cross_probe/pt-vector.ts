// Copy into the pinned cxp_poc2/src/cli directory. The imports below call
// the second implementation's original parser, ZIP reader, and importer.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { readZip } from "../crypto/archive.js";
import { deriveKeyPair, MTI_SUITE, serializePublicKey } from "../crypto/hpke.js";
import { openPayload, INDEX_PATH } from "../cxp/payload.js";
import { parseExportResponseJson } from "../cxp/schema.js";
import { decodeB64url, encodeB64url } from "../cxf/index.js";
import { getPolicy } from "../policy/index.js";

const VECTOR_VERSION = 1;
const SOURCE = {
  cxporter: "96bab31fdadcfd295542bba86b8ec8bd2355294a",
  cxp_poc2: "fee19d9ac392ffe0153bea8b917aa0a66f12b272",
};
// Public test-only IKM. Never use this recipient for real credentials.
const ikm = new Uint8Array(createHash("sha256").update("PasskeyTransit public CXP vector v1").digest());
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const describe = (error: unknown) => error instanceof Error ? error.name + ": " + error.message : String(error);

async function recipient() {
  const keyPair = await deriveKeyPair(MTI_SUITE.kem, ikm);
  const publicKey = new Uint8Array(await serializePublicKey(MTI_SUITE.kem, keyPair.publicKey));
  return { keyPair, publicKey };
}

async function generate(binary: string) {
  const cxf = JSON.parse(readFileSync(0, "utf8"));
  const { publicKey } = await recipient();
  const raw = execFileSync(binary, [], {
    input: JSON.stringify({ recipientPublicKey: encodeB64url(publicKey), cxf }),
    maxBuffer: 2 << 20,
  });
  const response = JSON.parse(raw.toString("utf8"));
  console.log(JSON.stringify({
    vector_version: VECTOR_VERSION,
    description: "Synthetic cxporter response for a public, derivable test recipient",
    source_commits: SOURCE,
    recipient_ikm_sha256: sha256(ikm),
    recipient_public_key: encodeB64url(publicKey),
    cxf_sha256: sha256(new TextEncoder().encode(JSON.stringify(cxf))),
    cxf,
    archive_sha256: sha256(decodeB64url(response.payload)),
    response,
  }, null, 2));
}

async function replay(file: string) {
  const vector = JSON.parse(readFileSync(file, "utf8"));
  if (vector.vector_version !== VECTOR_VERSION ||
      vector.source_commits?.cxporter !== SOURCE.cxporter ||
      vector.source_commits?.cxp_poc2 !== SOURCE.cxp_poc2) {
    throw new Error("vector version or source revision differs");
  }
  const { keyPair, publicKey } = await recipient();
  if (vector.recipient_ikm_sha256 !== sha256(ikm) ||
      vector.recipient_public_key !== encodeB64url(publicKey)) {
    throw new Error("recipient key differs from public test derivation");
  }
  if (vector.cxf_sha256 !== sha256(new TextEncoder().encode(JSON.stringify(vector.cxf)))) {
    throw new Error("synthetic CXF differs from its recorded digest");
  }
  const response = vector.response;
  const archive = decodeB64url(response.payload);
  if (vector.archive_sha256 !== sha256(archive)) {
    throw new Error("archive differs from its recorded digest");
  }
  const index = readZip(archive).get(INDEX_PATH);
  if (!index) throw new Error("cxporter index.jwe absent");
  const compact = new TextDecoder().decode(index);
  const protectedPart = compact.split(".")[0];
  if (!protectedPart) throw new Error("JWE protected header absent");
  const header = JSON.parse(new TextDecoder().decode(decodeB64url(protectedPart)));
  const enc = decodeB64url(header.epk.x);
  let schemaError = "";
  let patchedSchemaError = "";
  let payloadError = "";
  try { parseExportResponseJson(JSON.stringify(response)); }
  catch (error) { schemaError = describe(error); }
  try { parseExportResponseJson(JSON.stringify({ ...response, archive: "deflate" })); }
  catch (error) { patchedSchemaError = describe(error); }
  try {
    await openPayload({
      archive, suite: MTI_SUITE, recipientKey: keyPair, enc,
      binding: { policy: getPolicy("spec-minimal"), info: new Uint8Array(0), requestDigest: new Uint8Array(32) },
    });
  } catch (error) { payloadError = describe(error); }
  console.log(JSON.stringify({
    vector_version: VECTOR_VERSION,
    archive_sha256: sha256(archive),
    archive_member_count: readZip(archive).size,
    archive_file_count: [...readZip(archive).keys()].filter((path) => !path.endsWith("/")).length,
    index_jwe_alg: header.alg,
    response_has_archive: Object.hasOwn(response, "archive"),
    schema_error: schemaError,
    patched_schema_error: patchedSchemaError,
    payload_error: payloadError,
  }, null, 2));
}

const [mode, arg] = process.argv.slice(2);
if (mode === "generate" && arg) await generate(arg);
else if (mode === "replay" && arg) await replay(arg);
else throw new Error("usage: pt-vector.ts generate <cxporter-binary> | replay <vector.json>");
