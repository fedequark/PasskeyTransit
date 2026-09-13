import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { inflateRawSync } from "node:zlib";

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const document = JSON.parse(Buffer.concat(chunks).toString("utf8"));
const credential = document.accounts[0].items[0].credentials[0];
const decode = value => Buffer.from(value, "base64url");
const privateKey = createPrivateKey({ key: decode(credential.key), format: "der", type: "pkcs8" });
const publicSpki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
const largeBlob = credential.fido2Extensions?.largeBlob;
let blob = null;
if (largeBlob) {
  blob = inflateRawSync(decode(largeBlob.data));
  if (blob.length !== largeBlob.uncompressedSize) throw new Error("largeBlob length mismatch");
}
const digest = value => createHash("sha256").update(value).digest("hex");
process.stdout.write(JSON.stringify({
  envelope: document.version?.major === 1 && Array.isArray(document.accounts),
  passkeyType: credential.type === "passkey",
  pkcs8Parsed: privateKey.asymmetricKeyType === "ec",
  publicSpkiSha256: digest(publicSpki),
  credentialIdSha256: digest(decode(credential.credentialId)),
  largeBlobSha256: blob ? digest(blob) : null,
}));
