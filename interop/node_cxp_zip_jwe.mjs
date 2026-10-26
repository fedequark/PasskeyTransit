// Independent Node importer for the project's experimental CXP ZIP/JWE profile.
// This is not a third-party provider or a FIDO-specified HPKE-to-JWE mapping.
import {
  createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman,
} from 'node:crypto';
import {inflateRawSync} from 'node:zlib';

const KEM = 0x0020, KDF = 0x0001, AEAD = 0x0001;
const PROFILE = 'passkeytransit-cxp-zip-jwe-v1';
const ALG = 'urn:passkeytransit:hpke-wrap-v1';
const INFO = Buffer.from('PasskeyTransit experimental CXP ZIP/JWE CEK v1');
const INDEX = 'CXP-Export/index.jwe';
const u16 = n => Buffer.from([(n >>> 8) & 255, n & 255]);
const b64 = value => Buffer.from(value).toString('base64url');
const hash = value => createHash('sha256').update(value).digest();

function unb64(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('invalid base64url');
  const result = Buffer.from(value, 'base64url');
  if (b64(result) !== value) throw new Error('noncanonical base64url');
  return result;
}
function sort(value) {
  if (Array.isArray(value)) return value.map(sort);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, sort(value[key])]));
  }
  return value;
}
const canonical = value => Buffer.from(JSON.stringify(sort(value)));
const extract = (salt, ikm) => createHmac('sha256', salt.length ? salt : Buffer.alloc(32)).update(ikm).digest();
function expand(prk, info, length) {
  let output = Buffer.alloc(0), prior = Buffer.alloc(0);
  for (let counter = 1; output.length < length; counter++) {
    prior = createHmac('sha256', prk).update(Buffer.concat([prior, info, Buffer.from([counter])])).digest();
    output = Buffer.concat([output, prior]);
  }
  return output.subarray(0, length);
}
const labeledExtract = (suite, salt, label, ikm) =>
  extract(salt, Buffer.concat([Buffer.from('HPKE-v1'), suite, Buffer.from(label), ikm]));
const labeledExpand = (suite, prk, label, info, length) =>
  expand(prk, Buffer.concat([u16(length), Buffer.from('HPKE-v1'), suite, Buffer.from(label), info]), length);

function context(dh, enc, recipient, info) {
  const kemSuite = Buffer.concat([Buffer.from('KEM'), u16(KEM)]);
  const eae = labeledExtract(kemSuite, Buffer.alloc(0), 'eae_prk', dh);
  const shared = labeledExpand(kemSuite, eae, 'shared_secret', Buffer.concat([enc, recipient]), 32);
  const suite = Buffer.concat([Buffer.from('HPKE'), u16(KEM), u16(KDF), u16(AEAD)]);
  const pskHash = labeledExtract(suite, Buffer.alloc(0), 'psk_id_hash', Buffer.alloc(0));
  const infoHash = labeledExtract(suite, Buffer.alloc(0), 'info_hash', info);
  const schedule = Buffer.concat([Buffer.from([0]), pskHash, infoHash]);
  const secret = labeledExtract(suite, shared, 'secret', Buffer.alloc(0));
  return {
    key: labeledExpand(suite, secret, 'key', schedule, 16),
    nonce: labeledExpand(suite, secret, 'base_nonce', schedule, 12),
  };
}

function decryptAesGcm(key, iv, ciphertext, tag, aad) {
  const decipher = createDecipheriv('aes-128-gcm', key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function unzipTwoMembers(payload) {
  const bytes = unb64(payload);
  if (bytes.length > 1024 * 1024) throw new Error('archive exceeds limit');
  const members = new Map();
  const local = [];
  let offset = 0;
  while (offset + 4 <= bytes.length && bytes.readUInt32LE(offset) === 0x04034b50) {
    if (offset + 30 > bytes.length) throw new Error('truncated ZIP header');
    const flags = bytes.readUInt16LE(offset + 6);
    const method = bytes.readUInt16LE(offset + 8);
    const compressed = bytes.readUInt32LE(offset + 18);
    const plain = bytes.readUInt32LE(offset + 22);
    const crc = bytes.readUInt32LE(offset + 14);
    const nameLength = bytes.readUInt16LE(offset + 26);
    const extraLength = bytes.readUInt16LE(offset + 28);
    if (flags !== 0 || method !== 8 || plain > 256 * 1024) throw new Error('unsupported ZIP member');
    const nameStart = offset + 30;
    const bodyStart = nameStart + nameLength + extraLength;
    const bodyEnd = bodyStart + compressed;
    if (bodyEnd > bytes.length) throw new Error('truncated ZIP member');
    const name = bytes.subarray(nameStart, nameStart + nameLength).toString('utf8');
    if (!name.startsWith('CXP-Export/') || name.includes('..') || members.has(name)) throw new Error('invalid ZIP member name');
    const body = inflateRawSync(bytes.subarray(bodyStart, bodyEnd), {maxOutputLength: 256 * 1024});
    if (body.length !== plain) throw new Error('ZIP member length mismatch');
    if (crc32(body) !== crc) throw new Error('ZIP member CRC mismatch');
    members.set(name, body);
    local.push({name, offset, flags, method, compressed, plain, crc});
    offset = bodyEnd;
    if (members.size > 2) throw new Error('unexpected ZIP member count');
  }
  if (members.size !== 2 || !members.has(INDEX)) throw new Error('missing ZIP member');
  const centralOffset = offset;
  for (const member of local) {
    if (offset + 46 > bytes.length || bytes.readUInt32LE(offset) !== 0x02014b50) throw new Error('missing ZIP central header');
    const nameLength = bytes.readUInt16LE(offset + 28);
    const extraLength = bytes.readUInt16LE(offset + 30);
    const commentLength = bytes.readUInt16LE(offset + 32);
    const end = offset + 46 + nameLength + extraLength + commentLength;
    if (end > bytes.length || bytes.readUInt16LE(offset + 8) !== member.flags ||
        bytes.readUInt16LE(offset + 10) !== member.method ||
        bytes.readUInt32LE(offset + 16) !== member.crc ||
        bytes.readUInt32LE(offset + 20) !== member.compressed ||
        bytes.readUInt32LE(offset + 24) !== member.plain ||
        bytes.readUInt32LE(offset + 42) !== member.offset ||
        bytes.subarray(offset + 46, offset + 46 + nameLength).toString('utf8') !== member.name) {
      throw new Error('ZIP central/local mismatch');
    }
    offset = end;
  }
  if (offset + 22 !== bytes.length || bytes.readUInt32LE(offset) !== 0x06054b50 ||
      bytes.readUInt16LE(offset + 4) !== 0 || bytes.readUInt16LE(offset + 6) !== 0 ||
      bytes.readUInt16LE(offset + 8) !== 2 || bytes.readUInt16LE(offset + 10) !== 2 ||
      bytes.readUInt32LE(offset + 12) !== offset - centralOffset ||
      bytes.readUInt32LE(offset + 16) !== centralOffset || bytes.readUInt16LE(offset + 20) !== 0) {
    throw new Error('invalid ZIP end record');
  }
  return members;
}

function openMember(name, compact, privateJwk, request, metadata) {
  const segments = compact.toString('ascii').split('.');
  if (segments.length !== 5) throw new Error('JWE segment count');
  const [protectedPart, encryptedKeyPart, ivPart, contentPart, tagPart] = segments;
  const header = JSON.parse(unb64(protectedPart).toString('utf8'));
  const expected = {
    alg: ALG, enc: 'A128GCM',
    cty: name === INDEX ? 'application/json' : 'application/cxf+json',
    profile: PROFILE, name,
  };
  if (canonical(header).toString() !== canonical(expected).toString()) throw new Error('JWE header mismatch');
  const wrapped = unb64(encryptedKeyPart), iv = unb64(ivPart), tag = unb64(tagPart);
  const content = unb64(contentPart);
  if (wrapped.length !== 64 || iv.length !== 12 || tag.length !== 16 || !content.length) throw new Error('JWE field length');
  const privateKey = createPrivateKey({key: privateJwk, format: 'jwk'});
  const encapsulated = wrapped.subarray(0, 32);
  const publicJwk = {kty: 'OKP', crv: 'X25519', x: b64(encapsulated)};
  const publicKey = createPublicKey({key: publicJwk, format: 'jwk'});
  const dh = diffieHellman({privateKey, publicKey});
  const hpke = context(dh, encapsulated, unb64(privateJwk.x), INFO);
  const metadataHash = hash(canonical({draft: 'cxp-v1.0-wd-20241003', request, response: metadata}));
  const wrappingAad = Buffer.concat([Buffer.from(protectedPart), Buffer.from([0]), metadataHash]);
  const cek = decryptAesGcm(hpke.key, hpke.nonce, wrapped.subarray(32, 48), wrapped.subarray(48), wrappingAad);
  if (cek.length !== 16) throw new Error('CEK length');
  return decryptAesGcm(cek, iv, content, tag, Buffer.from(protectedPart));
}

function importZip(request, privateJwk, response, expectedExporter) {
  if (request?.version !== 0 || request?.mode !== 'direct' || !request.archive?.includes('deflate')) throw new Error('request negotiation');
  if (response?.version !== 0 || response.archive !== 'deflate' || response.exporter !== expectedExporter) throw new Error('response negotiation');
  const selected = request.hpke?.find(item => item.mode === 'base' && item.kem === KEM && item.kdf === KDF && item.aead === AEAD);
  if (!selected || canonical(selected).toString() !== canonical(response.hpke).toString()) throw new Error('HPKE selection mismatch');
  const binding = request._passkeyTransit, answer = response._passkeyTransit;
  if (answer?.profile !== PROFILE || answer.requestId !== binding?.requestId ||
      answer.challengeHash !== b64(hash(unb64(binding.challenge)))) throw new Error('request binding mismatch');
  const metadata = {version: response.version, hpke: response.hpke, archive: response.archive, exporter: response.exporter};
  const members = unzipTwoMembers(response.payload);
  const index = JSON.parse(openMember(INDEX, members.get(INDEX), privateJwk, request, metadata));
  if (!Array.isArray(index.documents) || index.documents.length !== 1 || typeof index.documents[0] !== 'string') throw new Error('index documents');
  const name = `CXP-Export/documents/${index.documents[0]}.jwe`;
  if (members.size !== 2 || !members.has(name)) throw new Error('index/member mismatch');
  const document = JSON.parse(openMember(name, members.get(name), privateJwk, request, metadata));
  if (!Array.isArray(document.accounts) || !document.accounts.length) throw new Error('CXF document missing accounts');
  return document;
}

let input = '';
for await (const chunk of process.stdin) input += chunk;
try {
  const request = JSON.parse(input);
  const document = importZip(request.request, request.privateJwk, request.response, request.expectedExporter);
  process.stdout.write(JSON.stringify({status: 'PASS', document}));
} catch (error) {
  process.stdout.write(JSON.stringify({status: 'FAIL', error: String(error.message || error)}));
  process.exitCode = 1;
}
