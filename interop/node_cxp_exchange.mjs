// Independent Node.js implementation of PasskeyTransit's experimental CXP v0
// binding. The CXP Working Draft does not specify this binding or ZIP/JWE wire
// mapping; this file is an interoperability control, not a conformant provider.
import {
  createCipheriv, createDecipheriv, createHmac, createHash, diffieHellman,
  generateKeyPairSync, createPrivateKey, createPublicKey, randomBytes,
} from 'node:crypto';
import { deflateRawSync, inflateRawSync } from 'node:zlib';

const KEM = 0x0020, KDF = 0x0001, AEAD = 0x0001;
const DRAFT = 'cxp-v1.0-wd-20241003';
const BINDING = 'passkeytransit-cxp-binding-v1';
const INFO = Buffer.from('PasskeyTransit CXP v0 CXF payload');
const u16 = n => Buffer.from([(n >>> 8) & 255, n & 255]);
const b64 = b => Buffer.from(b).toString('base64url');
const unb64 = s => Buffer.from(s, 'base64url');
const hash = b => createHash('sha256').update(b).digest();
const canonical = value => Buffer.from(JSON.stringify(sort(value)));

function sort(value) {
  if (Array.isArray(value)) return value.map(sort);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(k => [k, sort(value[k])]));
  }
  return value;
}

function extract(salt, ikm) {
  return createHmac('sha256', salt.length ? salt : Buffer.alloc(32)).update(ikm).digest();
}
function expand(prk, info, length) {
  let output = Buffer.alloc(0), previous = Buffer.alloc(0);
  for (let i = 1; output.length < length; i++) {
    previous = createHmac('sha256', prk).update(Buffer.concat([previous, info, Buffer.from([i])])).digest();
    output = Buffer.concat([output, previous]);
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

function publicFromJwk(jwk) {
  if (jwk?.kty !== 'OKP' || jwk?.crv !== 'X25519' || typeof jwk?.x !== 'string' || unb64(jwk.x).length !== 32) {
    throw new Error('invalid X25519 public JWK');
  }
  return createPublicKey({key: jwk, format: 'jwk'});
}
function seal(recipientJwk, plaintext, aad) {
  const recipient = publicFromJwk(recipientJwk);
  const ephemeral = generateKeyPairSync('x25519');
  const enc = unb64(ephemeral.publicKey.export({format: 'jwk'}).x);
  const recipientBytes = unb64(recipientJwk.x);
  const dh = diffieHellman({privateKey: ephemeral.privateKey, publicKey: recipient});
  const ctx = context(dh, enc, recipientBytes, INFO);
  const cipher = createCipheriv('aes-128-gcm', ctx.key, ctx.nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return {enc, ciphertext};
}
function open(privateJwk, enc, ciphertext, aad) {
  if (enc.length !== 32 || ciphertext.length < 16) throw new Error('invalid HPKE input');
  const privateKey = createPrivateKey({key: privateJwk, format: 'jwk'});
  const ephemeralJwk = {kty: 'OKP', crv: 'X25519', x: b64(enc)};
  const dh = diffieHellman({privateKey, publicKey: publicFromJwk(ephemeralJwk)});
  const ctx = context(dh, enc, unb64(privateJwk.x), INFO);
  const decipher = createDecipheriv('aes-128-gcm', ctx.key, ctx.nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(ciphertext.subarray(-16));
  return Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]);
}

function selected(request) {
  if (request?.version !== 0 || request?.mode !== 'direct' || !request.importer || !request.archive?.includes('deflate')) {
    throw new Error('unsupported request');
  }
  const hpke = request.hpke?.find(p => p.mode === 'base' && p.kem === KEM && p.kdf === KDF && p.aead === AEAD);
  if (!hpke) throw new Error('unsupported HPKE suite');
  publicFromJwk(hpke.key);
  const binding = request._passkeyTransit;
  if (binding?.binding !== BINDING || !binding.requestId || !binding.challenge || unb64(binding.challenge).length < 16) {
    throw new Error('invalid experimental request binding');
  }
  return hpke;
}
const aad = (request, metadata) => canonical({draft: DRAFT, request, response: metadata});

function initiate(importer) {
  if (!importer) throw new Error('importer required');
  const keys = generateKeyPairSync('x25519');
  const request = {
    version: 0,
    hpke: [{mode: 'base', kem: KEM, kdf: KDF, aead: AEAD, key: keys.publicKey.export({format: 'jwk'})}],
    archive: ['deflate'], mode: 'direct', importer,
    credentialTypes: ['passkey'], knownExtensions: ['fido2Extensions'],
    _passkeyTransit: {binding: BINDING, requestId: randomBytes(16).toString('hex'), challenge: b64(randomBytes(32))},
  };
  return {request, privateJwk: keys.privateKey.export({format: 'jwk'})};
}

function exportDocument(request, document, exporter) {
  const hpke = selected(request);
  if (!exporter || !document?.accounts?.length) throw new Error('invalid exporter or CXF document');
  const metadata = {version: 0, hpke, archive: 'deflate', exporter};
  const plaintext = deflateRawSync(canonical(document), {level: 9});
  const {enc, ciphertext} = seal(hpke.key, plaintext, aad(request, metadata));
  return {...metadata, payload: b64(ciphertext), _passkeyTransit: {
    binding: BINDING, requestId: request._passkeyTransit.requestId,
    challengeHash: b64(hash(unb64(request._passkeyTransit.challenge))), enc: b64(enc),
  }};
}

function importDocument(request, privateJwk, response, expectedExporter) {
  const hpke = selected(request);
  if (response?.version !== 0 || response?.archive !== 'deflate' || response?.exporter !== expectedExporter ||
      canonical(response.hpke).toString() !== canonical(hpke).toString()) throw new Error('response metadata mismatch');
  const binding = response._passkeyTransit;
  if (binding?.binding !== BINDING || binding.requestId !== request._passkeyTransit.requestId ||
      binding.challengeHash !== b64(hash(unb64(request._passkeyTransit.challenge)))) throw new Error('response binding mismatch');
  const metadata = {version: response.version, hpke: response.hpke, archive: response.archive, exporter: response.exporter};
  const plaintext = open(privateJwk, unb64(binding.enc), unb64(response.payload), aad(request, metadata));
  const document = JSON.parse(inflateRawSync(plaintext).toString('utf8'));
  if (!document?.accounts?.length) throw new Error('invalid recovered CXF document');
  return document;
}

function evaluatePrf(document, salt, userVerified) {
  const passkey = document?.accounts?.[0]?.items?.[0]?.credentials?.[0];
  const hmac = passkey?.fido2Extensions?.hmacCredentials;
  if (hmac?.algorithm !== 'hmac-sha256') throw new Error('CXF credential has no executable HMAC state');
  const secret = unb64(userVerified ? hmac.credWithUV : hmac.credWithoutUV);
  if (secret.length !== 32) throw new Error('invalid HMAC seed');
  const prfInput = hash(Buffer.concat([Buffer.from('WebAuthn PRF\0'), unb64(salt)]));
  return b64(createHmac('sha256', secret).update(prfInput).digest());
}

let input = '';
for await (const chunk of process.stdin) input += chunk;
try {
  const request = JSON.parse(input);
  let result;
  if (request.operation === 'initiate') result = initiate(request.importer);
  else if (request.operation === 'export') result = {response: exportDocument(request.request, request.document, request.exporter)};
  else if (request.operation === 'import') result = {document: importDocument(request.request, request.privateJwk, request.response, request.expectedExporter)};
  else if (request.operation === 'eval-prf') result = {prfFirst: evaluatePrf(request.document, request.salt, request.userVerified === true)};
  else throw new Error('unsupported operation');
  process.stdout.write(JSON.stringify({status: 'PASS', ...result}));
} catch (error) {
  process.stdout.write(JSON.stringify({status: 'FAIL', error: String(error.message || error)}));
  process.exitCode = 1;
}
