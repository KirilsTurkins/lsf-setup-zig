const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { test } = require('node:test');
const { parseKey, parseSignature, verifySignature } = require('../minisign');

async function fixture(algorithm = 'ED') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const id = crypto.randomBytes(8);
  const rawKey = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const key = await parseKey(Buffer.concat([Buffer.from('Ed'), id, rawKey]).toString('base64'));
  const content = Buffer.from('Zig archive fixture');
  const payload = algorithm === 'ED' ? crypto.createHash('blake2b512').update(content).digest() : content;
  const signature = crypto.sign(null, payload, privateKey);
  const comment = Buffer.from('timestamp:1\tfile:zig.tar.xz');
  const global = crypto.sign(null, Buffer.concat([signature, comment]), privateKey);
  const info = Buffer.concat([Buffer.from(algorithm), id, signature]).toString('base64');
  const parsed = parseSignature(Buffer.from(`untrusted comment: fixture\n${info}\ntrusted comment: ${comment}\n${global.toString('base64')}\n`));
  return { key, content, parsed };
}

for (const algorithm of ['Ed', 'ED']) {
  test(`accepts a correctly signed ${algorithm} archive`, async () => {
    const { key, content, parsed } = await fixture(algorithm);
    assert.equal(await verifySignature(key, parsed, content), true);
  });
}
test('rejects modified archive content', async () => {
  const { key, parsed } = await fixture();
  assert.equal(await verifySignature(key, parsed, Buffer.from('tampered')), false);
});
test('rejects a mismatched key identifier', async () => {
  const { key, content, parsed } = await fixture();
  parsed.key_id = Buffer.alloc(8);
  assert.equal(await verifySignature(key, parsed, content), false);
});
test('rejects a modified archive signature', async () => {
  const { key, content, parsed } = await fixture();
  parsed.signature[0] ^= 1;
  assert.equal(await verifySignature(key, parsed, content), false);
});
test('rejects a modified trusted comment', async () => {
  const { key, content, parsed } = await fixture();
  parsed.trusted_comment = Buffer.from('tampered');
  assert.equal(await verifySignature(key, parsed, content), false);
});
test('rejects malformed public keys and signature headers', async () => {
  await assert.rejects(parseKey('invalid'), /invalid public key/);
  assert.throws(() => parseSignature(Buffer.from('invalid')), /bad untrusted comment/);
});
