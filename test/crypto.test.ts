import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hashToken, newRefreshToken, passwordHash, passwordMatches } from '../src/auth/crypto';

test('password uses salted Argon2id and verifies correctly', async () => {
  const a = await passwordHash('My long test passphrase');
  const b = await passwordHash('My long test passphrase');
  assert.match(a, /^\$argon2id\$/);
  assert.notEqual(a, b);
  assert.equal(await passwordMatches(a, 'My long test passphrase'), true);
  assert.equal(await passwordMatches(a, 'wrong password'), false);
});

test('refresh token has 256 bits and hashes deterministically', () => {
  const token = newRefreshToken();
  assert.equal(Buffer.from(token, 'base64url').length, 32);
  assert.equal(hashToken(token).length, 64);
  assert.equal(hashToken(token), hashToken(token));
  assert.notEqual(hashToken(token), hashToken(newRefreshToken()));
});
