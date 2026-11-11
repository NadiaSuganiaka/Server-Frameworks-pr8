import { createHash, randomBytes } from 'node:crypto';
import * as argon2 from 'argon2';

export const passwordHash = (password: string) =>
  argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
  });

export const passwordMatches = (hash: string, password: string) => argon2.verify(hash, password);

export const newRefreshToken = () => randomBytes(32).toString('base64url');

export const hashToken = (token: string) => createHash('sha256').update(token).digest('hex');

export const validTokenShape = (token: unknown): token is string =>
  typeof token === 'string' && /^[A-Za-z0-9_-]{43}$/.test(token);
