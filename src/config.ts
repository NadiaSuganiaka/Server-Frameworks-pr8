import 'dotenv/config';

function positiveInt(name: string, fallback: number, max: number): number {
  const n = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(n) || n < 1 || n > max) throw new Error(`Invalid ${name}`);
  return n;
}

export function config() {
  const secret = process.env.JWT_SECRET ?? '';
  if (secret.length < 32 || secret.startsWith('REPLACE_')) {
    throw new Error('Set a random JWT_SECRET of at least 32 characters');
  }
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
  const origin = process.env.FRONTEND_ORIGIN ?? 'http://localhost:5173';
  if (new URL(origin).origin !== origin) throw new Error('FRONTEND_ORIGIN must be an origin');
  if (process.env.NODE_ENV === 'production' && !origin.startsWith('https://')) {
    throw new Error('Production FRONTEND_ORIGIN requires HTTPS');
  }
  return {
    secret,
    origin,
    secure: process.env.NODE_ENV === 'production',
    issuer: process.env.JWT_ISSUER ?? 'pr8-api',
    audience: process.env.JWT_AUDIENCE ?? 'pr8-web',
    port: positiveInt('PORT', 3000, 65535),
    accessTtl: positiveInt('ACCESS_TTL_SECONDS', 900, 3600),
    sessionTtl: positiveInt('SESSION_TTL_SECONDS', 604800, 2592000),
    sessionRetention: positiveInt('SESSION_RETENTION_SECONDS', 604800, 31536000),
    cleanupInterval: positiveInt('SESSION_CLEANUP_INTERVAL_SECONDS', 3600, 86400),
    rateLimit: positiveInt('RATE_LIMIT_PER_MINUTE', 30, 10000),
  };
}
