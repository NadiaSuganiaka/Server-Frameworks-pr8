import 'reflect-metadata';
import 'dotenv/config';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createApp } from '../src/bootstrap';
import { PrismaService } from '../src/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { config } from '../src/config';
import { SessionCleanupService } from '../src/auth/session-cleanup.service';

test('auth flow against PostgreSQL', { skip: !process.env.DATABASE_URL_TEST }, async (t) => {
  process.env.DATABASE_URL = process.env.DATABASE_URL_TEST;
  process.env.JWT_SECRET = randomBytes(48).toString('base64url');
  process.env.RATE_LIMIT_PER_MINUTE = '200';
  const app = await createApp();
  await app.listen(0, '127.0.0.1');
  const db = app.get(PrismaService);
  const url = await app.getUrl();
  const email = `test-${randomBytes(8).toString('hex')}@example.com`;
  const password = 'A long student test passphrase';

  const call = async (path: string, body?: unknown, cookie?: string, access?: string) => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-CSRF-Protection': '1',
    };
    if (cookie) headers.Cookie = cookie;
    if (access) headers.Authorization = `Bearer ${access}`;
    return fetch(`${url}/api/auth/${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  };
  const cookieOf = (res: Response) => res.headers.get('set-cookie')!.split(';')[0];
  const login = async () => {
    const r = await call('login', { email, password });
    assert.equal(r.status, 200);
    return { cookie: cookieOf(r), body: (await r.json()) as { accessToken: string } };
  };
  try {
    await t.test('register stores only hash and rejects short password', async () => {
      assert.equal((await call('register', { email, password: 'short' })).status, 400);
      const r = await call('register', { email, password });
      assert.equal(r.status, 201);
      const body = await r.json();
      assert.equal('passwordHash' in body, false);
      const user = await db.user.findUniqueOrThrow({ where: { email } });
      assert.match(user.passwordHash, /^\$argon2id\$/);
      assert.equal((await call('register', { email, password })).status, 409);
    });

    await t.test('invalid credentials and protected route return 401', async () => {
      assert.equal((await call('login', { email, password: 'wrong' })).status, 401);
      assert.equal((await call('me')).status, 401);
      assert.equal((await call('me', undefined, undefined, 'broken')).status, 401);
    });

    await t.test('login cookie, me and expired JWT', async () => {
      const r = await call('login', { email, password });
      assert.equal(r.status, 200);
      assert.match(r.headers.get('set-cookie')!, /HttpOnly/);
      assert.match(r.headers.get('set-cookie')!, /SameSite=Strict/);
      const body = (await r.json()) as { accessToken: string; refreshToken?: string };
      assert.equal(body.refreshToken, undefined);
      const me = await call('me', undefined, undefined, body.accessToken);
      assert.equal(me.status, 200);
      assert.equal((await me.json()).email, email);
      const claims = app.get(JwtService).decode(body.accessToken);
      const c = config();
      const expired = await app.get(JwtService).signAsync(
        { sub: claims.sub, sid: claims.sid, type: 'access' },
        {
          secret: c.secret,
          issuer: c.issuer,
          audience: c.audience,
          algorithm: 'HS256',
          expiresIn: -1,
        },
      );
      assert.equal((await call('me', undefined, undefined, expired)).status, 401);
    });

    await t.test('rotation, replay revokes session and newest token', async () => {
      const first = await login();
      const rotated = await call('refresh', {}, first.cookie);
      assert.equal(rotated.status, 200);
      const next = cookieOf(rotated);
      assert.notEqual(next, first.cookie);
      assert.equal((await call('refresh', {}, first.cookie)).status, 401);
      assert.equal((await call('refresh', {}, next)).status, 401);
      assert.equal((await call('me', undefined, undefined, first.body.accessToken)).status, 401);
    });

    await t.test('expired refresh returns 401', async () => {
      const first = await login();
      const claims = app.get(JwtService).decode(first.body.accessToken);
      await db.refreshToken.updateMany({
        where: { sessionId: claims.sid },
        data: { expiresAt: new Date(0) },
      });
      assert.equal((await call('refresh', {}, first.cookie)).status, 401);
    });

    await t.test('logout revokes current session but not another login', async () => {
      const a = await login(),
        b = await login();
      assert.equal((await call('logout', {}, a.cookie)).status, 204);
      assert.equal((await call('refresh', {}, a.cookie)).status, 401);
      assert.equal((await call('me', undefined, undefined, a.body.accessToken)).status, 401);
      assert.equal((await call('me', undefined, undefined, b.body.accessToken)).status, 200);
    });

    await t.test('parallel refresh consumes token only once', async () => {
      const a = await login();
      const results = await Promise.all([
        call('refresh', {}, a.cookie),
        call('refresh', {}, a.cookie),
      ]);
      assert.deepEqual(results.map((r) => r.status).sort(), [200, 401]);
      assert.equal((await call('me', undefined, undefined, a.body.accessToken)).status, 401);
    });

    await t.test(
      'login with nonexistent email returns the same 401 as wrong password',
      async () => {
        const unknown = await call('login', {
          email: `nobody-${randomBytes(8).toString('hex')}@example.com`,
          password,
        });
        const wrong = await call('login', { email, password: 'wrong password' });
        assert.equal(unknown.status, 401);
        assert.equal(wrong.status, 401);
        assert.equal(unknown.headers.get('set-cookie'), null);
        const a = await unknown.json(),
          b = await wrong.json();
        assert.equal(a.message, 'Invalid email or password');
        assert.deepEqual(a, b);
      },
    );
    await t.test('unknown body field is rejected with 400', async () => {
      const reg = await call('register', {
        email: `x-${randomBytes(8).toString('hex')}@example.com`,
        password,
        role: 'admin',
      });
      assert.equal(reg.status, 400);
      assert.match(JSON.stringify(await reg.json()), /property role should not exist/);
      assert.equal((await call('login', { email, password, isAdmin: true })).status, 400);
    });

    await t.test('JWT with wrong issuer, audience, type or secret returns 401', async () => {
      const { body } = await login();
      const claims = app.get(JwtService).decode(body.accessToken);
      const c = config();
      const sign = (
        payload: object,
        opts: { issuer?: string; audience?: string; secret?: string },
      ) =>
        app.get(JwtService).signAsync(payload, {
          algorithm: 'HS256',
          expiresIn: 60,
          secret: opts.secret ?? c.secret,
          issuer: opts.issuer ?? c.issuer,
          audience: opts.audience ?? c.audience,
        });
      const base = { sub: claims.sub, sid: claims.sid, type: 'access' };
      assert.equal((await call('me', undefined, undefined, await sign(base, {}))).status, 200);
      assert.equal(
        (await call('me', undefined, undefined, await sign(base, { issuer: 'evil-api' }))).status,
        401,
      );
      assert.equal(
        (await call('me', undefined, undefined, await sign(base, { audience: 'other-app' })))
          .status,
        401,
      );
      assert.equal(
        (await call('me', undefined, undefined, await sign({ ...base, type: 'refresh' }, {})))
          .status,
        401,
      );
      assert.equal(
        (
          await call(
            'me',
            undefined,
            undefined,
            await sign(base, { secret: randomBytes(48).toString('base64url') }),
          )
        ).status,
        401,
      );
    });

    await t.test('GET sessions lists only active sessions with safe fields', async () => {
      const a = await login(),
        b = await login();
      assert.equal((await call('sessions')).status, 401);
      assert.equal((await call('logout', {}, b.cookie)).status, 204);
      const r = await call('sessions', undefined, undefined, a.body.accessToken);
      assert.equal(r.status, 200);
      const list = (await r.json()) as Array<Record<string, unknown>>;
      const sidA = app.get(JwtService).decode(a.body.accessToken).sid;
      const sidB = app.get(JwtService).decode(b.body.accessToken).sid;
      assert.ok(list.some((s) => s.id === sidA && s.current === true));
      assert.equal(
        list.some((s) => s.id === sidB),
        false,
      );
      assert.equal(list.filter((s) => s.current).length, 1);
      for (const s of list)
        assert.deepEqual(Object.keys(s).sort(), ['createdAt', 'current', 'expiresAt', 'id']);
      assert.doesNotMatch(JSON.stringify(list), /tokenHash|userId/);
    });

    await t.test('cleanup deletes sessions ended before retention, keeps the rest', async () => {
      const user = await db.user.findUniqueOrThrow({ where: { email } });
      const day = 86400_000,
        now = Date.now();
      const mk = (expiresAt: number, revokedAt?: number) =>
        db.session.create({
          data: {
            userId: user.id,
            expiresAt: new Date(expiresAt),
            revokedAt: revokedAt ? new Date(revokedAt) : null,
            tokens: {
              create: {
                tokenHash: randomBytes(32).toString('hex'),
                expiresAt: new Date(expiresAt),
              },
            },
          },
        });
      const oldExpired = await mk(now - 30 * day);
      const oldRevoked = await mk(now + day, now - 30 * day);
      const recentExpired = await mk(now - day);
      const active = await mk(now + day);
      const deleted = await app.get(SessionCleanupService).purgeEndedSessions(new Date(now));
      assert.ok(deleted >= 2);
      const ids = (
        await db.session.findMany({ where: { userId: user.id }, select: { id: true } })
      ).map((s) => s.id);
      assert.equal(ids.includes(oldExpired.id), false);
      assert.equal(ids.includes(oldRevoked.id), false);
      assert.ok(ids.includes(recentExpired.id));
      assert.ok(ids.includes(active.id));
      assert.equal(
        await db.refreshToken.count({
          where: { sessionId: { in: [oldExpired.id, oldRevoked.id] } },
        }),
        0,
      );
    });

    await t.test('CSRF header and origin are required/checked', async () => {
      assert.equal((await fetch(`${url}/api/auth/logout`, { method: 'POST' })).status, 403);
      const r = await fetch(`${url}/api/auth/logout`, {
        method: 'POST',
        headers: {
          'X-CSRF-Protection': '1',
          Origin: 'https://evil.example',
        },
      });
      assert.equal(r.status, 403);
    });
  } finally {
    await db.user.deleteMany({ where: { email } });
    await app.close();
  }
});
