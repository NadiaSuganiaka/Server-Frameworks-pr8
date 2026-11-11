import { ConflictException, Injectable, OnModuleInit, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Prisma } from '@prisma/client';
import { randomBytes } from 'node:crypto';
import { config } from '../config';
import { PrismaService } from '../prisma.service';
import {
  hashToken,
  newRefreshToken,
  passwordHash,
  passwordMatches,
  validTokenShape,
} from './crypto';
import { LoginDto, RegisterDto } from './dto';

@Injectable()
export class AuthService implements OnModuleInit {
  private dummyHash!: string;

  constructor(
    private readonly db: PrismaService,
    private readonly jwt: JwtService,
  ) {}

  async onModuleInit() {
    this.dummyHash = await passwordHash(randomBytes(32).toString('hex'));
  }

  async register(dto: RegisterDto) {
    const hash = await passwordHash(dto.password);
    try {
      return await this.db.user.create({
        data: { email: dto.email, passwordHash: hash },
        select: { id: true, email: true, createdAt: true },
      });
    } catch (e) {
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') {
        throw new ConflictException({ code: 'EMAIL_EXISTS', message: 'Email already registered' });
      }
      throw e;
    }
  }

  async login(dto: LoginDto) {
    const user = await this.db.user.findUnique({ where: { email: dto.email } });
    const ok = await passwordMatches(user?.passwordHash ?? this.dummyHash, dto.password);
    if (!user || !ok) {
      throw new UnauthorizedException({
        code: 'INVALID_CREDENTIALS',
        message: 'Invalid email or password',
      });
    }

    const refreshToken = newRefreshToken();
    const expiresAt = new Date(Date.now() + config().sessionTtl * 1000);
    const session = await this.db.session.create({
      data: {
        userId: user.id,
        expiresAt,
        tokens: { create: { tokenHash: hashToken(refreshToken), expiresAt } },
      },
    });
    return this.issue(user.id, session.id, refreshToken, expiresAt);
  }

  private async issue(userId: string, sessionId: string, refreshToken: string, expiresAt: Date) {
    const c = config();
    const accessToken = await this.jwt.signAsync(
      { sub: userId, sid: sessionId, type: 'access' },
      {
        secret: c.secret,
        algorithm: 'HS256',
        issuer: c.issuer,
        audience: c.audience,
        expiresIn: c.accessTtl,
      },
    );
    return { accessToken, expiresIn: c.accessTtl, tokenType: 'Bearer', refreshToken, expiresAt };
  }

  async refresh(raw: unknown) {
    if (!validTokenShape(raw)) throw new UnauthorizedException('Invalid refresh token');
    const known = await this.db.refreshToken.findUnique({ where: { tokenHash: hashToken(raw) } });
    if (!known) throw new UnauthorizedException('Invalid refresh token');
    const fresh = newRefreshToken();

    const result = await this.db.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM "Session" WHERE id = ${known.sessionId}::uuid FOR UPDATE`;
      const token = await tx.refreshToken.findUnique({
        where: { id: known.id },
        include: { session: true },
      });
      const now = new Date();

      if (!token || token.session.revokedAt) {
        return { ok: false as const, code: 'SESSION_INVALID' };
      }
      if (token.usedAt) {
        await tx.session.update({ where: { id: token.sessionId }, data: { revokedAt: now } });
        return { ok: false as const, code: 'REFRESH_REUSED' };
      }
      if (token.expiresAt <= now || token.session.expiresAt <= now) {
        await tx.session.update({ where: { id: token.sessionId }, data: { revokedAt: now } });
        return { ok: false as const, code: 'SESSION_EXPIRED' };
      }

      await tx.refreshToken.update({ where: { id: token.id }, data: { usedAt: now } });
      await tx.refreshToken.create({
        data: {
          sessionId: token.sessionId,
          tokenHash: hashToken(fresh),
          expiresAt: token.session.expiresAt,
        },
      });
      return { ok: true as const, session: token.session };
    });
    if (!result.ok) {
      throw new UnauthorizedException({ code: result.code, message: 'Please sign in again' });
    }

    return this.issue(result.session.userId, result.session.id, fresh, result.session.expiresAt);
  }

  async logout(raw: unknown) {
    if (!validTokenShape(raw)) return;
    const token = await this.db.refreshToken.findUnique({ where: { tokenHash: hashToken(raw) } });
    if (!token) return;
    await this.db.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM "Session" WHERE id = ${token.sessionId}::uuid FOR UPDATE`;
      await tx.session.updateMany({
        where: { id: token.sessionId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
    });
  }
}
