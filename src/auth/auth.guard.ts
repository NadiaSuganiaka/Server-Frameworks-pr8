import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { config } from '../config';
import { PrismaService } from '../prisma.service';

export type AuthRequest = Request & { auth: { userId: string; sessionId: string } };

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly jwt: JwtService,
    private readonly db: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext) {
    const req = context.switchToHttp().getRequest<AuthRequest>();
    const match = /^Bearer ([^\s]+)$/.exec(req.headers.authorization ?? '');
    if (!match) throw new UnauthorizedException('Bearer token required');
    const c = config();
    let claims: { sub?: string; sid?: string; type?: string; exp?: number };
    try {
      claims = await this.jwt.verifyAsync(match[1], {
        secret: c.secret,
        algorithms: ['HS256'],
        issuer: c.issuer,
        audience: c.audience,
      });
    } catch {
      throw new UnauthorizedException('Invalid or expired access token');
    }

    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (
      claims.type !== 'access' ||
      !claims.sub ||
      !claims.sid ||
      !claims.exp ||
      !uuid.test(claims.sid) ||
      !uuid.test(claims.sub)
    ) {
      throw new UnauthorizedException();
    }

    const session = await this.db.session.findUnique({ where: { id: claims.sid } });
    if (
      !session ||
      session.userId !== claims.sub ||
      session.revokedAt ||
      session.expiresAt <= new Date()
    ) {
      throw new UnauthorizedException('Session revoked or expired');
    }
    req.auth = { userId: claims.sub, sessionId: claims.sid };
    return true;
  }
}
