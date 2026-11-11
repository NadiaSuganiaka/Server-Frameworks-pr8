import { Body, Controller, Get, HttpCode, Post, Req, Res, UseGuards } from '@nestjs/common';
import { Request, Response, CookieOptions } from 'express';
import { config } from '../config';
import { PrismaService } from '../prisma.service';
import { AuthGuard, AuthRequest } from './auth.guard';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './dto';

const COOKIE = 'refresh_token';

const cookieOptions = (): CookieOptions => ({
  httpOnly: true,
  secure: config().secure,
  sameSite: 'strict',
  path: '/api/auth',
});

@Controller('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly db: PrismaService,
  ) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.auth.register(dto);
  }

  @Post('login')
  @HttpCode(200)
  async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
    const { refreshToken, expiresAt, ...body } = await this.auth.login(dto);
    res.cookie(COOKIE, refreshToken, { ...cookieOptions(), expires: expiresAt });
    return body;
  }

  @Post('refresh')
  @HttpCode(200)
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    try {
      const { refreshToken, expiresAt, ...body } = await this.auth.refresh(req.cookies?.[COOKIE]);
      res.cookie(COOKIE, refreshToken, { ...cookieOptions(), expires: expiresAt });
      return body;
    } catch (e) {
      res.clearCookie(COOKIE, cookieOptions());
      throw e;
    }
  }

  @Post('logout')
  @HttpCode(204)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    await this.auth.logout(req.cookies?.[COOKIE]);
    res.clearCookie(COOKIE, cookieOptions());
  }

  @Get('me')
  @UseGuards(AuthGuard)
  me(@Req() req: AuthRequest) {
    return this.db.user.findUnique({
      where: { id: req.auth.userId },
      select: { id: true, email: true, createdAt: true },
    });
  }

  @Get('sessions')
  @UseGuards(AuthGuard)
  async sessions(@Req() req: AuthRequest) {
    const rows = await this.db.session.findMany({
      where: { userId: req.auth.userId, revokedAt: null, expiresAt: { gt: new Date() } },
      select: { id: true, createdAt: true, expiresAt: true },
      orderBy: { createdAt: 'desc' },
    });
    return rows.map((s) => ({ ...s, current: s.id === req.auth.sessionId }));
  }
}
