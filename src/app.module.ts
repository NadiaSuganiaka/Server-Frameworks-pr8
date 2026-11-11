import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { config } from './config';
import { PrismaService } from './prisma.service';
import { AuthController } from './auth/auth.controller';
import { AuthService } from './auth/auth.service';
import { AuthGuard } from './auth/auth.guard';
import { SessionCleanupService } from './auth/session-cleanup.service';

@Module({
  imports: [
    JwtModule.register({}),
    ThrottlerModule.forRootAsync({ useFactory: () => [{ ttl: 60000, limit: config().rateLimit }] }),
  ],
  controllers: [AuthController],
  providers: [
    PrismaService,
    AuthService,
    AuthGuard,
    SessionCleanupService,
    { provide: APP_GUARD, useClass: ThrottlerGuard },
  ],
})
export class AppModule {}
