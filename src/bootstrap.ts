import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { Request, Response, NextFunction } from 'express';
import { AppModule } from './app.module';
import { config } from './config';

export async function createApp() {
  const c = config();
  const app = await NestFactory.create(AppModule, { logger: ['error', 'warn'] });

  app.setGlobalPrefix('api');
  app.use(helmet());
  app.enableCors({
    origin: c.origin,
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Protection'],
  });
  app.use(cookieParser());

  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Request-Id', randomUUID());
    res.setHeader('Cache-Control', 'no-store');

    if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(req.method)) {
      const origin = req.get('Origin');
      const hasCsrfHeader = req.get('X-CSRF-Protection') === '1';
      if (!hasCsrfHeader || (origin && origin !== c.origin)) {
        res.status(403).json({
          statusCode: 403,
          code: 'CSRF_REJECTED',
          message: 'Missing header or invalid origin',
        });
        return;
      }
    }
    next();
  });

  app.useGlobalPipes(
    new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
  );
  app.enableShutdownHooks();
  await app.init();
  return app;
}
