import 'reflect-metadata';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Logger } from 'nestjs-pino';
import { AppModule } from './app.module';
import { AuthService } from './auth/auth.service';
import type { Env } from './config/env';

async function bootstrap() {
  // bodyParser is off so Better Auth can read the raw request itself; we re-enable it below for our own routes.
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bufferLogs: true, bodyParser: false });
  const config = app.get(ConfigService<Env, true>);

  app.useLogger(app.get(Logger));
  app.enableShutdownHooks();
  app.enableCors({ origin: config.get('WEB_URL', { infer: true }), credentials: true });

  // 1) Better Auth owns /api/auth/* (must be registered BEFORE body parsers).
  app.getHttpAdapter().getInstance().all('/api/auth/*splat', app.get(AuthService).nodeHandler);

  // 2) Body parsing for everything else.
  app.useBodyParser('json', { limit: '1mb' });

  // 3) Global validation: strip unknown fields, reject extras, coerce types.
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));

  const port = config.get('API_PORT', { infer: true });
  await app.listen(port);
  app.get(Logger).log(`Sentinel API listening on :${port}`);
}

bootstrap().catch((err) => {
  console.error(err);
  process.exit(1);
});
