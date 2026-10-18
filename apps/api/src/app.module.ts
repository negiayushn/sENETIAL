import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { LoggerModule } from 'nestjs-pino';
import { randomUUID } from 'node:crypto';
import { AuthModule } from './auth/auth.module';
import { validateEnv } from './config/env';
import { DashboardModule } from './dashboard/dashboard.module';
import { FindingsModule } from './findings/findings.module';
import { GithubModule } from './github/github.module';
import { HealthModule } from './health/health.module';
import { RateLimitModule } from './common/rate-limit.service';
import { PrismaModule } from './prisma/prisma.module';
import { QueueModule } from './queue/queue.module';
import { RedisModule } from './redis/redis.module';
import { ScansModule } from './scans/scans.module';
import { TargetsModule } from './targets/targets.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      envFilePath: ['.env', '../../.env'],
      validate: validateEnv,
    }),
    LoggerModule.forRoot({
      pinoHttp: {
        level: process.env.LOG_LEVEL ?? 'info',
        genReqId: (req, res) => {
          const id = (req.headers['x-request-id'] as string) ?? randomUUID();
          res.setHeader('x-request-id', id);
          return id;
        },
        redact: ['req.headers.authorization', 'req.headers.cookie', 'res.headers["set-cookie"]'],
        autoLogging: { ignore: (req) => (req.url ?? '').startsWith('/health') },
        transport:
          process.env.NODE_ENV === 'production'
            ? undefined
            : { target: 'pino-pretty', options: { singleLine: true, colorize: true, translateTime: 'SYS:HH:MM:ss' } },
      },
    }),
    PrismaModule,
    RedisModule,
    RateLimitModule,
    QueueModule,
    AuthModule,
    HealthModule,
    TargetsModule,
    ScansModule,
    GithubModule,
    FindingsModule,
    DashboardModule,
  ],
})
export class AppModule {}
