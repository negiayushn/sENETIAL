import { Global, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import type { Env } from '../config/env';
import { PrismaService } from '../prisma/prisma.service';
import { AuthGuard } from './auth.guard';
import { AuthService } from './auth.service';
import { MeController } from './me.controller';

@Global()
@Module({
  controllers: [MeController],
  providers: [
    {
      provide: AuthService,
      inject: [ConfigService, PrismaService],
      useFactory: async (config: ConfigService<Env, true>, prisma: PrismaService) => {
        const env = {
          API_URL: config.get('API_URL', { infer: true }),
          WEB_URL: config.get('WEB_URL', { infer: true }),
          BETTER_AUTH_SECRET: config.get('BETTER_AUTH_SECRET', { infer: true }),
          GITHUB_CLIENT_ID: config.get('GITHUB_CLIENT_ID', { infer: true }),
          GITHUB_CLIENT_SECRET: config.get('GITHUB_CLIENT_SECRET', { infer: true }),
        } as Env;
        return new AuthService(env, prisma).init();
      },
    },
    // Every route requires a session unless it is marked @Public().
    { provide: APP_GUARD, useClass: AuthGuard },
  ],
  exports: [AuthService],
})
export class AuthModule {}
