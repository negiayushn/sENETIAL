import { Injectable } from '@nestjs/common';
import type { IncomingHttpHeaders } from 'node:http';
import type { Env } from '../config/env';
import type { PrismaService } from '../prisma/prisma.service';

/**
 * better-auth is ESM-only while this API compiles to CommonJS, so it is loaded with a
 * real dynamic import() (preserved by `module: nodenext`). Everything async happens in
 * init(), which the module's provider factory awaits before the app starts.
 */
async function loadAuth(env: Env, prisma: PrismaService) {
  const { betterAuth } = await import('better-auth');
  const { prismaAdapter } = await import('better-auth/adapters/prisma');
  const { toNodeHandler, fromNodeHeaders } = await import('better-auth/node');

  const githubEnabled = Boolean(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET);

  const auth = betterAuth({
    appName: 'Sentinel',
    baseURL: env.API_URL,
    secret: env.BETTER_AUTH_SECRET,
    database: prismaAdapter(prisma, { provider: 'postgresql' }),
    trustedOrigins: [env.WEB_URL],
    emailAndPassword: { enabled: true, minPasswordLength: 8, maxPasswordLength: 128, autoSignIn: true },
    socialProviders: githubEnabled
      ? { github: { clientId: env.GITHUB_CLIENT_ID!, clientSecret: env.GITHUB_CLIENT_SECRET! } }
      : {},
  });

  return { auth, nodeHandler: toNodeHandler(auth), fromNodeHeaders, githubEnabled };
}

type Loaded = Awaited<ReturnType<typeof loadAuth>>;
export type AuthSession = NonNullable<Awaited<ReturnType<Loaded['auth']['api']['getSession']>>>;

@Injectable()
export class AuthService {
  private loaded!: Loaded;

  constructor(private readonly env: Env, private readonly prisma: PrismaService) {}

  async init() {
    this.loaded = await loadAuth(this.env, this.prisma);
    return this;
  }

  /** Express-compatible handler for every /api/auth/* route (sign-up, sign-in, OAuth callbacks, ...). */
  get nodeHandler() {
    return this.loaded.nodeHandler;
  }

  get githubEnabled() {
    return this.loaded.githubEnabled;
  }

  async getSession(headers: IncomingHttpHeaders): Promise<AuthSession | null> {
    return this.loaded.auth.api.getSession({ headers: this.loaded.fromNodeHeaders(headers) });
  }
}
