import {
  BadRequestException, ConflictException, ForbiddenException, Inject, Injectable, Logger, NotFoundException, ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  consumeInstallState, createGithubApp, createInstallState, getInstallation, installUrl, listInstallationRepos, userCanAccessInstallation,
  type GithubApp, type RepoInfo, type StateStore,
} from '@sentinel/github';
import type Redis from 'ioredis';
import type { Env } from '../config/env';
import { RateLimitService } from '../common/rate-limit.service';
import { PrismaService } from '../prisma/prisma.service';
import { REDIS } from '../redis/redis.module';

/** Reasons surfaced to the browser on the callback redirect. Fixed vocabulary: never reflects input or upstream errors. */
export type InstallOutcome = 'connected' | 'pending' | 'invalid_state' | 'no_code' | 'no_access' | 'not_configured' | 'failed';

@Injectable()
export class GithubService {
  private readonly log = new Logger(GithubService.name);
  private readonly app: GithubApp | null;
  private readonly slug: string | undefined;
  private readonly states: StateStore;

  constructor(
    config: ConfigService<Env, true>,
    private readonly prisma: PrismaService,
    private readonly rateLimit: RateLimitService,
    @Inject(REDIS) private readonly redis: Redis,
  ) {
    const g = (k: keyof Env) => config.get(k, { infer: true }) as string | undefined;
    this.slug = g('GITHUB_APP_SLUG');
    this.app =
      g('GITHUB_APP_ID') && g('GITHUB_APP_PRIVATE_KEY') && this.slug
        ? createGithubApp({ appId: g('GITHUB_APP_ID')!, privateKey: g('GITHUB_APP_PRIVATE_KEY')!, clientId: g('GITHUB_APP_CLIENT_ID'), clientSecret: g('GITHUB_APP_CLIENT_SECRET') })
        : null;
    this.states = {
      set: async (key, value, ttl) => void (await this.redis.set(key, value, 'EX', ttl)),
      getdel: (key) => this.redis.getdel(key),
    };
  }

  get configured() {
    return this.app !== null;
  }

  private requireApp(): GithubApp {
    if (!this.app) throw new ServiceUnavailableException('The GitHub integration is not configured on this server.');
    return this.app;
  }

  status() {
    return { configured: this.configured };
  }

  /** Step 1: send the user to GitHub, carrying a one-time state bound to them. */
  async startInstall(userId: string) {
    this.requireApp();
    await this.rateLimit.hit(`gh-install:${userId}`, 20, 3600, 'GitHub connection attempts');
    const state = await createInstallState(this.states, userId);
    return { url: installUrl(this.slug!, state) };
  }

  /**
   * Step 2: GitHub redirects the browser back here. Three independent checks, all required:
   *  1. `state` was issued to THIS signed-in user and is unused  → stops forged / replayed callbacks (CSRF).
   *  2. the OAuth `code` yields a USER token that can see this installation → stops claiming someone else's installation id.
   *  3. the installation data itself is read with the App's own credentials, never from the URL.
   * The user token is used once and discarded; only the installation id is stored.
   */
  async completeInstall(userId: string, q: { installation_id?: string; setup_action?: string; state?: string; code?: string }): Promise<InstallOutcome> {
    if (!this.app) return 'not_configured';
    const stateUser = await consumeInstallState(this.states, q.state);
    if (!stateUser || stateUser !== userId) return 'invalid_state';

    // Organisation installs that need an owner's approval come back with no installation yet.
    if (q.setup_action === 'request' || !q.installation_id) return 'pending';
    if (!/^\d{1,20}$/.test(q.installation_id)) return 'invalid_state';
    if (!q.code) return 'no_code';

    try {
      const user = await this.app.userRequesterFromCode(q.code);
      if (!(await userCanAccessInstallation(user, q.installation_id))) {
        this.log.warn({ userId, installationId: q.installation_id }, 'install callback rejected: user cannot access installation');
        return 'no_access';
      }
      const info = await getInstallation(await this.app.appRequester(), q.installation_id);
      const row = await this.prisma.githubInstallation.upsert({
        where: { userId_installationId: { userId, installationId: info.id } },
        create: { userId, installationId: info.id, accountLogin: info.accountLogin, accountType: info.accountType, repositorySelection: info.repositorySelection, suspendedAt: info.suspendedAt },
        update: { accountLogin: info.accountLogin, accountType: info.accountType, repositorySelection: info.repositorySelection, suspendedAt: info.suspendedAt },
      });
      if (!info.suspendedAt) await this.syncRepos(row.id, userId, info.id);
      return 'connected';
    } catch (err) {
      this.log.error({ err, userId }, 'install callback failed');
      return 'failed';
    }
  }

  /** Re-list repositories (e.g. after the user changed the installation's repo selection on GitHub). */
  async syncInstallation(userId: string, id: string) {
    const inst = await this.prisma.githubInstallation.findFirst({ where: { id, userId } });
    if (!inst) throw new NotFoundException('Installation not found');
    const app = this.requireApp();
    const info = await getInstallation(await app.appRequester(), inst.installationId).catch((err) => {
      if ((err as { status?: number }).status === 404) return null; // uninstalled on GitHub
      throw err;
    });
    if (!info) {
      await this.prisma.githubInstallation.delete({ where: { id } }); // cascades repositories and snapshots
      throw new ConflictException('This installation was removed on GitHub, so it has been disconnected here.');
    }
    await this.prisma.githubInstallation.update({ where: { id }, data: { accountLogin: info.accountLogin, repositorySelection: info.repositorySelection, suspendedAt: info.suspendedAt } });
    if (!info.suspendedAt) await this.syncRepos(id, userId, inst.installationId);
    return this.listInstallations(userId);
  }

  /** Forget the installation (and its repositories/snapshots). Uninstalling on GitHub is up to the user. */
  async disconnect(userId: string, id: string) {
    const { count } = await this.prisma.githubInstallation.deleteMany({ where: { id, userId } });
    if (count === 0) throw new NotFoundException('Installation not found');
    return { disconnected: true };
  }

  async listInstallations(userId: string) {
    const rows = await this.prisma.githubInstallation.findMany({
      where: { userId },
      orderBy: { createdAt: 'asc' },
      include: { _count: { select: { repositories: true } } },
    });
    return rows.map((r) => ({
      id: r.id, accountLogin: r.accountLogin, accountType: r.accountType, repositorySelection: r.repositorySelection,
      suspended: r.suspendedAt !== null, repositoryCount: r._count.repositories,
    }));
  }

  private async syncRepos(installationRowId: string, userId: string, githubInstallationId: string) {
    const app = this.requireApp();
    // Read-only token, only for the duration of this call.
    const requester = await app.installationRequester(githubInstallationId, { permissions: { metadata: 'read' } });
    const repos = await listInstallationRepos(requester);
    await this.applyRepos(installationRowId, userId, repos);
  }

  /** Upsert what GitHub says is visible; remove what is no longer visible (access revoked ⇒ data goes with it). */
  async applyRepos(installationRowId: string, userId: string, repos: RepoInfo[]) {
    await this.prisma.$transaction([
      ...repos.map((r) => {
        const fields = { owner: r.owner, name: r.name, fullName: r.fullName, defaultBranch: r.defaultBranch, private: r.private, archived: r.archived };
        return this.prisma.repository.upsert({
          where: { installationId_githubRepoId: { installationId: installationRowId, githubRepoId: r.id } },
          create: { ...fields, userId, installationId: installationRowId, githubRepoId: r.id },
          update: fields,
        });
      }),
      this.prisma.repository.deleteMany({ where: { installationId: installationRowId, githubRepoId: { notIn: repos.map((r) => r.id) } } }),
    ]);
  }
}
