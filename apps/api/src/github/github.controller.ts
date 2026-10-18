import { Controller, Delete, Get, HttpCode, Param, Post, Query, Res } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Response } from 'express';
import { CurrentUser } from '../auth/decorators';
import type { Env } from '../config/env';
import { GithubService } from './github.service';

@Controller('github')
export class GithubController {
  constructor(private readonly github: GithubService, private readonly config: ConfigService<Env, true>) {}

  @Get('status')
  status() {
    return this.github.status();
  }

  /** Returns the GitHub install URL (with a one-time state). The web app navigates the browser to it. */
  @Get('install')
  install(@CurrentUser() user: { id: string }) {
    return this.github.startInstall(user.id);
  }

  /**
   * The App's "Setup URL". A browser navigation (carrying the session cookie), so it answers with a redirect back to the
   * web app, never JSON. The outcome is one of a fixed set of codes.
   */
  @Get('callback')
  async callback(
    @CurrentUser() user: { id: string },
    @Query('installation_id') installationId: string | undefined,
    @Query('setup_action') setupAction: string | undefined,
    @Query('state') state: string | undefined,
    @Query('code') code: string | undefined,
    @Res() res: Response,
  ) {
    const outcome = await this.github.completeInstall(user.id, { installation_id: installationId, setup_action: setupAction, state, code });
    const web = this.config.get('WEB_URL', { infer: true });
    res.redirect(302, `${web}/repositories?github=${outcome}`);
  }

  @Get('installations')
  installations(@CurrentUser() user: { id: string }) {
    return this.github.listInstallations(user.id);
  }

  @Post('installations/:id/sync')
  @HttpCode(200)
  sync(@CurrentUser() user: { id: string }, @Param('id') id: string) {
    return this.github.syncInstallation(user.id, id);
  }

  @Delete('installations/:id')
  disconnect(@CurrentUser() user: { id: string }, @Param('id') id: string) {
    return this.github.disconnect(user.id, id);
  }
}
