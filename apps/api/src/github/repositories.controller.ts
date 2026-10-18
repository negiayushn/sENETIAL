import { Controller, Get, HttpCode, Param, Post, Query } from '@nestjs/common';
import { CurrentUser } from '../auth/decorators';
import { RepositoriesService } from './repositories.service';

const int = (v: string | undefined, def: number, min: number, max: number) => {
  const n = Number.parseInt(v ?? '', 10);
  return Number.isFinite(n) ? Math.min(Math.max(n, min), max) : def;
};

@Controller('repositories')
export class RepositoriesController {
  constructor(private readonly repos: RepositoriesService) {}

  @Get()
  list(@CurrentUser() user: { id: string }) {
    return this.repos.list(user.id);
  }

  /** 202: queued (or already in progress). Poll GET /repositories. */
  @Post(':id/inventory')
  @HttpCode(202)
  requestInventory(@CurrentUser() user: { id: string }, @Param('id') id: string) {
    return this.repos.requestInventory(user.id, id);
  }

  /** 202: queued. Matching also runs automatically after each inventory. */
  @Post(':id/match')
  @HttpCode(202)
  requestMatch(@CurrentUser() user: { id: string }, @Param('id') id: string) {
    return this.repos.requestMatch(user.id, id);
  }

  @Get(':id/inventory')
  inventory(
    @CurrentUser() user: { id: string },
    @Param('id') id: string,
    @Query('take') take?: string,
    @Query('skip') skip?: string,
    @Query('direct') direct?: string,
  ) {
    return this.repos.inventory(user.id, id, { take: int(take, 100, 1, 500), skip: int(skip, 0, 0, 1_000_000), directOnly: direct === 'true' });
  }
}
