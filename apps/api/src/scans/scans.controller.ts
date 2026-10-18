import { Controller, Get, HttpCode, Param, Post } from '@nestjs/common';
import { CurrentUser } from '../auth/decorators';
import { ScansService } from './scans.service';

@Controller()
export class ScansController {
  constructor(private readonly scans: ScansService) {}

  /** 202: the scan is queued, not done. Poll GET /scans/:id. */
  @Post('targets/:id/scans')
  @HttpCode(202)
  create(@CurrentUser() user: { id: string }, @Param('id') targetId: string) {
    return this.scans.create(user.id, targetId);
  }

  @Get('targets/:id/scans')
  list(@CurrentUser() user: { id: string }, @Param('id') targetId: string) {
    return this.scans.listForTarget(user.id, targetId);
  }

  @Get('scans/:id')
  get(@CurrentUser() user: { id: string }, @Param('id') id: string) {
    return this.scans.get(user.id, id);
  }
}
