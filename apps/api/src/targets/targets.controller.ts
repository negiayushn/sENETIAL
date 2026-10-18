import { Body, Controller, Get, HttpCode, Param, Post } from '@nestjs/common';
import { CurrentUser } from '../auth/decorators';
import { CreateTargetDto } from './dto';
import { TargetsService } from './targets.service';

@Controller('targets')
export class TargetsController {
  constructor(private readonly targets: TargetsService) {}

  @Get()
  list(@CurrentUser() user: { id: string }) {
    return this.targets.list(user.id);
  }

  @Post()
  create(@CurrentUser() user: { id: string }, @Body() dto: CreateTargetDto) {
    return this.targets.create(user.id, dto.hostname);
  }

  /** Checks DNS for the challenge record and flips the target to VERIFIED. 200 on success, 422 with instructions otherwise. */
  @Post(':id/verify')
  @HttpCode(200)
  verify(@CurrentUser() user: { id: string }, @Param('id') id: string) {
    return this.targets.verify(user.id, id);
  }
}
