import { Controller, Get, Query } from '@nestjs/common';
import { CurrentUser } from '../auth/decorators';
import { PrismaService } from '../prisma/prisma.service';
import { ListFindingsQuery } from './dto';

@Controller('findings')
export class FindingsController {
  constructor(private readonly prisma: PrismaService) {}

  @Get()
  async list(@CurrentUser() user: { id: string }, @Query() q: ListFindingsQuery) {
    return this.prisma.finding.findMany({
      where: { userId: user.id, ...(q.status && { status: q.status }), ...(q.severity && { severity: q.severity }), ...(q.source && { source: q.source }) },
      orderBy: [{ lastSeenAt: 'desc' }],
      take: 200,
      include: { target: { select: { hostname: true } }, repository: { select: { fullName: true } } },
    });
  }
}
