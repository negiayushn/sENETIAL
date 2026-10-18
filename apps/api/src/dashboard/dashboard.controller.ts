import { Controller, Get } from '@nestjs/common';
import { CurrentUser } from '../auth/decorators';
import { PrismaService } from '../prisma/prisma.service';

@Controller('dashboard')
export class DashboardController {
  constructor(private readonly prisma: PrismaService) {}

  @Get('summary')
  async summary(@CurrentUser() user: { id: string }) {
    const [targets, verifiedTargets, repositories, inventoriedRepositories, openBySeverity] = await Promise.all([
      this.prisma.target.count({ where: { userId: user.id } }),
      this.prisma.target.count({ where: { userId: user.id, status: 'VERIFIED' } }),
      this.prisma.repository.count({ where: { userId: user.id } }),
      this.prisma.repository.count({ where: { userId: user.id, inventoryStatus: 'SUCCEEDED' } }),
      this.prisma.finding.groupBy({
        by: ['severity'],
        where: { userId: user.id, status: { in: ['OPEN', 'REOPENED'] } },
        _count: { _all: true },
      }),
    ]);
    const severity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const row of openBySeverity) severity[row.severity] = row._count._all;
    return {
      targets,
      verifiedTargets,
      repositories,
      inventoriedRepositories,
      openFindings: Object.values(severity).reduce((a, b) => a + b, 0),
      openBySeverity: severity,
      // Phase 5 will populate this from SyncState; the UI already renders it honestly.
      lastIntelligenceSync: null as string | null,
    };
  }
}
