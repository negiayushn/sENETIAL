import { ConflictException, Injectable, NotFoundException, UnprocessableEntityException } from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import { challengeRecordName, challengeRecordValue, checkDnsChallenge } from '@sentinel/core';
import { Target } from '@sentinel/db';
import { RateLimitService } from '../common/rate-limit.service';
import { PrismaService } from '../prisma/prisma.service';

/** The DNS TXT record a user must publish to prove they own the target. */
function withVerification(t: Target) {
  return {
    ...t,
    verification: {
      method: 'dns-txt' as const,
      recordName: challengeRecordName(t.hostname),
      recordValue: challengeRecordValue(t.verifyToken),
    },
  };
}

const FAILURE_MESSAGES = {
  NO_RECORD: 'We could not find the TXT record yet. DNS changes can take a few minutes to propagate; check the name and value, then try again.',
  TOKEN_MISMATCH: 'A sentinel-verify record exists, but its token does not match this target. Make sure you copied the current value.',
  DNS_ERROR: 'The DNS lookup failed. Please try again in a moment.',
} as const;

@Injectable()
export class TargetsService {
  constructor(private readonly prisma: PrismaService, private readonly rateLimit: RateLimitService) {}

  async list(userId: string) {
    const targets = await this.prisma.target.findMany({ where: { userId }, orderBy: { createdAt: 'desc' } });
    return targets.map(withVerification);
  }

  async create(userId: string, hostname: string) {
    const exists = await this.prisma.target.findUnique({ where: { userId_hostname: { userId, hostname } } });
    if (exists) throw new ConflictException('This target is already registered');
    const target = await this.prisma.target.create({
      // 128 bits from the CSPRNG; this is the proof-of-ownership challenge.
      data: { userId, hostname, verifyToken: randomBytes(16).toString('hex') },
    });
    return withVerification(target);
  }

  /** Marks the target VERIFIED iff `sentinel-verify=<token>` is published at `_sentinel-challenge.<hostname>`. */
  async verify(userId: string, id: string) {
    const target = await this.prisma.target.findFirst({ where: { id, userId } });
    if (!target) throw new NotFoundException('Target not found');
    if (target.status === 'VERIFIED') return withVerification(target);

    await this.rateLimit.hit(`verify:${target.id}`, 10, 60, 'verification attempts');

    const result = await checkDnsChallenge(target.hostname, target.verifyToken);
    if (!result.verified) {
      const v = withVerification(target).verification;
      throw new UnprocessableEntityException({
        statusCode: 422,
        message: FAILURE_MESSAGES[result.reason],
        reason: result.reason,
        record: { name: v.recordName, value: v.recordValue },
      });
    }
    const updated = await this.prisma.target.update({ where: { id: target.id }, data: { status: 'VERIFIED', verifiedAt: new Date() } });
    return withVerification(updated);
  }
}
