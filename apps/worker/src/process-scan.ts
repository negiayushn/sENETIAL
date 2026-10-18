import {
  BlockedAddressError, fingerprint, redactEvidence, runScan as realRunScan, SsrfError,
  type ScanResult,
} from '@sentinel/core';
import type { Prisma, PrismaClient } from '@sentinel/db';

export interface Log {
  info(obj: object, msg?: string): void;
  warn(obj: object, msg?: string): void;
  error(obj: object, msg?: string): void;
}

export interface ScanDeps {
  prisma: PrismaClient;
  log: Log;
  /** Called when the scan reaches a terminal state, so the per-target "scan in progress" lock is released. */
  releaseLock: (targetId: string, scanId: string) => Promise<void>;
  /** Injectable for tests */
  run?: (hostname: string) => Promise<ScanResult>;
}

/** Messages shown to the user. Never include raw error text, stack traces, or internal addresses. */
function userMessage(err: unknown): string {
  if (err instanceof BlockedAddressError) return 'The hostname resolves to a non-public address, so it cannot be scanned.';
  if (err instanceof SsrfError) return 'The scan was blocked by Sentinel’s network safety rules.';
  const code = (err as NodeJS.ErrnoException)?.code;
  if (code === 'ENOTFOUND' || code === 'ENODATA') return 'The hostname could not be resolved in DNS.';
  return 'The scan failed unexpectedly. Please try again.';
}

export const NOT_VERIFIED_MESSAGE = 'This target is not verified. Verify ownership before scanning.';

/**
 * Executes one scan. The job only tells us WHICH scan; everything else (hostname, owner, verification status)
 * is read from the database here, so a forged or stale queue message can never make us scan an arbitrary host.
 */
export async function processScan(scanId: string, deps: ScanDeps): Promise<void> {
  const { prisma, log } = deps;

  const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { target: true } });
  if (!scan) {
    log.warn({ scanId }, 'scan not found (deleted?), dropping job');
    return;
  }
  if (scan.status === 'SUCCEEDED' || scan.status === 'FAILED') {
    log.info({ scanId, status: scan.status }, 'scan already finished, ignoring duplicate delivery');
    return;
  }

  const finish = (data: Prisma.ScanUpdateInput) => prisma.scan.update({ where: { id: scanId }, data: { finishedAt: new Date(), ...data } });

  try {
    // ── Verification gate. Enforced here, not only in the API: the worker is the thing that touches the network. ──
    if (scan.target.status !== 'VERIFIED' || scan.target.userId !== scan.userId) {
      log.warn({ scanId, targetId: scan.targetId, targetStatus: scan.target.status }, 'refusing to scan unverified target');
      await finish({ status: 'FAILED', error: NOT_VERIFIED_MESSAGE });
      return;
    }

    await prisma.scan.update({ where: { id: scanId }, data: { status: 'RUNNING', startedAt: new Date(), error: null } });
    log.info({ scanId, hostname: scan.target.hostname }, 'scan started');

    const result = await (deps.run ?? ((h: string) => realRunScan({ hostname: h })))(scan.target.hostname);

    // If NOTHING could run (e.g. host unreachable) this is a failed scan, not a clean one.
    if (result.checks.length > 0 && result.checks.every((c) => c.status === 'error')) {
      await finish({ status: 'FAILED', error: result.checks[0].error ?? 'No check could complete.', summary: summarise(result) });
      log.warn({ scanId }, 'scan failed: every check errored');
      return;
    }

    await saveFindings(deps, scan.id, scan.userId, scan.targetId, result);
    await finish({ status: 'SUCCEEDED', summary: summarise(result) });
    log.info({ scanId, findings: result.findings.length, requests: result.requests }, 'scan finished');
  } catch (err) {
    log.error({ scanId, err }, 'scan crashed');
    await finish({ status: 'FAILED', error: userMessage(err) }).catch((e) => log.error({ scanId, err: e }, 'could not record scan failure'));
    throw err; // BullMQ marks the job failed (attempts=1, so no retry)
  } finally {
    await deps.releaseLock(scan.targetId, scan.id).catch((e) => log.error({ scanId, err: e }, 'could not release scan lock'));
  }
}

function summarise(r: ScanResult): Prisma.InputJsonObject {
  const bySeverity: Record<string, number> = {};
  for (const f of r.findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  return {
    requests: r.requests,
    checks: r.checks.map((c) => ({ ...c })),
    findings: { total: r.findings.length, bySeverity },
    partial: r.checks.some((c) => c.status === 'error'),
  };
}

/**
 * Upsert by fingerprint, in ONE transaction so a scan's findings appear atomically.
 *  - new fingerprint        → created OPEN
 *  - known fingerprint      → severity/title/evidence/lastSeenAt refreshed; firstSeenAt and the user's triage status
 *                             (ACKNOWLEDGED / IGNORED) are left alone
 *  - previously FIXED       → REOPENED (the problem came back)
 * Evidence is redacted here, after the checks, as a last line of defence.
 */
async function saveFindings(deps: ScanDeps, scanId: string, userId: string, targetId: string, result: ScanResult) {
  const now = new Date();
  const ops = result.findings.flatMap((f) => {
    const fp = fingerprint({ source: 'WEB', owner: targetId, type: f.type, key: f.key });
    const data = {
      type: f.type,
      title: f.title,
      severity: f.severity,
      confidence: f.confidence,
      remediation: f.remediation ?? null,
      evidence: redactEvidence(f.evidence ?? {}) as Prisma.InputJsonObject,
      lastSeenAt: now,
      lastScanId: scanId,
    };
    return [
      deps.prisma.finding.updateMany({ where: { fingerprint: fp, status: 'FIXED' }, data: { status: 'REOPENED' } }),
      deps.prisma.finding.upsert({
        where: { fingerprint: fp },
        create: { ...data, fingerprint: fp, source: 'WEB', userId, targetId },
        update: data,
      }),
    ];
  });
  if (ops.length) await deps.prisma.$transaction(ops);
}
