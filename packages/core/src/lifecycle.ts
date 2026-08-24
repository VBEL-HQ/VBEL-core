import type { SignedEvent } from "./envelope.js";

/**
 * Records are never overwritten or deleted (TECHNICAL-BRIEF.md §4.1). A
 * correction is a new ACTIVE event with `supersedes` set; a revocation is a
 * new REVOKED event with `revokes` set. The status shown for an OLDER event
 * is therefore derived by scanning for later events that reference it — the
 * older event's own envelope never changes, or its hash and signature would
 * break.
 */
export type DerivedStatus = "ACTIVE" | "SUPERSEDED" | "REVOKED";

export interface ChainIssue {
  eventId: string;
  message: string;
}

export interface ChainValidationResult {
  valid: boolean;
  issues: ChainIssue[];
  derivedStatus: Map<string, DerivedStatus>;
}

export function deriveStatus(events: SignedEvent[]): Map<string, DerivedStatus> {
  const status = new Map<string, DerivedStatus>();
  for (const e of events) status.set(e.envelope.eventId, "ACTIVE");
  for (const e of events) {
    if (e.envelope.supersedes) status.set(e.envelope.supersedes, "SUPERSEDED");
    if (e.envelope.revokes) status.set(e.envelope.revokes, "REVOKED");
  }
  return status;
}

/**
 * Structural validation of a set of events: previousEventHash links resolve,
 * supersedes/revokes point at events that exist, and each subject's events
 * form a single hash-linked chain. Does not verify signatures — see
 * verifyEvent in sign.ts for that, kept separate because it's async.
 */
export function validateChain(events: SignedEvent[]): ChainValidationResult {
  const issues: ChainIssue[] = [];
  const byEventId = new Map(events.map((e) => [e.envelope.eventId, e]));
  const byEventHash = new Map(events.map((e) => [e.eventHash, e]));

  for (const e of events) {
    const { eventId, previousEventHash, supersedes, revokes } = e.envelope;

    if (previousEventHash && !byEventHash.has(previousEventHash)) {
      issues.push({ eventId, message: `previousEventHash ${previousEventHash} does not match any known event` });
    }
    if (supersedes && !byEventId.has(supersedes)) {
      issues.push({ eventId, message: `supersedes references unknown eventId ${supersedes}` });
    }
    if (revokes && !byEventId.has(revokes)) {
      issues.push({ eventId, message: `revokes references unknown eventId ${revokes}` });
    }
  }

  const bySubject = new Map<string, SignedEvent[]>();
  for (const e of events) {
    const list = bySubject.get(e.envelope.subjectId) ?? [];
    list.push(e);
    bySubject.set(e.envelope.subjectId, list);
  }

  for (const [subjectId, list] of bySubject) {
    const sorted = [...list].sort((a, b) => a.envelope.issuedAt.localeCompare(b.envelope.issuedAt));
    for (let i = 1; i < sorted.length; i++) {
      const prev = sorted[i - 1]!;
      const curr = sorted[i]!;
      if (curr.envelope.previousEventHash !== prev.eventHash) {
        issues.push({
          eventId: curr.envelope.eventId,
          message: `chain break for subject ${subjectId}: expected previousEventHash ${prev.eventHash}, got ${curr.envelope.previousEventHash ?? "null"}`,
        });
      }
    }
  }

  return { valid: issues.length === 0, issues, derivedStatus: deriveStatus(events) };
}
