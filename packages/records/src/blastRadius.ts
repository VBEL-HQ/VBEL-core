import type { LedgerRecord, RecordVerdict } from "./types.js";

/**
 * A record's own hash and signature can verify while it still depends on a
 * record whose payload has changed: a later record chains to an earlier one by
 * hash, without re-checking that record's payload. This walks forward through
 * previousEventHash and supersedes links from every record whose stored payload
 * no longer matches what was signed, and returns for each record the disputed
 * records it descends from. The set is empty for a record with no disputed
 * ancestor.
 *
 * It starts from `mismatch` only, never from `withheld`. A withheld payload is
 * a record somebody chose not to show, not one that failed a check, and
 * starting from it would mark every descendant of a redaction as affected.
 */
export function computeBlastRadius(
  records: LedgerRecord[],
  verdicts: Map<string, RecordVerdict>
): Map<string, Set<string>> {
  const disputedIds = new Set<string>();
  const byEventHash = new Map<string, LedgerRecord>();
  const contaminatedBy = new Map<string, Set<string>>();

  for (const r of records) {
    const id = r.event.envelope.eventId;
    contaminatedBy.set(id, new Set());
    byEventHash.set(r.event.eventHash, r);
    if (verdicts.get(id)?.payloadState === "mismatch") {
      disputedIds.add(id);
    }
  }

  const childrenOf = new Map<string, LedgerRecord[]>();
  const addChild = (parentId: string, child: LedgerRecord) => {
    let children = childrenOf.get(parentId);
    if (!children) {
      children = [];
      childrenOf.set(parentId, children);
    }
    children.push(child);
  };

  for (const r of records) {
    const prevHash = r.event.envelope.previousEventHash;
    const parent = prevHash ? byEventHash.get(prevHash) : undefined;
    if (parent) addChild(parent.event.envelope.eventId, r);

    const supersedesId = r.event.envelope.supersedes;
    if (supersedesId) addChild(supersedesId, r);
  }

  for (const disputedId of disputedIds) {
    const children = childrenOf.get(disputedId);
    if (!children || children.length === 0) continue;
    const queue = [...children];
    const visited = new Set<string>();
    let head = 0;
    while (head < queue.length) {
      const record = queue[head++]!;
      const id = record.event.envelope.eventId;
      if (visited.has(id)) continue;
      visited.add(id);
      contaminatedBy.get(id)!.add(disputedId);
      const nextChildren = childrenOf.get(id);
      if (nextChildren) {
        for (let i = 0; i < nextChildren.length; i++) {
          queue.push(nextChildren[i]!);
        }
      }
    }
  }

  return contaminatedBy;
}
