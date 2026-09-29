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
  const disputedIds = new Set(
    records
      .filter((r) => verdicts.get(r.event.envelope.eventId)?.payloadState === "mismatch")
      .map((r) => r.event.envelope.eventId)
  );

  const byEventHash = new Map(records.map((r) => [r.event.eventHash, r]));
  const childrenOf = new Map<string, LedgerRecord[]>();
  const addChild = (parentId: string, child: LedgerRecord) => {
    childrenOf.set(parentId, [...(childrenOf.get(parentId) ?? []), child]);
  };
  for (const r of records) {
    const prevHash = r.event.envelope.previousEventHash;
    const parent = prevHash ? byEventHash.get(prevHash) : undefined;
    if (parent) addChild(parent.event.envelope.eventId, r);

    const supersedesId = r.event.envelope.supersedes;
    if (supersedesId) addChild(supersedesId, r);
  }

  const contaminatedBy = new Map<string, Set<string>>();
  for (const r of records) contaminatedBy.set(r.event.envelope.eventId, new Set());

  for (const disputedId of disputedIds) {
    const queue = [...(childrenOf.get(disputedId) ?? [])];
    const visited = new Set<string>();
    while (queue.length > 0) {
      const record = queue.shift()!;
      const id = record.event.envelope.eventId;
      if (visited.has(id)) continue;
      visited.add(id);
      contaminatedBy.get(id)!.add(disputedId);
      for (const child of childrenOf.get(id) ?? []) queue.push(child);
    }
  }

  return contaminatedBy;
}
