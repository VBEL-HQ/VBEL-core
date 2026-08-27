import type { LedgerRecord, RecordVerdict } from "./types";

/**
 * A record's own hash and signature can verify perfectly while it still
 * depends on a fact currently in dispute — a correction chains to an
 * acceptance by hash, not by re-checking that acceptance's payload every
 * time. This walks forward through previousEventHash and supersedes links
 * from every record whose stored payload no longer matches what was signed,
 * and returns, for each record, which disputed record(s) it descends from.
 * Empty for a record with no disputed ancestor.
 */
export function computeBlastRadius(
  records: LedgerRecord[],
  verdicts: Map<string, RecordVerdict>
): Map<string, Set<string>> {
  const disputedIds = new Set(
    records
      .filter((r) => verdicts.get(r.event.envelope.eventId)?.payloadValid === false)
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
