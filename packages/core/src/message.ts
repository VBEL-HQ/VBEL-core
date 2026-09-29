/**
 * The readable text a signer actually sees, for signatures produced by a
 * wallet rather than by code holding a key.
 *
 * The original scheme signs the digest string itself. That is correct and
 * stays the default, but when the signing surface is a wallet the signer is
 * shown `sha256:8f3a...` and asked to approve it, which is blind signing with
 * extra steps. A product whose whole claim is attributable consent cannot ask
 * for consent to an opaque string.
 *
 * Two properties make this safe to put in the record format:
 *
 *   The text is stored verbatim, in `SignatureBlock.message`, and the
 *   signature is verified over the stored text. It is not reconstructed.
 *   Reconstruction would have forced the message to contain only envelope
 *   fields, because under selective disclosure a verifier may hold the
 *   envelope with the payload sealed, and the amount lives in the payload.
 *   Quoting the amount and reconstructing it are mutually exclusive; storing
 *   it keeps both the legible wallet screen and the sealed-payload verifier.
 *
 *   The digest is not merely present in the text, it is the last line, and
 *   verification parses that line rather than searching the text. A frontend
 *   cannot show a signer a flattering digest on one line and quietly commit
 *   them to a different one buried in another, because line breaks are
 *   rejected inside entries and only the final line counts.
 *
 * What it still does not prove: that a quoted amount matches the payload the
 * digest commits to. Both are signed by the same party, so a contradiction is
 * attributable rather than deniable, and `contradictedFacts` reports it to
 * anyone holding the payload. The text is what the signer agreed to, never
 * evidence about the payload.
 */

/** Identifies the scheme in `SignatureBlock.scheme`. */
export const SIGNATURE_SCHEME_EVENT_HASH = "event-hash";
export const SIGNATURE_SCHEME_MESSAGE_V1 = "vbel-message-v1";

const HEADER = `VBEL record (${SIGNATURE_SCHEME_MESSAGE_V1})`;
const COMMITS_PREFIX = "Commits to: ";
const SEPARATOR = ": ";

export interface MessageEntry {
  label: string;
  value: string;
}

export interface SigningMessage {
  /** One line of plain language: what the signer is agreeing to do. */
  action: string;
  entries: MessageEntry[];
  /** The digest this signature commits to. */
  commitsTo: string;
}

/**
 * What a caller supplies. `commitsTo` is not among the fields because the
 * digest is computed from the envelope by the signing path, never passed in:
 * a caller able to choose it could commit a signer to a record they were not
 * shown.
 */
export interface SigningMessageRequest {
  action: string;
  /**
   * Facts worth reading before approving, in the order they should be read.
   * May quote payload content, which is the point.
   */
  entries?: MessageEntry[];
}

function assertSingleLine(value: string, what: string): void {
  if (value.length === 0) {
    throw new Error(`signing message ${what} is empty`);
  }
  if (/[\r\n]/.test(value)) {
    throw new Error(`signing message ${what} contains a line break, which would forge the structure`);
  }
}

function assertLabel(label: string): void {
  assertSingleLine(label, "label");
  if (label.includes(":")) {
    throw new Error(`signing message label ${JSON.stringify(label)} contains a colon, which would make the line ambiguous`);
  }
}

export function buildSigningMessage(message: SigningMessage): string {
  assertSingleLine(message.action, "action");
  assertSingleLine(message.commitsTo, "commitsTo");
  for (const entry of message.entries) {
    assertLabel(entry.label);
    assertSingleLine(entry.value, `value for ${entry.label}`);
  }

  const lines = [HEADER, message.action];
  if (message.entries.length > 0) {
    lines.push("", ...message.entries.map((e) => `${e.label}${SEPARATOR}${e.value}`));
  }
  lines.push("", COMMITS_PREFIX + message.commitsTo);
  return lines.join("\n");
}

/** Null when the text is not a well formed v1 message. Callers treat that as a failed signature, never as an empty one. */
export function parseSigningMessage(text: string): SigningMessage | null {
  const lines = text.split("\n");
  if (lines.length < 3 || lines[0] !== HEADER) return null;

  const last = lines[lines.length - 1] ?? "";
  if (!last.startsWith(COMMITS_PREFIX)) return null;
  const commitsTo = last.slice(COMMITS_PREFIX.length);
  if (commitsTo.length === 0) return null;

  const action = lines[1] ?? "";
  if (action.length === 0) return null;

  const entries: MessageEntry[] = [];
  for (const line of lines.slice(2, -1)) {
    if (line.length === 0) continue;
    const at = line.indexOf(SEPARATOR);
    if (at <= 0) return null;
    entries.push({ label: line.slice(0, at), value: line.slice(at + SEPARATOR.length) });
  }

  return { action, entries, commitsTo };
}

/**
 * Facts the signer was shown that the record itself contradicts. The caller
 * supplies the truth, because only they know which payload fields the labels
 * were meant to quote, and a label with no counterpart in `truth` is not a
 * contradiction: a message may legitimately say more than the payload does.
 */
/**
 * Drops the fields a decoder restores anyway, for callers that put records on a
 * wire where every character is paid for.
 *
 * A chain travels as a URL, and the budget for one is real: three records have
 * to stay inside a length a phone camera can scan. Writing `scheme` and
 * `message` when they hold their defaults spends that budget on nothing, and it
 * makes a digest-signed record encode differently than it did before the
 * readable scheme existed, for no gain. Omitting them keeps those records byte
 * identical to the ones already in circulation, so only a record that really
 * carries readable text pays for it.
 *
 * `SignatureBlockSchema` restores both on parse, which is what makes this safe
 * rather than clever.
 */
export function compactSignatureBlock<T extends { scheme: string; message: string | null }>(
  block: T
): Partial<T> {
  const compact: Partial<T> = { ...block };
  if (block.scheme === SIGNATURE_SCHEME_EVENT_HASH) delete compact.scheme;
  if (block.message === null) delete compact.message;
  return compact;
}

export function contradictedFacts(
  message: SigningMessage,
  truth: Record<string, string>
): MessageEntry[] {
  const byLabel = new Map(Object.entries(truth).map(([k, v]) => [k.toLowerCase(), v]));
  return message.entries.filter((entry) => {
    const expected = byLabel.get(entry.label.toLowerCase());
    return expected !== undefined && expected !== entry.value;
  });
}
