/**
 * The readable text a signer sees, for signatures produced by a wallet rather
 * than by code holding a key.
 *
 * The original scheme signs the digest string itself. That stays the default,
 * but a wallet would show the signer `sha256:8f3a...` and ask them to approve
 * it, which is blind signing. Attributable consent needs text a person can read.
 *
 * Two properties make this safe to put in the record format:
 *
 *   The text is stored verbatim in `SignatureBlock.message`, and the signature
 *   is verified over the stored text rather than a reconstruction. Under
 *   selective disclosure a verifier may hold the envelope with the payload
 *   sealed, and a reconstructed message could then only contain envelope
 *   fields. Storing the text lets it quote payload content (an amount, say)
 *   and still be verified with the payload sealed.
 *
 *   The digest is the last line, and verification parses that line rather than
 *   searching the text. A frontend cannot show a signer one digest and commit
 *   them to another buried elsewhere, because line breaks are rejected inside
 *   entries and only the final line counts.
 *
 * It does not prove that a quoted amount matches the payload the digest commits
 * to. Both are signed by the same party, so a contradiction is attributable,
 * and `contradictedFacts` reports it to anyone holding the payload. The text is
 * what the signer agreed to, not evidence about the payload.
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
 * What a caller supplies. `commitsTo` is absent because the signing path
 * computes the digest from the envelope. A caller able to choose it could
 * commit a signer to a record they were not shown.
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
 * Drops the fields a decoder restores anyway, for records put on a wire where
 * every character counts.
 *
 * A chain travels as a URL, and a few records have to stay within a length a
 * phone camera can scan. Writing `scheme` and `message` at their defaults
 * spends that budget on nothing, and omitting them keeps digest-signed records
 * byte-identical to their earlier encoding. Only a record that carries readable
 * text pays for it.
 *
 * `SignatureBlockSchema` restores both on parse, which is what makes this safe.
 */
export function compactSignatureBlock<T extends { scheme: string; message: string | null }>(
  block: T
): Partial<T> {
  const compact: Partial<T> = { ...block };
  if (block.scheme === SIGNATURE_SCHEME_EVENT_HASH) delete compact.scheme;
  if (block.message === null) delete compact.message;
  return compact;
}

/**
 * Facts the signer was shown that the record itself contradicts. The caller
 * supplies the truth, because only they know which payload fields the labels
 * were meant to quote. A label with no counterpart in `truth` is not a
 * contradiction: a message may say more than the payload does.
 */
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
