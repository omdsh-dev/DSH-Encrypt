//#region src/security/redaction/literal-matcher.d.ts
interface LiteralMatch {
  start: number;
  end: number;
  value: string;
}
/**
 * Immutable literal matcher with leftmost, longest, non-overlapping results.
 *
 * The trie walks at most the longest registered value from each candidate
 * position. Credential limits keep that bound small and predictable.
 */
declare class LiteralMatcher {
  #private;
  constructor(values: Iterable<string>);
  size(): number;
  find(text: string): LiteralMatch[];
}
//#endregion
//#region src/leak-guard.d.ts
/** Marker substituted for every detected credential occurrence. */
declare const REDACTION_MARKER = "[REDACTED:dsh-encrypt]";
interface LeakGuardOptions {
  enabled?: boolean;
  minMaskLength?: number;
  maxMaskLength?: number;
  marker?: string;
}
interface ScanResult {
  text: string;
  matched: number;
  refs: string[];
}
interface PassthroughFrame {
  passthrough: true;
  raw: Buffer;
  rest: Buffer;
}
interface ParsedFrame {
  passthrough: false;
  fin: boolean;
  opcode: number;
  headerLen: number;
  payloadLen: number;
  raw: Buffer;
  rest: Buffer;
}
/**
 * Detects registered secret values in text and replaces them with a
 * redaction marker. A literal trie resolves overlapping candidates to the
 * longest registered secret at the earliest position.
 */
declare class LeakGuard {
  #private;
  enabled: boolean;
  minMaskLength: number;
  maxMaskLength: number;
  marker: string;
  /**
   * @param {object} [options] - guard configuration.
   * @param {boolean} [options.enabled=true] - master switch.
   * @param {number} [options.minMaskLength=8] - values shorter than this are never masked.
   * @param {number} [options.maxMaskLength=256] - values longer than this are never masked.
   * @param {string} [options.marker=REDACTION_MARKER] - the replacement text.
   */
  constructor(options?: LeakGuardOptions);
  /** Number of registered secret values. */
  size(): number;
  /** Whether one value is currently registered. */
  has(value: string): boolean;
  /** The references a registered value was first seen under, if recorded. */
  refsOf(value: string): string[];
  /**
   * Register one secret value. Ignores non-strings, values outside the
   * length window, and duplicates. Adding a value invalidates the cached
   * pattern lazily (it is rebuilt on the next scan).
   * @param {string} value - the plaintext credential value.
   * @param {string} [ref] - the credential reference it belongs to (audit only).
   * @returns {boolean} true when the value newly entered the mask set.
   */
  add(value: unknown, ref?: string): boolean;
  /** Register many values at once (same rules as {@link LeakGuard.add}). */
  addAll(values: Iterable<unknown>, ref?: string): void;
  /** Replace the whole mask set with the given values. */
  rebuild(values: Iterable<unknown>, ref?: string): void;
  /** Drop every registered value (lock, password change, dispose). */
  clear(): void;
  /**
   * Scan one text and replace every registered occurrence with the marker.
   * @param {string} text - the text to scan.
   * @returns {{ text: string, matched: number, refs: string[] }} the masked
   *   text, the number of replaced occurrences, and the distinct references
   *   of the secrets that were matched.
   */
  scan(text: string): ScanResult;
  /** Alias returning only the masked text. */
  mask(text: string): string;
  /**
   * Open a streaming redaction filter. The filter refreshes its matcher for
   * every chunk, so values registered during a response protect later output.
   * @returns {RedactionStream} the filter.
   */
  stream(): RedactionStream;
  /** Current immutable matcher snapshot for a single scan operation. */
  matcherSnapshot(): LiteralMatcher | null;
}
/**
 * Chunk-boundary-safe streaming redactor. Feeds string/Buffer chunks in
 * {@link RedactionStream.push} and emits masked string pieces; the last
 * \`maxMaskLength - 1\` characters are always held back so a secret
 * split across chunks is masked as a whole before any of it is emitted.
 */
declare class RedactionStream {
  #private;
  matched: number;
  refs: string[];
  /**
   * @param {LeakGuard} guard - the owning guard (marker, length window).
   */
  constructor(guard: LeakGuard);
  /**
   * Push one chunk. Strings pass through as-is; buffers are UTF-8 decoded
   * with streaming state so multi-byte characters split across chunks stay
   * intact.
   * @param {string|Buffer|Uint8Array} chunk - the incoming bytes/text.
   * @returns {string[]} masked pieces ready to write (possibly empty).
   */
  push(chunk: string | Buffer | Uint8Array | null | undefined): string[];
  /**
   * Finish the stream: re-scan the held tail (any complete occurrence is
   * masked) and return it.
   * @returns {string} the final masked piece (possibly empty).
   */
  flush(): string;
}
/**
 * Parse one server→client WebSocket frame header from the front of a buffer.
 * Server frames are unmasked; a masked frame in this direction is a protocol
 * violation and is reported as passthrough so it is never corrupted.
 * @param {Buffer} buffer - the accumulated byte stream.
 * @returns {null | { opcode: number, fin: boolean, passthrough: boolean, headerLen: number, payloadLen: number, raw: Buffer, rest: Buffer }} null while incomplete.
 */
declare function readServerFrame(buffer: Buffer): PassthroughFrame | ParsedFrame | null;
/**
 * Build one unmasked server→client WebSocket frame (FIN set) with the
 * correct length encoding for the payload size.
 * @param {number} opcode - 0/1/2/8/9/10.
 * @param {string|Buffer|Uint8Array} payload - the frame body.
 * @returns {Buffer} the complete frame.
 */
declare function buildServerFrame(opcode: number, payload: string | Buffer | Uint8Array): Buffer;
/**
 * Incremental WebSocket frame filter: accumulates bytes, emits complete
 * frames, and redacts text-frame payloads through a scan callback. Handles
 * partial frames, several frames per write, and re-encodes the length field
 * when redaction changes the payload size.
 */
declare class WsFrameFilter {
  #private;
  matched: number;
  /** @param {(text: string) => string} scan - payload redactor. */
  constructor(scan: (text: string) => string);
  /**
   * Push one raw byte chunk (usually one socket.write payload).
   * @param {string|Buffer|Uint8Array} chunk - incoming bytes.
   * @returns {Buffer[]} complete frames ready to forward.
   */
  push(chunk: string | Buffer | Uint8Array): Buffer[];
  /** Emit whatever bytes remain (a dying socket's incomplete frame). */
  flush(): Buffer[];
}
//#endregion
export { ScanResult as a, readServerFrame as c, RedactionStream as i, LeakGuardOptions as n, WsFrameFilter as o, REDACTION_MARKER as r, buildServerFrame as s, LeakGuard as t };
//# sourceMappingURL=leak-guard-BYcHOd2D.d.ts.map