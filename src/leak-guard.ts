import type { LiteralMatch } from './security/redaction/literal-matcher.js'
/**
 * Credential leak guard — the pure, dependency-free detection layer of
 * dsh-encrypt's prompt-injection / credential-exfiltration defense.
 *
 * While the vault is unlocked, the provider registers the plaintext of every
 * credential it actually resolves. The guard then detects those values in
 * text it is asked to scan — model output streams, HTTP responses, WebSocket
 * frames — and replaces each occurrence with {@link REDACTION_MARKER}.
 *
 * Streaming correctness: {@link RedactionStream} never emits the last
 * \`maxMaskLength - 1\` characters of its masked input. A secret that
 * straddles a chunk boundary therefore stays held until it either completes
 * (and is masked as a whole) or the stream ends (and the held tail is
 * re-scanned in {@link RedactionStream.flush}). No emitted piece can ever
 * contain a prefix of a secret whose remainder arrives later. Redaction
 * markers that straddle a chunk boundary may be split across pieces — a
 * cosmetic trade-off, never a leak.
 *
 * Honest limits: only values the provider has actually resolved are known
 * (a secret the model never received cannot be echoed either); short values
 * (< minMaskLength) are not masked to avoid mangling ordinary prose; a
 * determined exfiltrator that splits or re-encodes a secret can defeat
 * substring matching. This layer shrinks the accidental-leak surface — it is
 * not a sandbox.
 * @module dsh-encrypt/leak-guard
 */
import { LiteralMatcher } from './security/redaction/literal-matcher.js'

/** Marker substituted for every detected credential occurrence. */
export const REDACTION_MARKER = '[REDACTED:dsh-encrypt]'

export interface LeakGuardOptions {
  enabled?: boolean
  minMaskLength?: number
  maxMaskLength?: number
  marker?: string
}

export interface ScanResult {
  text: string
  matched: number
  refs: string[]
}

interface SecretEntry {
  refs: Set<string>
}

interface PassthroughFrame {
  passthrough: true
  raw: Buffer
  rest: Buffer
}

interface ParsedFrame {
  passthrough: false
  fin: boolean
  opcode: number
  headerLen: number
  payloadLen: number
  raw: Buffer
  rest: Buffer
}

/**
 * Detects registered secret values in text and replaces them with a
 * redaction marker. A literal trie resolves overlapping candidates to the
 * longest registered secret at the earliest position.
 */
export class LeakGuard {
  #values = /* @__PURE__ */ new Map<string, SecretEntry>()
  #matcher: LiteralMatcher | null = null
  enabled: boolean
  minMaskLength: number
  maxMaskLength: number
  marker: string
  /**
   * @param {object} [options] - guard configuration.
   * @param {boolean} [options.enabled=true] - master switch.
   * @param {number} [options.minMaskLength=8] - values shorter than this are never masked.
   * @param {number} [options.maxMaskLength=256] - values longer than this are never masked.
   * @param {string} [options.marker=REDACTION_MARKER] - the replacement text.
   */
  constructor(options: LeakGuardOptions = {}) {
    this.enabled = options.enabled ?? true
    this.minMaskLength = options.minMaskLength ?? 8
    this.maxMaskLength = options.maxMaskLength ?? 256
    this.marker = options.marker ?? REDACTION_MARKER
  }
  /** Number of registered secret values. */
  size(): number {
    return this.#values.size
  }
  /** Whether one value is currently registered. */
  has(value: string): boolean {
    return this.#values.has(value)
  }
  /** The references a registered value was first seen under, if recorded. */
  refsOf(value: string): string[] {
    return [...(this.#values.get(value)?.refs ?? [])]
  }
  /**
   * Register one secret value. Ignores non-strings, values outside the
   * length window, and duplicates. Adding a value invalidates the cached
   * pattern lazily (it is rebuilt on the next scan).
   * @param {string} value - the plaintext credential value.
   * @param {string} [ref] - the credential reference it belongs to (audit only).
   * @returns {boolean} true when the value newly entered the mask set.
   */
  add(value: unknown, ref?: string): boolean {
    if (typeof value !== 'string' || value.length < this.minMaskLength || value.length > this.maxMaskLength)
      return false
    const existing = this.#values.get(value)
    if (existing !== void 0) {
      if (ref !== void 0) existing.refs.add(ref)
      return false
    }
    this.#values.set(value, { refs: /* @__PURE__ */ new Set(ref !== void 0 ? [ref] : []) })
    this.#matcher = null
    return true
  }
  /** Register many values at once (same rules as {@link LeakGuard.add}). */
  addAll(values: Iterable<unknown>, ref?: string): void {
    for (const value of values) this.add(value, ref)
  }
  /** Replace the whole mask set with the given values. */
  rebuild(values: Iterable<unknown>, ref?: string): void {
    this.clear()
    this.addAll(values, ref)
  }
  /** Drop every registered value (lock, password change, dispose). */
  clear(): void {
    this.#values.clear()
    this.#matcher = null
  }
  /**
   * Scan one text and replace every registered occurrence with the marker.
   * @param {string} text - the text to scan.
   * @returns {{ text: string, matched: number, refs: string[] }} the masked
   *   text, the number of replaced occurrences, and the distinct references
   *   of the secrets that were matched.
   */
  scan(text: string): ScanResult {
    if (text.length === 0 || !this.enabled || this.#values.size === 0) return { text, matched: 0, refs: [] }
    const matcher = this.#matcherFor()
    if (matcher === null) return { text, matched: 0, refs: [] }
    const refs: string[] = []
    const matches = matcher.find(text)
    let masked = ''
    let cursor = 0
    for (const match of matches) {
      masked += text.slice(cursor, match.start) + this.marker
      cursor = match.end
      const entry = this.#values.get(match.value)
      if (entry !== void 0) {
        for (const ref of entry.refs) {
          if (!refs.includes(ref)) refs.push(ref)
        }
      }
    }
    masked += text.slice(cursor)
    return { text: masked, matched: matches.length, refs }
  }
  /** Alias returning only the masked text. */
  mask(text: string): string {
    return this.scan(text).text
  }
  /**
   * Open a streaming redaction filter. The filter refreshes its matcher for
   * every chunk, so values registered during a response protect later output.
   * @returns {RedactionStream} the filter.
   */
  stream(): RedactionStream {
    return new RedactionStream(this)
  }
  /** Current immutable matcher snapshot for a single scan operation. */
  matcherSnapshot(): LiteralMatcher | null {
    return this.#matcherFor()
  }
  /** Build or reuse the immutable literal-matcher snapshot. */
  #matcherFor(): LiteralMatcher | null {
    if (this.#matcher === null) {
      const matcher = new LiteralMatcher(this.#values.keys())
      this.#matcher = matcher.size() === 0 ? null : matcher
    }
    return this.#matcher
  }
}

/**
 * Chunk-boundary-safe streaming redactor. Feeds string/Buffer chunks in
 * {@link RedactionStream.push} and emits masked string pieces; the last
 * \`maxMaskLength - 1\` characters are always held back so a secret
 * split across chunks is masked as a whole before any of it is emitted.
 */
export class RedactionStream {
  #guard: LeakGuard
  #hold: number
  #tail = ''
  #decoder = new TextDecoder()
  matched = 0
  refs: string[] = []
  /**
   * @param {LeakGuard} guard - the owning guard (marker, length window).
   */
  constructor(guard: LeakGuard) {
    this.#guard = guard
    this.#hold = Math.max(0, guard.maxMaskLength - 1)
  }
  /**
   * Push one chunk. Strings pass through as-is; buffers are UTF-8 decoded
   * with streaming state so multi-byte characters split across chunks stay
   * intact.
   * @param {string|Buffer|Uint8Array} chunk - the incoming bytes/text.
   * @returns {string[]} masked pieces ready to write (possibly empty).
   */
  push(chunk: string | Buffer | Uint8Array | null | undefined): string[] {
    if (chunk === void 0 || chunk === null) return []
    const matcher = this.#guard.matcherSnapshot()
    if (!this.#guard.enabled || matcher === null) {
      const text = typeof chunk === 'string' ? chunk : this.#decoder.decode(chunk, { stream: true })
      return text.length === 0 ? [] : [text]
    }
    const text = typeof chunk === 'string' ? chunk : this.#decoder.decode(chunk, { stream: true })
    if (text.length === 0) return []
    const combined = this.#tail + text
    const matches: LiteralMatch[] = matcher.find(combined)
    let emitEnd = Math.max(0, combined.length - this.#hold)
    // A match crossing the emit boundary would leak its prefix; hold back
    // to its start so the whole secret stays intact for the next round.
    for (const match of matches) {
      if (match.start < emitEnd && match.end > emitEnd) emitEnd = match.start
    }
    let output = ''
    let cursor = 0
    for (const match of matches) {
      if (match.start >= emitEnd) break
      output += combined.slice(cursor, match.start) + this.#guard.marker
      cursor = match.end
      this.matched++
      const entry = this.#guard.refsOf(match.value)
      for (const ref of entry) {
        if (!this.refs.includes(ref)) this.refs.push(ref)
      }
    }
    output += combined.slice(cursor, emitEnd)
    this.#tail = combined.slice(emitEnd)
    return output.length === 0 ? [] : [output]
  }
  /**
   * Finish the stream: re-scan the held tail (any complete occurrence is
   * masked) and return it.
   * @returns {string} the final masked piece (possibly empty).
   */
  flush(): string {
    const matcher = this.#guard.matcherSnapshot()
    if (!this.#guard.enabled || matcher === null) {
      const tail = this.#tail
      this.#tail = ''
      return tail
    }
    const tail = this.#tail
    this.#tail = ''
    const matches: LiteralMatch[] = matcher.find(tail)
    let output = tail
    let shift = 0
    for (const match of matches) {
      const start = match.start + shift
      const end = match.end + shift
      output = output.slice(0, start) + this.#guard.marker + output.slice(end)
      shift += this.#guard.marker.length - (match.end - match.start)
      this.matched++
      for (const ref of this.#guard.refsOf(match.value)) {
        if (!this.refs.includes(ref)) this.refs.push(ref)
      }
    }
    return output
  }
}

/**
 * Parse one server→client WebSocket frame header from the front of a buffer.
 * Server frames are unmasked; a masked frame in this direction is a protocol
 * violation and is reported as passthrough so it is never corrupted.
 * @param {Buffer} buffer - the accumulated byte stream.
 * @returns {null | { opcode: number, fin: boolean, passthrough: boolean, headerLen: number, payloadLen: number, raw: Buffer, rest: Buffer }} null while incomplete.
 */
export function readServerFrame(buffer: Buffer): PassthroughFrame | ParsedFrame | null {
  if (buffer.length < 2) return null
  const b0 = buffer.readUInt8(0)
  const b1 = buffer.readUInt8(1)
  const fin = (b0 & 128) !== 0
  const opcode = b0 & 15
  const masked = (b1 & 128) !== 0
  const len7 = b1 & 127
  let headerLen = 2
  let payloadLen = len7
  if (len7 === 126) {
    if (buffer.length < 4) return null
    payloadLen = buffer.readUInt16BE(2)
    headerLen = 4
  } else if (len7 === 127) {
    if (buffer.length < 10) return null
    const hi = buffer.readUInt32BE(2)
    const lo = buffer.readUInt32BE(6)
    if (hi > 2097151) return { passthrough: true, raw: buffer, rest: Buffer.alloc(0) }
    payloadLen = hi * 4294967296 + lo
    headerLen = 10
  }
  const total = headerLen + payloadLen
  if (buffer.length < total) return null
  if (masked) {
    return {
      passthrough: true,
      raw: buffer.subarray(0, total),
      rest: buffer.subarray(total),
    }
  }
  return {
    fin,
    opcode,
    passthrough: false,
    headerLen,
    payloadLen,
    raw: buffer.subarray(0, total),
    rest: buffer.subarray(total),
  }
}

/**
 * Build one unmasked server→client WebSocket frame (FIN set) with the
 * correct length encoding for the payload size.
 * @param {number} opcode - 0/1/2/8/9/10.
 * @param {string|Buffer|Uint8Array} payload - the frame body.
 * @returns {Buffer} the complete frame.
 */
export function buildServerFrame(opcode: number, payload: string | Buffer | Uint8Array): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : Buffer.from(payload)
  let header: Buffer
  if (body.length < 126) {
    header = Buffer.from([128 | (opcode & 15), body.length])
  } else if (body.length < 65536) {
    header = Buffer.alloc(4)
    header[0] = 128 | (opcode & 15)
    header[1] = 126
    header.writeUInt16BE(body.length, 2)
  } else {
    header = Buffer.alloc(10)
    header[0] = 128 | (opcode & 15)
    header[1] = 127
    header.writeUInt32BE(Math.floor(body.length / 4294967296), 2)
    header.writeUInt32BE(body.length >>> 0, 6)
  }
  return Buffer.concat([header, body])
}

/**
 * Incremental WebSocket frame filter: accumulates bytes, emits complete
 * frames, and redacts text-frame payloads through a scan callback. Handles
 * partial frames, several frames per write, and re-encodes the length field
 * when redaction changes the payload size.
 */
export class WsFrameFilter {
  #buffer: Buffer = Buffer.alloc(0)
  #scan: (text: string) => string
  #textFragments: Buffer[] | null = null
  #textFragmentBytes = 0
  #binaryFragment = false
  matched = 0
  /** @param {(text: string) => string} scan - payload redactor. */
  constructor(scan: (text: string) => string) {
    this.#scan = scan
  }
  /**
   * Push one raw byte chunk (usually one socket.write payload).
   * @param {string|Buffer|Uint8Array} chunk - incoming bytes.
   * @returns {Buffer[]} complete frames ready to forward.
   */
  push(chunk: string | Buffer | Uint8Array): Buffer[] {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    this.#buffer = this.#buffer.length === 0 ? buf : Buffer.concat([this.#buffer, buf])
    const out: Buffer[] = []
    for (;;) {
      const frame = readServerFrame(this.#buffer)
      if (frame === null) break
      if (frame.passthrough) {
        throw new Error('dsh-encrypt: unsupported or invalid server WebSocket frame')
      }
      const { fin, opcode, headerLen, payloadLen, raw, rest } = frame
      if (((raw[0] ?? 0) & 0x70) !== 0)
        throw new Error('dsh-encrypt: WebSocket extension frames are not accepted by the redaction layer')
      const payload = raw.subarray(headerLen, headerLen + payloadLen)
      this.#buffer = rest
      if (opcode === 1) {
        if (this.#textFragments !== null || this.#binaryFragment)
          throw new Error('dsh-encrypt: invalid nested WebSocket data message')
        if (!fin) {
          this.#textFragments = [Buffer.from(payload)]
          this.#textFragmentBytes = payload.length
          continue
        }
        const text = payload.toString('utf8')
        const masked = this.#scan(text)
        if (masked !== text) {
          this.matched++
          out.push(buildServerFrame(opcode, masked))
          continue
        }
        out.push(raw)
        continue
      }
      if (opcode === 0 && this.#textFragments !== null) {
        this.#textFragmentBytes += payload.length
        if (this.#textFragmentBytes > 8 * 1024 * 1024)
          throw new Error('dsh-encrypt: fragmented WebSocket text message exceeds 8 MiB')
        this.#textFragments.push(Buffer.from(payload))
        if (!fin) continue
        const text = Buffer.concat(this.#textFragments, this.#textFragmentBytes).toString('utf8')
        this.#textFragments = null
        this.#textFragmentBytes = 0
        const masked = this.#scan(text)
        if (masked !== text) this.matched++
        out.push(buildServerFrame(1, masked))
        continue
      }
      if (opcode === 2) {
        if (this.#textFragments !== null || this.#binaryFragment)
          throw new Error('dsh-encrypt: invalid nested WebSocket data message')
        this.#binaryFragment = !fin
        out.push(raw)
        continue
      }
      if (opcode === 0 && this.#binaryFragment) {
        this.#binaryFragment = !fin
        out.push(raw)
        continue
      }
      if (opcode === 0) throw new Error('dsh-encrypt: unexpected WebSocket continuation frame')
      out.push(raw)
    }
    return out
  }
  /** Emit whatever bytes remain (a dying socket's incomplete frame). */
  flush(): Buffer[] {
    const rest = this.#buffer
    this.#buffer = Buffer.alloc(0)
    return rest.length > 0 ? [rest] : []
  }
}
