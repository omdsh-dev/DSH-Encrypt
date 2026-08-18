import type { GenericSchema } from 'valibot'
import {
  check,
  integer,
  literal,
  maxValue,
  minValue,
  number,
  pipe,
  safeParse,
  strictObject,
  string,
  union,
} from 'valibot'
import { VaultError } from '../../domain/vault/model.js'
import { isAsciiLowerHex } from '../../shared/validation/primitives.js'

export interface DigestRequest {
  digest: string
}

export interface ChangePasswordRequest extends DigestRequest {
  oldDigest: string
}

export type ConfigRequest = { action?: 'get' | undefined } | { action: 'set'; rememberDays: number }

const digestSchema = pipe(
  // Valibot owns the boundary; the custom action keeps hexadecimal parsing regex-free.
  // The explicit generic preserves the string output through the pipe.
  string(),
  check<string>(value => isAsciiLowerHex(value, 64)),
)
const emptyRequestSchema = strictObject({})
const digestRequestSchema = strictObject({ digest: digestSchema })
const changePasswordRequestSchema = strictObject({ oldDigest: digestSchema, digest: digestSchema })
const configRequestSchema = union([
  strictObject({}),
  strictObject({ action: literal('get') }),
  strictObject({ action: literal('set'), rememberDays: pipe(number(), integer(), minValue(-1), maxValue(30)) }),
])

/** Validate an operation that accepts no request fields. */
export function parseEmptyRequest(input: unknown): Record<string, never> {
  return parseBoundary<Record<string, never>>(
    emptyRequestSchema,
    input,
    'the request body must be an empty JSON object',
  )
}

/** Validate a password-digest request. */
export function parseDigestRequest(input: unknown): DigestRequest {
  return parseBoundary<DigestRequest>(
    digestRequestSchema,
    input,
    'digest must be a 64-character lowercase SHA3-256 hexadecimal string',
  )
}

/** Validate a change-password request. */
export function parseChangePasswordRequest(input: unknown): ChangePasswordRequest {
  return parseBoundary<ChangePasswordRequest>(
    changePasswordRequestSchema,
    input,
    'oldDigest and digest must be 64-character lowercase SHA3-256 hexadecimal strings',
  )
}

/** Validate the remembered-login configuration request. */
export function parseConfigRequest(input: unknown): ConfigRequest {
  return parseBoundary<ConfigRequest>(
    configRequestSchema,
    input,
    'config action must be get, or set with rememberDays from -1 through 30',
  )
}

function parseBoundary<T>(schema: GenericSchema, input: unknown, message: string): T {
  const parsed = safeParse(schema, input)
  if (!parsed.success) throw new VaultError('BAD_REQUEST', message)
  return parsed.output as T
}
