import { credentialRef } from '@deepseek-ai/dsh-credentials'
import { Document, parseDocument as parseYaml } from 'yaml'

/** Parse a plaintext credential YAML mapping. */
export function parsePlainEntries(text: string, filename: string): Map<string, string> {
  const document = parseYaml(text, { prettyErrors: true, uniqueKeys: true })
  if (document.errors.length > 0) {
    throw new Error(
      `dsh-encrypt: invalid document at ${filename}: ${document.errors
        .map(error => {
          const at = error.linePos?.[0]
          return `${error.code}${at === void 0 ? '' : ` at line ${String(at.line)}, column ${String(at.col)}`}`
        })
        .join('; ')}`,
    )
  }
  const root: unknown = document.toJS() ?? {}
  if (typeof root !== 'object' || root === null || Array.isArray(root)) {
    throw new TypeError(`dsh-encrypt: ${filename} must be a mapping of credential reference to value`)
  }
  const entries = new Map<string, string>()
  for (const [key, value] of Object.entries(root)) {
    credentialRef(key)
    if (typeof value !== 'string') {
      throw new TypeError(`dsh-encrypt: the value for "${key}" in ${filename} must be a string`)
    }
    if (value.length === 0) {
      throw new Error(`dsh-encrypt: the value for "${key}" in ${filename} is empty; remove the key instead`)
    }
    entries.set(key, value)
  }
  return entries
}

/** Render one plaintext credential edit while preserving YAML comments. */
export function renderPlainDocument(text: string | undefined, ref: string, value: string | undefined): string {
  const document = text === void 0 ? new Document({}) : parseYaml(text)
  if (value === void 0) document.deleteIn([ref])
  else document.setIn([ref], value)
  return document.toString()
}
