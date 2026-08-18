export interface LiteralMatch {
  start: number
  end: number
  value: string
}

interface TrieNode {
  children: Map<string, TrieNode>
  value?: string | undefined
}

/**
 * Immutable literal matcher with leftmost, longest, non-overlapping results.
 *
 * The trie walks at most the longest registered value from each candidate
 * position. Credential limits keep that bound small and predictable.
 */
export class LiteralMatcher {
  #root: TrieNode = { children: new Map() }
  #size = 0

  constructor(values: Iterable<string>) {
    for (const value of values) this.#insert(value)
  }

  size(): number {
    return this.#size
  }

  find(text: string): LiteralMatch[] {
    const matches: LiteralMatch[] = []
    let start = 0
    while (start < text.length) {
      let node = this.#root
      let cursor = start
      let longest: LiteralMatch | undefined
      while (cursor < text.length) {
        const next = node.children.get(text[cursor] as string)
        if (next === void 0) break
        node = next
        cursor += 1
        if (node.value !== void 0) longest = { start, end: cursor, value: node.value }
      }
      if (longest === void 0) {
        start += 1
      } else {
        matches.push(longest)
        start = longest.end
      }
    }
    return matches
  }

  #insert(value: string): void {
    if (value.length === 0) return
    let node = this.#root
    for (let index = 0; index < value.length; index += 1) {
      const character = value[index] as string
      let next = node.children.get(character)
      if (next === void 0) {
        next = { children: new Map() }
        node.children.set(character, next)
      }
      node = next
    }
    if (node.value === void 0) {
      node.value = value
      this.#size += 1
    }
  }
}
