import * as React from 'react'
import { renderToString } from 'react-dom/server'
import { describe, expect, it } from 'vitest'

interface ClientPlugin {
  apply: (ctx: ClientContext) => void
  inject: string[]
  digestPassword: (text: string) => string
}

interface ClientContext {
  slots: {
    inject: (slot: string, callback: () => unknown) => unknown
    register: (options: Record<string, unknown>, component: React.ComponentType<{ close: () => void }>) => unknown
  }
}

interface ModuleSpec {
  id: string
  factory: (require: (name: string) => unknown) => ClientPlugin
}

describe('browser client bundle', () => {
  it('loads through ModuleLoader and server-renders its settings card', async () => {
    let loaded: ModuleSpec | undefined
    Object.defineProperty(globalThis, 'window', {
      configurable: true,
      value: {
        __ModuleLoader__: {
          load(spec: ModuleSpec) {
            loaded = spec
          },
        },
      },
    })

    await import('../lib/client.js')
    expect(loaded).toBeDefined()
    if (loaded === undefined) throw new Error('client.js did not call __ModuleLoader__.load')
    expect(loaded.id).toBe('dsh-encrypt')

    const plugin = loaded.factory(name => {
      if (name === 'react') return React
      throw new Error(`unexpected require in client bundle: ${name}`)
    })
    expect(plugin.apply).toBeTypeOf('function')
    expect(plugin.inject).toEqual(['slots'])
    expect(plugin.digestPassword('abc')).toBe('3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532')

    let registered:
      | { options: Record<string, unknown>; component: React.ComponentType<{ close: () => void }> }
      | undefined
    const ctx: ClientContext = {
      slots: {
        inject(slot, callback) {
          expect(slot).toBe('settings.section')
          return callback()
        },
        register(options, component) {
          registered = { options, component }
        },
      },
    }
    plugin.apply(ctx)
    expect(registered).toBeDefined()
    if (registered === undefined) throw new Error('apply did not register the settings.section slot')
    expect(registered.options.id).toBe('encryption')

    const html = renderToString(React.createElement(registered.component, { close: () => undefined }))
    expect(html.length).toBeGreaterThan(0)
  })
})
