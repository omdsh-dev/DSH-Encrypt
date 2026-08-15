/**
 * Smoke test for the hand-written browser bundle: load it through a minimal
 * ModuleLoader shim, run its factory with a React require, apply it to a mock
 * ctx, and server-render the settings card (effects don't run under SSR, so
 * the component must render its loading state without throwing).
 */
import { createRequire } from "node:module";
import { renderToString } from "react-dom/server";

const require_ = createRequire(import.meta.url);
const React = require_("react");

let loaded = null;
globalThis.window = {
	__ModuleLoader__: {
		load(spec) {
			loaded = spec;
		}
	}
};
await import("../lib/client.js");
if (loaded === null) throw new Error("client.js did not call __ModuleLoader__.load");
if (loaded.id !== "dsh-encrypt") throw new Error(`unexpected module id ${loaded.id}`);

const fakeRequire = (name) => {
	if (name === "react") return React;
	throw new Error(`unexpected require in client bundle: ${name}`);
};
const plugin = loaded.factory(fakeRequire);
if (typeof plugin.apply !== "function") throw new Error("bundle exports no apply");
if (!Array.isArray(plugin.inject) || plugin.inject.length !== 1 || plugin.inject[0] !== "slots") throw new Error(`bundle must inject only the slots service (pending-wait boot guard), got: ${JSON.stringify(plugin.inject)}`);

let registered = null;
const ctx = {
	slots: {
		inject(slot, fn) {
			if (slot !== "settings.section") throw new Error(`unexpected slot ${slot}`);
			fn();
		},
		register(options, component) {
			registered = { options, component };
		}
	}
};
plugin.apply(ctx);
if (registered === null) throw new Error("apply did not register the settings.section slot");
if (registered.options.id !== "encryption") throw new Error(`unexpected section id ${registered.options.id}`);

const html = renderToString(React.createElement(registered.component, { close: () => {} }));
if (typeof html !== "string" || html.length === 0) throw new Error("section rendered empty");
console.log(`client bundle smoke OK: module id ${loaded.id}, section id ${registered.options.id}, order ${registered.options.order}, SSR html ${html.length} chars`);
