import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Context } from "@deepseek-ai/cordis";
import { credentialRef } from "@deepseek-ai/dsh-credentials";
import { EncryptedCredentialProvider, VaultError } from "../lib/index.js";

/** Boot a provider over a fresh harness home and return its disposal helper. */
async function bootProvider(home, overrides = {}) {
	const ctx = new Context();
	const fiber = ctx.plugin(EncryptedCredentialProvider, {
		dshHome: home,
		watch: false,
		...overrides
	});
	await fiber;
	const provider = await ctx.get("credentials");
	assert.ok(provider instanceof EncryptedCredentialProvider);
	return { ctx, fiber, provider };
}

const PASSWORD = "correct horse battery staple";
const storePath = (home) => join(home, ".credentials.yaml");

describe("dsh-encrypt single-file provider", () => {
	it("default plain form: full seam contract, plaintext YAML on disk", async () => {
		const home = await mkdtemp(join(tmpdir(), "dsh-enc-"));
		try {
			const { provider } = await bootProvider(home);
			assert.deepEqual(await provider.status(), { format: "plain", unlocked: true });
			const ref = credentialRef("TEST_KEY");
			assert.equal(await provider.resolve(ref), undefined);
			assert.deepEqual(await provider.describe(ref), { configured: false, writable: true });
			await provider.set(ref, "sk-plain-value-1");
			const text = await readFile(storePath(home), "utf8");
			assert.ok(text.includes("sk-plain-value-1"), "plain form stores the value verbatim");
			const hit = await provider.resolve(ref);
			assert.equal(hit.value, "sk-plain-value-1");
			assert.equal(hit.source, "file");
			await provider.unset(ref);
			assert.equal(await provider.resolve(ref), undefined);
			// unset of an absent ref is a no-op
			await provider.unset(ref);
		} finally {
			await rm(home, { recursive: true, force: true });
		}
	});
	it("setPassword replaces the file contents with ciphertext in place and stays unlocked", async () => {
		const home = await mkdtemp(join(tmpdir(), "dsh-enc-"));
		try {
			const { provider } = await bootProvider(home);
			await provider.set(credentialRef("KEY_A"), "sk-super-secret-42");
			await provider.setPassword(PASSWORD);
			assert.deepEqual(await provider.status(), { format: "encrypted", unlocked: true });
			const text = await readFile(storePath(home), "utf8");
			assert.ok(!text.includes("sk-super-secret-42"), "ciphertext must not contain the plaintext");
			assert.ok(text.includes('"dsh-encrypt-credentials"'));
			assert.ok(text.includes('"sha3"'));
			// still resolvable while unlocked
			assert.equal((await provider.resolve(credentialRef("KEY_A"))).value, "sk-super-secret-42");
			// new writes encrypt too
			await provider.set(credentialRef("KEY_B"), "another-secret");
			assert.ok(!(await readFile(storePath(home), "utf8")).includes("another-secret"));
		} finally {
			await rm(home, { recursive: true, force: true });
		}
	});
	it("restart after setPassword boots LOCKED: resolve throws VAULT_LOCKED, writes refused, describe reports locked", async () => {
		const home = await mkdtemp(join(tmpdir(), "dsh-enc-"));
		try {
			const first = await bootProvider(home);
			await first.provider.set(credentialRef("KEY"), "secret");
			await first.provider.setPassword(PASSWORD);
			first.fiber.dispose();
			const second = await bootProvider(home);
			assert.deepEqual(await second.provider.status(), { format: "encrypted", unlocked: false });
			await assert.rejects(second.provider.resolve(credentialRef("KEY")), { code: "VAULT_LOCKED" });
			await assert.rejects(second.provider.set(credentialRef("KEY"), "new"), { code: "VAULT_LOCKED" });
			assert.deepEqual(await second.provider.describe(credentialRef("KEY")), { configured: false, source: "locked", writable: false });
		} finally {
			await rm(home, { recursive: true, force: true });
		}
	});
	it("unlock: wrong password → PASSWORD_WRONG, right password → credentials decrypt", async () => {
		const home = await mkdtemp(join(tmpdir(), "dsh-enc-"));
		try {
			const first = await bootProvider(home);
			await first.provider.set(credentialRef("KEY"), "unlock-me");
			await first.provider.setPassword(PASSWORD);
			first.fiber.dispose();
			const second = await bootProvider(home);
			await assert.rejects(second.provider.unlock("wrong password"), { code: "PASSWORD_WRONG" });
			assert.equal((await second.provider.status()).unlocked, false);
			const result = await second.provider.unlock(PASSWORD);
			assert.equal(result.unlocked, true);
			assert.equal((await second.provider.resolve(credentialRef("KEY"))).value, "unlock-me");
			assert.deepEqual(await second.provider.status(), { format: "encrypted", unlocked: true });
			// idempotent
			assert.equal((await second.provider.unlock(PASSWORD)).unlocked, true);
		} finally {
			await rm(home, { recursive: true, force: true });
		}
	});
	it("changePassword re-encrypts: the new password unlocks after restart, the old one does not", async () => {
		const home = await mkdtemp(join(tmpdir(), "dsh-enc-"));
		try {
			const { provider, fiber } = await bootProvider(home);
			await provider.set(credentialRef("KEY"), "rotate-me");
			await provider.setPassword(PASSWORD);
			const NEW = "new password nine chars";
			await provider.changePassword(NEW);
			fiber.dispose();
			const second = await bootProvider(home);
			await assert.rejects(second.provider.unlock(PASSWORD), { code: "PASSWORD_WRONG" });
			await second.provider.unlock(NEW);
			assert.equal((await second.provider.resolve(credentialRef("KEY"))).value, "rotate-me");
		} finally {
			await rm(home, { recursive: true, force: true });
		}
	});
	it("clearPassword decrypts everything back to plaintext YAML", async () => {
		const home = await mkdtemp(join(tmpdir(), "dsh-enc-"));
		try {
			const { provider, fiber } = await bootProvider(home);
			await provider.set(credentialRef("KEY"), "back-to-plain");
			await provider.setPassword(PASSWORD);
			await provider.clearPassword();
			assert.deepEqual(await provider.status(), { format: "plain", unlocked: true });
			const text = await readFile(storePath(home), "utf8");
			assert.ok(text.includes("back-to-plain"));
			assert.ok(!text.includes("dsh-encrypt-credentials"));
			// a fresh boot reads it directly, no password involved
			fiber.dispose();
			const second = await bootProvider(home);
			assert.equal((await second.provider.resolve(credentialRef("KEY"))).value, "back-to-plain");
		} finally {
			await rm(home, { recursive: true, force: true });
		}
	});
	it("password transitions on the wrong form fail with the stable codes", async () => {
		const home = await mkdtemp(join(tmpdir(), "dsh-enc-"));
		try {
			const { provider } = await bootProvider(home);
			await assert.rejects(provider.unlock(PASSWORD), { code: "VAULT_NOT_ENCRYPTED" });
			await assert.rejects(provider.changePassword(PASSWORD), { code: "VAULT_NOT_ENCRYPTED" });
			await assert.rejects(provider.clearPassword(), { code: "VAULT_NOT_ENCRYPTED" });
			await provider.setPassword(PASSWORD);
			await assert.rejects(provider.setPassword("other password"), { code: "VAULT_ALREADY_ENCRYPTED" });
		} finally {
			await rm(home, { recursive: true, force: true });
		}
	});
	it("boot auto-unlocks with DSH_CREDENTIAL_PASSWORD and fails loud on a wrong one", async () => {
		const home = await mkdtemp(join(tmpdir(), "dsh-enc-"));
		const old = process.env.DSH_CREDENTIAL_PASSWORD;
		try {
			const first = await bootProvider(home);
			await first.provider.set(credentialRef("KEY"), "env-unlock");
			await first.provider.setPassword(PASSWORD);
			first.fiber.dispose();
			process.env.DSH_CREDENTIAL_PASSWORD = PASSWORD;
			const second = await bootProvider(home);
			assert.deepEqual(await second.provider.status(), { format: "encrypted", unlocked: true });
			assert.equal((await second.provider.resolve(credentialRef("KEY"))).value, "env-unlock");
			second.fiber.dispose();
			process.env.DSH_CREDENTIAL_PASSWORD = "definitely wrong";
			const ctx = new Context();
			const fiber = ctx.plugin(EncryptedCredentialProvider, { dshHome: home, watch: false });
			await assert.rejects(async () => {
				await fiber;
			}, { code: "PASSWORD_WRONG" });
		} finally {
			if (old === undefined) delete process.env.DSH_CREDENTIAL_PASSWORD;
			else process.env.DSH_CREDENTIAL_PASSWORD = old;
			await rm(home, { recursive: true, force: true });
		}
	});
	it("a corrupted encrypted file fails activation (never treated as empty)", async () => {
		const home = await mkdtemp(join(tmpdir(), "dsh-enc-"));
		try {
			const { provider, fiber } = await bootProvider(home);
			await provider.set(credentialRef("KEY"), "value");
			await provider.setPassword(PASSWORD);
			fiber.dispose();
			const path = storePath(home);
			const doc = JSON.parse(await readFile(path, "utf8"));
			doc.entries.KEY.data = `${doc.entries.KEY.data.slice(0, -1)}${doc.entries.KEY.data.endsWith("A") ? "B" : "A"}`;
			await writeFile(path, `${JSON.stringify(doc, null, 2)}\n`);
			const ctx = new Context();
			const failing = ctx.plugin(EncryptedCredentialProvider, { dshHome: home, watch: false });
			await assert.rejects(async () => {
				await failing;
			}, { code: "VAULT_CORRUPTED" });
		} finally {
			await rm(home, { recursive: true, force: true });
		}
	});
	it("external plain edits hot-publish; external encryption locks the provider", async () => {
		const home = await mkdtemp(join(tmpdir(), "dsh-enc-"));
		try {
			const { provider, fiber } = await bootProvider(home, { watch: true, debounceMs: 50 });
			await provider.set(credentialRef("KEY"), "old-value");
			// external plain edit
			await writeFile(storePath(home), "KEY: new-value\n");
			const deadline = Date.now() + 5000;
			while (Date.now() < deadline) {
				try {
					if ((await provider.resolve(credentialRef("KEY"))).value === "new-value") break;
				} catch {}
				await new Promise((resolve) => setTimeout(resolve, 50));
			}
			assert.equal((await provider.resolve(credentialRef("KEY"))).value, "new-value");
			// external encryption (via a helper provider) locks this one
			const helper = await bootProvider(home);
			await helper.provider.setPassword(PASSWORD);
			helper.fiber.dispose();
			const deadline2 = Date.now() + 5000;
			while (Date.now() < deadline2 && (await provider.status()).format !== "encrypted") {
				await new Promise((resolve) => setTimeout(resolve, 50));
			}
			assert.deepEqual(await provider.status(), { format: "encrypted", unlocked: false });
			await assert.rejects(provider.resolve(credentialRef("KEY")), { code: "VAULT_LOCKED" });
			fiber.dispose();
		} finally {
			await rm(home, { recursive: true, force: true });
		}
	});
	it("rejects an empty stored value and environment-shadowed writes", async () => {
		const home = await mkdtemp(join(tmpdir(), "dsh-enc-"));
		const old = process.env.SHADOWED_KEY;
		try {
			const { provider } = await bootProvider(home);
			await assert.rejects(provider.set(credentialRef("EMPTY"), ""), /empty value/);
			process.env.SHADOWED_KEY = "from-env";
			await assert.rejects(provider.set(credentialRef("SHADOWED_KEY"), "value"), /read-only by the launching environment/);
			const hit = await provider.resolve(credentialRef("SHADOWED_KEY"));
			assert.equal(hit.value, "from-env");
			assert.equal(hit.source, "env");
		} finally {
			if (old === undefined) delete process.env.SHADOWED_KEY;
			else process.env.SHADOWED_KEY = old;
			await rm(home, { recursive: true, force: true });
		}
	});
	it("plain form rejects structurally invalid YAML at startup", async () => {
		const home = await mkdtemp(join(tmpdir(), "dsh-enc-"));
		try {
			await writeFile(storePath(home), "9BAD: value\n");
			const ctx = new Context();
			const fiber = ctx.plugin(EncryptedCredentialProvider, { dshHome: home, watch: false });
			await assert.rejects(async () => {
				await fiber;
			});
		} finally {
			await rm(home, { recursive: true, force: true });
		}
	});
});
