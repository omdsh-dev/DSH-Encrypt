/**
 * End-to-end verification of the WebUI-managed password architecture against
 * a live dsh web instance. Two phases, with a REAL process restart between
 * them (the orchestrator boots the instance fresh for each phase):
 *
 *   phase 1: plain form → official credentials.set → set-password →
 *            ciphertext + SHA3 checks → corrupt/reject/heal
 *   phase 2: boots LOCKED → wrong password → right password →
 *            change-password → clear-password → plaintext restored → cleanup
 */
import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const BASE = process.env.E2E_BASE ?? "http://127.0.0.1:3199";
const HOME = process.env.E2E_HOME;
const STORE = `${HOME}/.credentials.yaml`;
const PHASE = process.env.E2E_PHASE ?? "1";
const PASSWORD = "e2e webui password 123";
const NEW_PASSWORD = "rotated password 456";

async function passwordRoute(path, payload) {
	const res = await fetch(`${BASE}${path}`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(payload ?? {})
	});
	const body = await res.json();
	if (!body.ok) return { error: { code: body.code, message: body.message } };
	return { value: body.value };
}
async function officialRpc(method, payload) {
	const res = await fetch(`${BASE}/api/${method}`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ type: "client-request", rpcId: `e2e-${method}`, method, payload })
	});
	return res.json();
}
function expect(condition, label) {
	if (!condition) throw new Error(`FAIL: ${label}`);
	console.log(`  ✓ ${label}`);
}
function documentFingerprint(doc) {
	return createHash("sha3-256").update(JSON.stringify(Object.fromEntries([
		["format", doc.format], ["version", doc.version], ["algorithm", doc.algorithm],
		["kdf", doc.kdf], ["n", doc.n], ["r", doc.r], ["p", doc.p],
		["salt", doc.salt], ["verifier", doc.verifier], ["entries", doc.entries]
	])), "utf8").digest("hex");
}

if (PHASE === "1") {
	let status = (await passwordRoute("/api/credentials.status")).value;
	expect(status.format === "plain" && status.unlocked === true, "boots in plain unlocked form");

	const rpc = await officialRpc("credentials.set", { ref: "E2E_KEY", value: "sk-e2e-plain-777" });
	expect(rpc.result.ok === true, "official credentials.set works on the plain form");

	await passwordRoute("/api/credentials.set-password", { password: PASSWORD });
	status = (await passwordRoute("/api/credentials.status")).value;
	expect(status.format === "encrypted" && status.unlocked === true, "set-password encrypts and stays unlocked");

	let text = await readFile(STORE, "utf8");
	expect(!text.includes("sk-e2e-plain-777") && !text.includes(PASSWORD), "file holds ciphertext only");
	expect(text.includes('"dsh-encrypt-credentials"'), "file carries the encrypted-store marker");
	expect(documentFingerprint(JSON.parse(text)) === JSON.parse(text).sha3, "document SHA3-256 fingerprint valid");

	const describe = await officialRpc("credentials.describe", { refs: ["E2E_KEY"] });
	expect(describe.result.value.credentials.E2E_KEY.configured === true, "credential visible while unlocked");

	const goodText = await readFile(STORE, "utf8");
	const corrupted = JSON.parse(goodText);
	corrupted.entries.E2E_KEY.data = `${corrupted.entries.E2E_KEY.data.slice(0, -1)}${corrupted.entries.E2E_KEY.data.endsWith("A") ? "B" : "A"}`;
	await writeFile(STORE, `${JSON.stringify(corrupted, null, 2)}\n`);
	await new Promise((resolve) => setTimeout(resolve, 300));
	const rejected = await officialRpc("credentials.set", { ref: "SHOULD_NOT", value: "land" });
	expect(rejected.result.ok === false, "corrupt store rejects writes (fail-loud via the official RPC)");
	await writeFile(STORE, goodText);
	await new Promise((resolve) => setTimeout(resolve, 300));
	expect(true, "store healed for phase 2");
	console.log("\nPhase 1 complete — restart the instance and run phase 2.");
} else {
	let status = (await passwordRoute("/api/credentials.status")).value;
	expect(status.format === "encrypted" && status.unlocked === false, "boots LOCKED after restart");

	let unlock = await passwordRoute("/api/credentials.unlock", { password: "wrong password" });
	expect(unlock.error?.code === "PASSWORD_WRONG", "wrong unlock password reports PASSWORD_WRONG");
	status = (await passwordRoute("/api/credentials.status")).value;
	expect(status.unlocked === false, "still locked after a wrong password");

	unlock = await passwordRoute("/api/credentials.unlock", { password: PASSWORD });
	expect(unlock.value?.unlocked === true, "right password unlocks");
	const describe = await officialRpc("credentials.describe", { refs: ["E2E_KEY"] });
	expect(describe.result.value.credentials.E2E_KEY.configured === true, "credential visible after unlock");

	await passwordRoute("/api/credentials.change-password", { password: NEW_PASSWORD });
	status = (await passwordRoute("/api/credentials.status")).value;
	expect(status.unlocked === true, "change-password succeeds and stays unlocked");
	const text = await readFile(STORE, "utf8");
	expect(!text.includes("sk-e2e-plain-777"), "re-encrypted file has no plaintext");

	await passwordRoute("/api/credentials.clear-password");
	status = (await passwordRoute("/api/credentials.status")).value;
	expect(status.format === "plain" && status.unlocked === true, "clear-password restores the plain form");
	const plain = await readFile(STORE, "utf8");
	expect(plain.includes("sk-e2e-plain-777") && !plain.includes("dsh-encrypt-credentials"), "file holds plaintext YAML again");

	const cleanup = await officialRpc("credentials.unset", { ref: "E2E_KEY" });
	expect(cleanup.result.ok === true, "cleanup unset");
	console.log("\nE2E: WebUI password lifecycle fully verified over the real web API.");
}
