import { readdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { computeIntegrityManifest } from "../lib/integrity.js";

// Regenerate lib/integrity-manifest.json over every shipped file: the
// JavaScript in lib/ plus cordis.patch.yml. Wired as prepack/pretest so the
// manifest always describes the exact bytes npm packs and the tests run.
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const libDir = join(root, "lib");
const relFiles = [];
for (const name of readdirSync(libDir)) {
	if (name === "integrity-manifest.json") continue;
	if (name.endsWith(".js")) relFiles.push("lib/" + name);
}
relFiles.push("cordis.patch.yml");
const manifest = computeIntegrityManifest(root, relFiles);
writeFileSync(join(libDir, "integrity-manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log("dsh-encrypt: integrity manifest written for " + relFiles.length + " shipped files");