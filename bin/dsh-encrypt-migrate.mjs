#!/usr/bin/env node
import { migrateLegacySidecar } from "../lib/migrate.js";

const args = process.argv.slice(2);
const value = (name) => {
  const index = args.indexOf(name);
  return index < 0 ? void 0 : args[index + 1];
};
const path = value("--path");
if (args.includes("--help")) {
  console.log("Usage: dsh-encrypt-migrate --path <legacy .credentials.yaml> [--sidecar <target>]");
  process.exit(0);
}
if (path === void 0) {
  console.error("Usage: dsh-encrypt-migrate --path <legacy .credentials.yaml> [--sidecar <target>]");
  process.exit(2);
}
try {
  const result = await migrateLegacySidecar({ path, encryptedPath: value("--sidecar") });
  console.log(`Migrated ${result.filename} to ${result.sidecar}`);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
