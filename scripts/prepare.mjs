// `prepare` runs on every install, including `npm ci --omit=dev`, where the compiler is absent.
// Build when it is available and say nothing when it is not - the package still works from `dist/`.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const tsc = fileURLToPath(new URL("../node_modules/typescript/bin/tsc", import.meta.url));
if (!existsSync(tsc)) process.exit(0);

// Run the compiler through this same node binary: no shell, no npx, no PATH assumptions.
const result = spawnSync(process.execPath, [tsc, "-p", "tsconfig.json"], { stdio: "inherit", cwd: root });
process.exit(result.status ?? 0);
