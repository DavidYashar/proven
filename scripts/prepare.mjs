// `prepare` runs on every install, including `npm ci --omit=dev`, where the compiler is absent.
// Build when it is available and say nothing when it is not — the package still works from `dist/`.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";

if (!existsSync(new URL("../node_modules/typescript/bin/tsc", import.meta.url))) {
  process.exit(0);
}

const result = spawnSync(process.platform === "win32" ? "npx.cmd" : "npx", ["tsc", "-p", "tsconfig.json"], {
  stdio: "inherit",
  cwd: new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"),
});
process.exit(result.status ?? 0);
