import { build } from "esbuild";
import fs from "node:fs";

const isDev = process.env.NODE_ENV === "development";

await build({
    entryPoints: ["./src/main.ts"],
    outfile: "./dist/index.cjs",
    bundle: true,
    platform: "node",
    target: "node20",
    format: "cjs",
    minify: !isDev,
    sourcemap: isDev,
    sourcesContent: isDev,
    define: {
        "process.env.NODE_ENV": JSON.stringify(isDev ? "development" : "production"),
    },
    external: [
        // Add any external dependencies that shouldn't be bundled
        // These are typically native modules or packages that cause issues when bundled
    ],
}).catch(() => process.exit(1));

fs.writeFileSync(
    "./dist/scf_bootstrap",
    `#!/usr/bin/env bash
/var/lang/node20/bin/node ./index.cjs "$@"
`,
);
fs.chmodSync("./dist/scf_bootstrap", 0o755);
