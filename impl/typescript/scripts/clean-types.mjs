// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
// Remove the generated .d.mts declaration files under naalp/ before `tsc` regenerates
// them. The declarations are committed (so GitHub and no-build consumers see real types),
// but that means a re-run of `build:types` — as `prepack`/`npm publish` triggers — would
// otherwise fail TS5055 ("would overwrite input file") when tsc treats the existing .d.mts
// as inputs. Deleting them first makes the declaration build idempotent.
import { readdirSync, rmSync } from "node:fs";

const dir = "naalp";
for (const f of readdirSync(dir)) {
  if (f.endsWith(".d.mts")) rmSync(new URL(`../${dir}/${f}`, import.meta.url));
}
