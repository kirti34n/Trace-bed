#!/usr/bin/env node
/**
 * Dashboard dependency licence gate — the npm counterpart of
 * scripts/license_check.py, and deliberately the same discipline:
 *
 *   - it walks the RESOLVED tree on disk (node_modules), not the declared one
 *     in package.json, because transitive pulls are exactly what this catches;
 *   - an UNKNOWN licence fails. Silence is not consent. A package that ships no
 *     machine-readable licence is treated as more dangerous than one that
 *     honestly declares a copyleft licence, because nobody has read it;
 *   - a conditional licence passes only when THIS distribution is named in
 *     RATIONALE with a written justification (the psycopg carve-out pattern
 *     from scripts/license_policy.toml, D-036);
 *   - `--self-test` proves the gate bites, so a gate that has silently stopped
 *     classifying anything cannot masquerade as a clean run.
 *
 * The policy lives in this file rather than beside license_policy.toml because
 * Node has no TOML parser in its standard library, and a licence gate that
 * needs a dependency in order to check dependencies is a gate with a hole in
 * it. The two policies are kept deliberately consistent; where they differ
 * (CC0-1.0, CC-BY-4.0) it is because those licences appear only in the npm
 * tree and never in the Python one.
 *
 * Usage:
 *   node scripts/license_check.mjs              # gate the dashboard's tree
 *   node scripts/license_check.mjs --self-test  # prove the gate actually fails
 *   node scripts/license_check.mjs --all        # include dev-only, same verdict
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const DASHBOARD_ROOT = resolve(HERE, "..");

// --------------------------------------------------------------------- //
// Policy
// --------------------------------------------------------------------- //

/** Accepted outright. Permissive: no obligation beyond preserving a notice. */
const ALLOW = new Set(
  [
    "MIT",
    "MIT-0",
    "ISC",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "0BSD",
    "BSD Zero Clause License",
    "Apache-2.0",
    "Unlicense",
    "Python-2.0",
    "PSF-2.0",
    // File-level copyleft: obliges publishing modifications to the covered
    // FILES, not relicensing the dashboard. Nothing here is vendored or
    // modified, so the obligation never attaches. Same reasoning, same
    // wording, as the Python policy's MPL entry.
    "MPL-2.0",
  ].map(normaliseLicence)
);

/** Accepted only when the package is named in RATIONALE below. */
const CONDITIONAL = new Set(
  [
    // Public-domain dedication. Strictly MORE permissive than MIT — it is
    // conditional here not because it is risky but because it is not on the
    // mandated allowlist, and widening that list silently is how an allowlist
    // stops meaning anything. Each use gets a named, recorded assertion.
    "CC0-1.0",
    // Attribution required on redistribution of the WORK. Fine for a build
    // tool consulted at compile time, not fine for anything vendored into a
    // shipped bundle — which is precisely the distinction RATIONALE records.
    "CC-BY-4.0",
    "LGPL-3.0-only",
    "LGPL-3.0",
    "LGPL-2.1",
  ].map(normaliseLicence)
);

/** Hard fail. No rationale can rescue these — network copyleft, source-available
 * licences, and the "no licence at all" marker npm uses. */
const DENY = new Set(
  [
    "AGPL-1.0",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "SSPL",
    "SSPL-1.0",
    "BUSL-1.1",
    "BSL-1.1",
    "Elastic-2.0",
    "RSAL",
    "CC-BY-NC-4.0",
    "CC-BY-SA-4.0",
    "UNLICENSED",
  ].map(normaliseLicence)
);

/**
 * package name -> why its conditional licence is acceptable HERE.
 *
 * Every entry is a human assertion. It must say what the package is, why the
 * licence's obligation does not attach, and — critically — whether the package
 * reaches the shipped bundle, because that is the fact the obligation turns on.
 */
const RATIONALE = {
  "caniuse-lite":
    "CC-BY-4.0. Browser-support DATA consulted by autoprefixer/browserslist at " +
    "build time to choose CSS prefixes. Build-time toolchain only: the database " +
    "is never copied into dist/, so the dashboard redistributes none of the " +
    "CC-BY-licensed work and the attribution obligation does not attach to the " +
    "shipped artefact. Attribution is preserved in node_modules for anyone " +
    "building from source.",
  "language-subtag-registry":
    "CC0-1.0. IANA subtag data used by eslint-plugin-jsx-a11y to validate lang " +
    "attributes. Lint-time only, never bundled. CC0 is a public-domain " +
    "dedication carrying no obligation even if it were redistributed.",
};

/** Packages reachable only through devDependencies are toolchain, not artefact.
 * They are still classified and still reported; this flag only decides whether
 * a failure among them blocks the gate, mirroring the Python gate's DEV_ONLY
 * set. Default is STRICT (they block too) — the lenient path must be asked for. */
const DEV_FAILURES_BLOCK = true;

// --------------------------------------------------------------------- //
// Licence parsing
// --------------------------------------------------------------------- //

function normaliseLicence(value) {
  // Parentheses are dropped mid-string rather than trimmed from the edges, for
  // the same reason the Python gate does it: "(MIT OR CC0-1.0)" must not leave
  // an unbalanced atom that can never match anything.
  return String(value)
    .replace(/[()]/g, " ")
    .trim()
    .toLowerCase()
    .replace(/[\s_]+/g, "-");
}

/** Read a licence out of the three package.json conventions, newest first. */
function readLicence(pkg) {
  if (typeof pkg.license === "string") return pkg.license.trim();
  // Legacy object form: { "license": { "type": "MIT", "url": ... } }
  if (pkg.license && typeof pkg.license === "object" && typeof pkg.license.type === "string") {
    return pkg.license.type.trim();
  }
  // Legacy array form: { "licenses": [{ "type": "MIT" }, ...] } — an OR by
  // npm's own historical definition, so join it as one.
  if (Array.isArray(pkg.licenses)) {
    const types = pkg.licenses
      .map((l) => (typeof l === "string" ? l : l && typeof l.type === "string" ? l.type : ""))
      .filter(Boolean);
    if (types.length > 0) return types.join(" OR ");
  }
  return "";
}

/** Split an SPDX expression into atoms. `A OR B` passes if ANY atom passes;
 * `A AND B` is treated the same way here, conservatively flagged by the DENY
 * check running first — a denied atom anywhere fails regardless of operator. */
function splitExpression(expr) {
  return expr
    .split(/\s+(?:OR|AND)\s+|\s*;\s*/i)
    .map((p) => p.replace(/^[\s()]+|[\s()]+$/g, ""))
    .filter(Boolean);
}

/** A licence string that names a file instead of a licence tells us nothing
 * machine-readable, and "nothing" must not be mistaken for a match. */
function isUninformative(licence) {
  return /^see\s+license/i.test(licence) || licence === "" || /^custom$/i.test(licence);
}

function classify(name, licence, channel) {
  if (isUninformative(licence)) {
    return {
      name,
      licence: licence || "(none)",
      channel,
      status: "unknown",
      detail: "no machine-readable licence in package.json (no license, no licenses[])",
    };
  }

  const atoms = splitExpression(licence).map(normaliseLicence);

  const denied = atoms.find((a) => DENY.has(a));
  if (denied) {
    return { name, licence, channel, status: "denied", detail: `denylisted licence: ${denied}` };
  }
  if (atoms.some((a) => ALLOW.has(a))) {
    return { name, licence, channel, status: "allowed", detail: "" };
  }
  if (atoms.some((a) => CONDITIONAL.has(a))) {
    const why = RATIONALE[name];
    if (why) return { name, licence, channel, status: "conditional-ok", detail: why };
    return {
      name,
      licence,
      channel,
      status: "denied",
      detail: "conditional licence with no named entry in RATIONALE",
    };
  }
  return {
    name,
    licence,
    channel,
    status: "unknown",
    detail: "licence not present in ALLOW, CONDITIONAL, or DENY",
  };
}

// --------------------------------------------------------------------- //
// Resolved-tree walk
// --------------------------------------------------------------------- //

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

/** Node's own resolution: walk up from `fromDir` looking for node_modules/<name>.
 * This is what actually gets loaded, which is the only tree worth gating —
 * a hoisted transitive dep and a top-level one are the same risk. */
function resolvePackageDir(name, fromDir) {
  let dir = fromDir;
  for (;;) {
    const candidate = join(dir, "node_modules", name);
    if (existsSync(join(candidate, "package.json"))) return candidate;
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/**
 * BFS from the root manifest. `runtime` marks everything reachable through
 * `dependencies` alone — the closure that can actually reach dist/. Anything
 * reached only via devDependencies is toolchain. Runtime always wins a tie,
 * because a package that is both must be judged by its stricter role.
 */
function walkTree(rootDir) {
  const manifest = readJson(join(rootDir, "package.json"));
  const found = new Map(); // name -> { version, licence, channel }
  const queue = [];

  for (const name of Object.keys(manifest.dependencies ?? {})) {
    queue.push({ name, from: rootDir, channel: "runtime" });
  }
  for (const name of Object.keys(manifest.devDependencies ?? {})) {
    queue.push({ name, from: rootDir, channel: "dev" });
  }

  while (queue.length > 0) {
    const { name, from, channel } = queue.shift();
    const seen = found.get(name);
    // Re-walk only when a dev-marked package turns out to be runtime-reachable.
    if (seen && !(seen.channel === "dev" && channel === "runtime")) continue;

    const dir = resolvePackageDir(name, from);
    if (!dir) {
      // A declared dependency that is not on disk means the tree was never
      // installed, or was installed partially. Either way the gate has not
      // seen what will actually ship, and saying PASS would be a lie.
      found.set(name, { version: "(not installed)", licence: "", channel, missing: true });
      continue;
    }
    const pkg = readJson(join(dir, "package.json"));
    found.set(name, {
      version: pkg.version ?? "?",
      licence: readLicence(pkg),
      channel,
      dir,
    });

    for (const dep of Object.keys(pkg.dependencies ?? {})) {
      queue.push({ name: dep, from: dir, channel });
    }
    // Optional deps that are present on disk do load, so they are gated too.
    for (const dep of Object.keys(pkg.optionalDependencies ?? {})) {
      if (resolvePackageDir(dep, dir)) queue.push({ name: dep, from: dir, channel });
    }
  }
  return found;
}

/** Everything physically installed, whether or not the manifest closure reaches
 * it. Used to report drift between "what we declared" and "what npm put on
 * disk" — a package present but unreferenced is still a package a build can
 * pick up. */
function scanInstalled(rootDir) {
  const modules = join(rootDir, "node_modules");
  const out = new Set();
  if (!existsSync(modules)) return out;
  const visit = (dir, scope) => {
    for (const entry of readdirSync(dir)) {
      if (entry.startsWith(".")) continue;
      const p = join(dir, entry);
      if (!statSync(p).isDirectory()) continue;
      if (entry.startsWith("@")) {
        visit(p, entry);
        continue;
      }
      if (existsSync(join(p, "package.json"))) out.add(scope ? `${scope}/${entry}` : entry);
    }
  };
  visit(modules, null);
  return out;
}

// --------------------------------------------------------------------- //
// Report
// --------------------------------------------------------------------- //

const STATUS_ORDER = { denied: 0, unknown: 1, "conditional-ok": 2, allowed: 3 };

function render(findings) {
  const lines = [
    "package                                  version      channel   status           licence",
    "-".repeat(110),
  ];
  for (const f of findings) {
    lines.push(
      `${f.name.slice(0, 40).padEnd(40)} ${String(f.version).slice(0, 12).padEnd(12)} ` +
        `${f.channel.padEnd(9)} ${f.status.padEnd(16)} ${f.licence.slice(0, 30)}`
    );
    if (f.detail && f.status !== "allowed") {
      const wrapped = f.detail.length > 88 ? `${f.detail.slice(0, 88)}...` : f.detail;
      lines.push(`${"".padEnd(40)} ${"".padEnd(12)} '-- ${wrapped}`);
    }
  }
  return lines.join("\n");
}

// --------------------------------------------------------------------- //
// Self-test
// --------------------------------------------------------------------- //

/**
 * A gate nobody has watched fail is a gate nobody knows is running. Each case
 * below is a licence class the dashboard could plausibly acquire, and the two
 * that matter most are the last two: a package with NO licence must fail, and
 * a conditional licence on an UNNAMED package must fail. Those are the paths
 * where a broken gate quietly returns "allowed".
 */
function selfTest() {
  const cases = [
    ["fake-sspl-db", "SSPL-1.0", "runtime", "denied"],
    ["fake-agpl-widget", "AGPL-3.0-only", "runtime", "denied"],
    ["fake-gpl-lib", "GPL-3.0", "runtime", "denied"],
    ["fake-busl-lib", "BUSL-1.1", "runtime", "denied"],
    ["react", "MIT", "runtime", "allowed"],
    ["some-apache-lib", "Apache-2.0", "runtime", "allowed"],
    ["type-fest", "(MIT OR CC0-1.0)", "dev", "allowed"],
    ["caniuse-lite", "CC-BY-4.0", "dev", "conditional-ok"],
    ["language-subtag-registry", "CC0-1.0", "dev", "conditional-ok"],
    ["unnamed-cc0-lib", "CC0-1.0", "dev", "denied"],
    ["unnamed-lgpl-lib", "LGPL-3.0-only", "runtime", "denied"],
    ["mystery-lib", "", "runtime", "unknown"],
    ["file-licence-lib", "SEE LICENSE IN LICENSE.md", "runtime", "unknown"],
    ["private-lib", "UNLICENSED", "runtime", "denied"],
    ["exotic-lib", "WTFPL", "runtime", "unknown"],
    // A denied atom must lose even when OR-ed with a permissive one: the
    // permissive branch does not erase the fact that we cannot tell which
    // branch a downstream consumer will rely on.
    ["dual-trap", "MIT OR SSPL-1.0", "runtime", "denied"],
  ];

  let ok = true;
  for (const [name, licence, channel, expected] of cases) {
    const got = classify(name, licence, channel).status;
    if (got !== expected) ok = false;
    console.log(
      `[${got === expected ? "ok  " : "FAIL"}] ${name.padEnd(26)} ` +
        `${(licence || "(none)").padEnd(26)} expected=${expected.padEnd(15)} got=${got}`
    );
  }
  console.log();
  console.log(ok ? "SELF-TEST: PASS — the gate rejects what it claims to reject" : "SELF-TEST: FAIL");
  return ok ? 0 : 1;
}

// --------------------------------------------------------------------- //
// Main
// --------------------------------------------------------------------- //

function main(argv) {
  if (argv.includes("--self-test")) return selfTest();

  if (!existsSync(join(DASHBOARD_ROOT, "node_modules"))) {
    console.error(
      "LICENCE GATE: FAIL — dashboard/node_modules does not exist. Run `npm ci` first;\n" +
        "a gate that has nothing to inspect must not report PASS."
    );
    return 1;
  }

  const tree = walkTree(DASHBOARD_ROOT);
  const findings = [];
  for (const [name, info] of tree) {
    if (info.missing) {
      findings.push({
        name,
        version: "(not installed)",
        licence: "(none)",
        channel: info.channel,
        status: "unknown",
        detail: "declared as a dependency but not present in node_modules",
      });
      continue;
    }
    findings.push({ ...classify(name, info.licence, info.channel), version: info.version });
  }
  findings.sort(
    (a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || a.name.localeCompare(b.name)
  );

  console.log(render(findings));

  const installed = scanInstalled(DASHBOARD_ROOT);
  const unreached = [...installed].filter((n) => !tree.has(n));

  const blocking = findings.filter(
    (f) =>
      (f.status === "denied" || f.status === "unknown") &&
      (DEV_FAILURES_BLOCK || f.channel === "runtime")
  );

  const counts = findings.reduce((acc, f) => {
    acc[f.status] = (acc[f.status] ?? 0) + 1;
    return acc;
  }, {});

  console.log();
  console.log(
    `${findings.length} package(s) in the resolved tree: ` +
      `${counts.allowed ?? 0} allowed, ${counts["conditional-ok"] ?? 0} conditional (named), ` +
      `${counts.denied ?? 0} denied, ${counts.unknown ?? 0} unknown.`
  );
  if (unreached.length > 0) {
    // Not a failure: npm hoists build-time-only packages that no manifest in
    // the closure references. Reported because an unreferenced package on disk
    // is still something a future import can reach without review.
    console.log(
      `${unreached.length} installed package(s) are not reachable from package.json's ` +
        "closure (npm hoisting artefacts); they ship nothing and are not gated."
    );
  }

  if (blocking.length > 0) {
    console.log(`\nLICENCE GATE: FAIL — ${blocking.length} package(s) blocked`);
    for (const f of blocking) {
      console.log(`  - ${f.name} ${f.version} [${f.channel}]: ${f.licence} — ${f.detail}`);
    }
    return 1;
  }
  console.log(`\nLICENCE GATE: PASS — ${findings.length} package(s) cleared`);
  return 0;
}

process.exit(main(process.argv.slice(2)));
