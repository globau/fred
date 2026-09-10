/**
 * Collect supply-chain evidence for a Dependabot pull request.
 *
 * Reads the Dependabot metadata plus the base and head lockfiles, gathers npm
 * registry and upstream git evidence, then writes an evidence report for review
 * alongside a deterministic merge gate.
 *
 * This performs network reads only. It never installs, unpacks, or executes any
 * dependency, so a hostile package cannot run code here.
 */

import { readFile, writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";

/**
 * One entry of Dependabot's `updated-dependencies-json` output.
 *
 * @typedef {object} UpdatedDependency
 * @property {string} [dependencyName] package name, or `owner/repo` for an action
 * @property {string} [dependencyType] for example `direct:development`
 * @property {string} [updateType] for example `version-update:semver-minor`
 * @property {string} [packageEcosystem] `npm_and_yarn` or `github_actions`
 * @property {string} [prevVersion] version being replaced
 * @property {string} [newVersion] version being introduced
 * @property {boolean} [maintainerChanges] whether the maintainer set changed
 * @property {string} [alertState] set when the bump fixes a security alert
 * @property {string} [ghsaId] advisory identifier for that alert
 * @property {number} [cvss] severity score for that alert
 */

/**
 * A single version's document within an npm packument.
 *
 * @typedef {object} NpmVersion
 * @property {string} [deprecated] deprecation notice, when the version carries one
 * @property {{ tarball?: string, unpackedSize?: number, attestations?: object }} [dist] tarball location, size and provenance
 * @property {{ name?: string }} [_npmUser] account that published this version
 * @property {string | { url?: string }} [repository] declared source repository
 */

/**
 * The npm registry's metadata document for a package.
 *
 * @typedef {object} Packument
 * @property {Record<string, NpmVersion>} [versions] every published version
 * @property {Record<string, string>} [time] publish timestamp per version
 * @property {{ name?: string }[]} [maintainers] accounts able to publish
 * @property {string | { url?: string }} [repository] declared source repository
 */

/**
 * A commit as returned by the GitHub compare API.
 *
 * @typedef {object} GitCommit
 * @property {string} [sha] commit identifier
 * @property {{ message?: string, author?: { name?: string } }} [commit] message and git author
 * @property {{ login?: string }} [author] GitHub account, when the commit is linked to one
 */

/**
 * The GitHub compare API's response for a tag range.
 *
 * @typedef {object} Comparison
 * @property {GitCommit[]} [commits] commits in the range, capped by the API
 * @property {number} [total_commits] total in the range, which may exceed `commits`
 */

/**
 * A git ref or annotated tag object from the GitHub API.
 *
 * @typedef {object} GitReference
 * @property {{ type?: string, sha?: string }} [object] what the ref points at
 */

/**
 * One entry of a lockfile's `packages` map.
 *
 * @typedef {object} LockfileEntry
 * @property {string} [version] resolved version
 * @property {string} [resolved] URL the tarball came from
 * @property {boolean} [hasInstallScript] whether npm runs a script on install
 */

/**
 * A parsed npm lockfile.
 *
 * @typedef {object} Lockfile
 * @property {Record<string, LockfileEntry>} [packages] entries keyed by install path
 */

const REGISTRY = "https://registry.npmjs.org";
const GITHUB_API = "https://api.github.com";
const TRUSTED_REGISTRY_HOSTS = new Set(["registry.npmjs.org"]);
const UNPACKED_SIZE_RATIO = 3;
const FRESH_PUBLISH_DAYS = 2;
const MAX_COMMITS = 50;
const MAX_LISTED = 25;
const FETCH_ATTEMPTS = 3;
const FETCH_TIMEOUT_MS = 60_000;
const MILLISECONDS_PER_DAY = 86_400_000;

const { values: options } = parseArgs({
  options: {
    deps: { type: "string" },
    diff: { type: "string", default: "" },
    "base-lockfile": { type: "string", default: "" },
    "head-lockfile": { type: "string", default: "" },
    "out-dir": { type: "string" },
  },
});

const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN || "";

/** @param {string} url */
async function fetchJson(url) {
  /** @type {Record<string, string>} */
  const headers = { accept: "application/json" };
  if (token && url.startsWith(GITHUB_API)) {
    headers.authorization = `Bearer ${token}`;
  }

  for (let attempt = 0; attempt < FETCH_ATTEMPTS; attempt++) {
    try {
      const response = await fetch(url, {
        headers,
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!response.ok) {
        // a missing tag or a denied request will not resolve on a retry.
        if ([401, 403, 404].includes(response.status)) {
          return;
        }
        throw new Error(`http ${response.status}`);
      }
      return await response.json();
    } catch {
      if (attempt === FETCH_ATTEMPTS - 1) {
        return;
      }
    }
  }
}

/** @param {string} path */
async function loadJson(path) {
  if (!path) {
    return;
  }
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    return;
  }
}

/** @param {string} path */
async function readText(path) {
  try {
    return await readFile(path, "utf8");
  } catch {
    return "";
  }
}

/** @param {string | undefined} version */
function semver(version) {
  const match = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version ?? "");
  return match?.slice(1, 4).map(Number);
}

/** @param {string | undefined} updateType */
function shortUpdateType(updateType) {
  return (updateType ?? "").split(":semver-").at(-1) || "unknown";
}

/**
 * @param {string | undefined} previous
 * @param {string} updateType
 */
function breaksBelowOne(previous, updateType) {
  const parts = semver(previous);
  if (!parts || parts[0] !== 0) {
    return false;
  }
  if (updateType === "minor") {
    return true;
  }
  return updateType === "patch" && parts[1] === 0;
}

/** @param {string | undefined} url */
function hostOf(url) {
  try {
    return new URL(url ?? "").hostname;
  } catch {
    return;
  }
}

/** @param {string | undefined} url */
function githubRepo(url) {
  const match = /github\.com[/:]([^/]+)\/(.+?)(?:\.git)?(?:[/#?]|$)/.exec(
    url ?? "",
  );
  return match ? `${match[1]}/${match[2]}` : undefined;
}

/** @param {Packument | NpmVersion | undefined} document */
function repositoryUrl(document) {
  const repository = document?.repository;
  if (typeof repository === "string") {
    return repository;
  }
  return repository?.url;
}

/**
 * @param {string} name
 * @param {string} version
 */
function tagCandidates(name, version) {
  const leaf = name.split("/").at(-1);
  return [
    `v${version}`,
    version,
    `${name}@${version}`,
    `${leaf}@${version}`,
    `${leaf}-v${version}`,
  ];
}

/** @param {string | undefined} timestamp */
function publishedDaysAgo(timestamp) {
  if (!timestamp) {
    return;
  }
  const published = Date.parse(timestamp);
  if (Number.isNaN(published)) {
    return;
  }
  return Math.floor((Date.now() - published) / MILLISECONDS_PER_DAY);
}

/**
 * Find the upstream tag pair for this bump and return the commits between them.
 *
 * @param {string} repo
 * @param {string} name
 * @param {string} previous
 * @param {string} next
 */
async function compareUpstream(repo, name, previous, next) {
  const previousTags = tagCandidates(name, previous);
  const nextTags = tagCandidates(name, next);

  for (const [index, previousTag] of previousTags.entries()) {
    const nextTag = nextTags[index];
    if (!nextTag) {
      continue;
    }
    const range = `${encodeURIComponent(previousTag)}...${encodeURIComponent(nextTag)}`;
    /** @type {Comparison | undefined} */
    const comparison = await fetchJson(
      `${GITHUB_API}/repos/${repo}/compare/${range}`,
    );
    if (comparison?.commits) {
      return { previousTag, nextTag, comparison };
    }
  }
}

/**
 * @param {string} repo
 * @param {string} version
 */
async function resolveTagSha(repo, version) {
  for (const tag of [`v${version}`, version]) {
    /** @type {GitReference | undefined} */
    const reference = await fetchJson(
      `${GITHUB_API}/repos/${repo}/git/ref/tags/${encodeURIComponent(tag)}`,
    );
    if (!reference) {
      continue;
    }
    if (reference.object?.type === "tag") {
      /** @type {GitReference | undefined} */
      const annotated = await fetchJson(
        `${GITHUB_API}/repos/${repo}/git/tags/${reference.object.sha}`,
      );
      if (annotated) {
        return { tag, sha: annotated.object?.sha };
      }
    }
    return { tag, sha: reference.object?.sha };
  }
}

/**
 * @param {string} diff
 * @param {string} name
 */
function pinnedShas(diff, name) {
  const escaped = name.replaceAll(/[$()*+.?[\\\]^{|}]/g, "\\$&");
  const pattern = new RegExp(`^\\+.*uses:\\s*${escaped}@([\\da-f]{40})`, "gim");
  return new Set(
    [...diff.matchAll(pattern)].map(([, sha]) => (sha ?? "").toLowerCase()),
  );
}

/**
 * @param {Iterable<string>} items
 * @param {number} limit
 */
function truncated(items, limit = MAX_LISTED) {
  const listed = [...items];
  if (listed.length <= limit) {
    return listed;
  }
  return [...listed.slice(0, limit), `... and ${listed.length - limit} more`];
}

class Evidence {
  /** @type {string[]} */
  blocks = [];
  /** @type {string[]} */
  signals = [];
  /** @type {string[]} */
  lines = [];

  /** @param {string} reason */
  block(reason) {
    if (!this.blocks.includes(reason)) {
      this.blocks.push(reason);
    }
  }

  /** @param {string} note */
  signal(note) {
    if (!this.signals.includes(note)) {
      this.signals.push(note);
    }
  }

  /** @param {string} line */
  write(line = "") {
    this.lines.push(line);
  }
}

/**
 * @param {Evidence} evidence
 * @param {UpdatedDependency} dependency
 */
function assessSemver(evidence, dependency) {
  const name = dependency.dependencyName ?? "unknown";
  const previous = dependency.prevVersion ?? "";
  const next = dependency.newVersion ?? "";
  const updateType = shortUpdateType(dependency.updateType);

  if (updateType === "major") {
    evidence.block(`${name}: major version bump (${previous} -> ${next})`);
  } else if (breaksBelowOne(previous, updateType)) {
    evidence.block(
      `${name}: ${updateType} bump below 1.0.0 is breaking under semver (${previous} -> ${next})`,
    );
  } else if (updateType === "unknown") {
    evidence.block(`${name}: Dependabot reported no semver update type`);
  }

  if (dependency.alertState) {
    evidence.signal(
      `${name}: fixes security alert ${dependency.ghsaId || "unknown"} (state ${dependency.alertState}, CVSS ${dependency.cvss})`,
    );
  }
}

/**
 * @param {Evidence} evidence
 * @param {string} label
 * @param {Comparison} comparison
 */
function writeCommits(evidence, label, comparison) {
  const commits = comparison.commits ?? [];
  evidence.write(
    `- Upstream commits (${label}, ${comparison.total_commits ?? commits.length} total):`,
  );
  for (const commit of commits.slice(0, MAX_COMMITS)) {
    const [subject = ""] = (commit.commit?.message ?? "").split("\n");
    const author =
      commit.author?.login ?? commit.commit?.author?.name ?? "unknown";
    evidence.write(
      `  - ${(commit.sha ?? "").slice(0, 9)} ${author}: ${subject}`,
    );
  }
  if (commits.length > MAX_COMMITS) {
    evidence.write(`  - ... and ${commits.length - MAX_COMMITS} more`);
  }
  evidence.write();
}

/**
 * @param {Evidence} evidence
 * @param {UpdatedDependency} dependency
 */
async function assessNpm(evidence, dependency) {
  const name = dependency.dependencyName ?? "";
  const previous = dependency.prevVersion ?? "";
  const next = dependency.newVersion ?? "";

  evidence.write(`### ${name} ${previous} -> ${next} (npm)`);
  evidence.write();

  /** @type {Packument | undefined} */
  const packument = await fetchJson(
    `${REGISTRY}/${name.split("/").map(encodeURIComponent).join("/")}`,
  );
  if (!packument) {
    evidence.block(`${name}: npm registry metadata could not be fetched`);
    evidence.write("Registry metadata unavailable.");
    evidence.write();
    return;
  }

  const versions = packument.versions ?? {};
  const previousDocument = versions[previous];
  const nextDocument = versions[next];
  const times = packument.time ?? {};

  if (!nextDocument) {
    evidence.block(
      `${name}: version ${next} is not present in the npm registry`,
    );
  }

  if (nextDocument?.deprecated) {
    evidence.block(`${name}: version ${next} is deprecated`);
    evidence.write(`- Deprecated: ${nextDocument.deprecated}`);
  }

  const nextDist = nextDocument?.dist;
  const previousDist = previousDocument?.dist;

  const tarballHost = hostOf(nextDist?.tarball);
  if (tarballHost && !TRUSTED_REGISTRY_HOSTS.has(tarballHost)) {
    evidence.block(`${name}: tarball served from ${tarballHost}`);
  }
  evidence.write(`- Tarball host: ${tarballHost ?? "unknown"}`);

  const age = publishedDaysAgo(times[next]);
  // dependabot files a pull request as soon as a version lands, so a fresh
  // publish is the norm here and only means something next to another anomaly.
  const freshness =
    age !== undefined && age <= FRESH_PUBLISH_DAYS
      ? ` (published ${age} day(s) ago)`
      : "";

  const previousPublisher = previousDocument?._npmUser?.name;
  const nextPublisher = nextDocument?._npmUser?.name;
  evidence.write(
    `- Publisher: ${previousPublisher ?? "unknown"} -> ${nextPublisher ?? "unknown"}`,
  );
  if (
    previousPublisher &&
    nextPublisher &&
    previousPublisher !== nextPublisher
  ) {
    evidence.signal(
      `${name}: publisher changed from ${previousPublisher} to ${nextPublisher}${freshness}`,
    );
  }

  const maintainers = (packument.maintainers ?? [])
    .map((entry) => entry.name ?? "")
    .sort();
  evidence.write(
    `- Current maintainers: ${maintainers.join(", ") || "unknown"}`,
  );

  const previousAttestations = Boolean(previousDist?.attestations);
  const nextAttestations = Boolean(nextDist?.attestations);
  evidence.write(
    `- npm provenance attestations: ${previousAttestations} -> ${nextAttestations}`,
  );
  if (previousAttestations && !nextAttestations) {
    evidence.signal(
      `${name}: lost the npm provenance attestations present on ${previous}${freshness}`,
    );
  }

  const previousSize = previousDist?.unpackedSize;
  const nextSize = nextDist?.unpackedSize;
  evidence.write(`- Unpacked size: ${previousSize} -> ${nextSize}`);
  if (
    previousSize &&
    nextSize &&
    nextSize > previousSize * UNPACKED_SIZE_RATIO
  ) {
    evidence.signal(
      `${name}: unpacked size grew ${(nextSize / previousSize).toFixed(1)}x (${previousSize} -> ${nextSize} bytes)${freshness}`,
    );
  }

  evidence.write(`- Published: ${times[next] ?? "unknown"} (${age} days ago)`);

  const previousRepository = repositoryUrl(previousDocument);
  const nextRepository =
    repositoryUrl(nextDocument) ?? repositoryUrl(packument);
  evidence.write(`- Repository: ${nextRepository ?? "unknown"}`);
  if (
    previousRepository &&
    nextRepository &&
    githubRepo(previousRepository) !== githubRepo(nextRepository)
  ) {
    evidence.signal(
      `${name}: source repository changed from ${previousRepository} to ${nextRepository}`,
    );
  }

  const repo = githubRepo(nextRepository);
  if (!repo) {
    evidence.signal(
      `${name}: no GitHub repository to corroborate the release notes`,
    );
    evidence.write(
      "- Upstream commits: repository not on GitHub, cannot corroborate",
    );
    evidence.write();
    return;
  }

  const upstream = await compareUpstream(repo, name, previous, next);
  if (!upstream) {
    evidence.signal(
      `${name}: no upstream tags matched ${previous}/${next} in ${repo}, release notes are uncorroborated`,
    );
    evidence.write(`- Upstream commits: no matching tags found in ${repo}`);
    evidence.write();
    return;
  }

  writeCommits(
    evidence,
    `${repo} ${upstream.previousTag}...${upstream.nextTag}`,
    upstream.comparison,
  );
}

/**
 * @param {Evidence} evidence
 * @param {UpdatedDependency} dependency
 * @param {string} diff
 */
async function assessGithubAction(evidence, dependency, diff) {
  const name = dependency.dependencyName ?? "";
  const previous = dependency.prevVersion ?? "";
  const next = dependency.newVersion ?? "";

  evidence.write(`### ${name} ${previous} -> ${next} (github-actions)`);
  evidence.write();

  const resolved = await resolveTagSha(name, next);
  evidence.write(
    `- Resolved tag: ${resolved?.tag ?? "none"} -> ${resolved?.sha ?? "unknown"}`,
  );
  if (resolved?.sha) {
    const expected = resolved.sha.toLowerCase();
    const shas = pinnedShas(diff, name);
    evidence.write(
      `- Pinned SHAs added by this PR: ${[...shas].sort().join(", ") || "none"}`,
    );
    const mismatched = [...shas].filter((sha) => sha !== expected).sort();
    if (mismatched.length > 0) {
      evidence.block(
        `${name}: pinned SHA ${mismatched.join(", ")} does not match tag ${resolved.tag} (${resolved.sha})`,
      );
    } else if (shas.size === 0) {
      evidence.signal(
        `${name}: no pinned SHA found in the diff to verify against ${resolved.tag}`,
      );
    }
  } else {
    evidence.block(
      `${name}: tag ${next} could not be resolved in the upstream repository`,
    );
  }

  const upstream = await compareUpstream(name, name, previous, next);
  if (upstream) {
    writeCommits(
      evidence,
      `${upstream.previousTag}...${upstream.nextTag}`,
      upstream.comparison,
    );
  } else {
    evidence.signal(`${name}: no upstream tags matched ${previous}/${next}`);
    evidence.write("- Upstream commits: no matching tags found");
    evidence.write();
  }
}

/**
 * @param {Evidence} evidence
 * @param {UpdatedDependency} dependency
 * @param {string} diff
 */
async function assessDependency(evidence, dependency, diff) {
  assessSemver(evidence, dependency);
  return dependency.packageEcosystem === "github_actions"
    ? assessGithubAction(evidence, dependency, diff)
    : assessNpm(evidence, dependency);
}

/**
 * @param {Evidence} evidence
 * @param {Lockfile | undefined} baseLockfile
 * @param {Lockfile | undefined} headLockfile
 */
function assessLockfile(evidence, baseLockfile, headLockfile) {
  evidence.write("## Lockfile delta");
  evidence.write();

  if (!baseLockfile?.packages || !headLockfile?.packages) {
    evidence.write("No lockfile pair available for this pull request.");
    evidence.write();
    return;
  }

  const basePackages = baseLockfile.packages;
  const headPackages = headLockfile.packages;

  const added = Object.keys(headPackages)
    .filter((key) => !(key in basePackages))
    .sort();
  const removed = Object.keys(basePackages)
    .filter((key) => !(key in headPackages))
    .sort();
  const changed = Object.keys(headPackages)
    .filter(
      (key) =>
        key in basePackages &&
        headPackages[key]?.version !== basePackages[key]?.version,
    )
    .sort();

  evidence.write(
    `- Packages added: ${added.length}, removed: ${removed.length}, version-changed: ${changed.length}`,
  );

  /** @type {[string, string[]][]} */
  const groups = [
    ["Added", added],
    ["Removed", removed],
    ["Changed", changed],
  ];
  for (const [label, keys] of groups) {
    if (keys.length === 0) {
      continue;
    }
    evidence.write(`- ${label}:`);
    for (const key of truncated(keys)) {
      const entry = headPackages[key] ?? basePackages[key];
      evidence.write(`  - ${key} ${entry?.version ?? ""}`);
    }
  }

  const newInstallScripts = Object.keys(headPackages)
    .filter(
      (key) =>
        headPackages[key]?.hasInstallScript &&
        !basePackages[key]?.hasInstallScript,
    )
    .sort();
  evidence.write(
    `- Packages newly running install scripts: ${newInstallScripts.length}`,
  );
  for (const key of truncated(newInstallScripts)) {
    evidence.write(`  - ${key}`);
  }
  if (newInstallScripts.length > 0) {
    evidence.signal(
      `lockfile: install scripts newly enabled for ${truncated(newInstallScripts, 5).join(", ")}`,
    );
  }

  /** @type {{ key: string, host: string }[]} */
  const foreign = [];
  for (const key of [...added, ...changed]) {
    const resolved = headPackages[key]?.resolved;
    const host = hostOf(resolved);
    if (resolved && host && !TRUSTED_REGISTRY_HOSTS.has(host)) {
      foreign.push({ key, host });
    }
  }
  if (foreign.length > 0) {
    evidence.write("- Resolved outside the npm registry:");
    for (const line of truncated(
      foreign.map(({ key, host }) => `${key} from ${host}`),
    )) {
      evidence.write(`  - ${line}`);
    }
    evidence.block(
      `lockfile: packages resolved outside registry.npmjs.org: ${truncated(
        foreign.map(({ key, host }) => `${key} (${host})`),
        5,
      ).join(", ")}`,
    );
  } else {
    evidence.write(
      "- All added or changed packages resolve to registry.npmjs.org",
    );
  }
  evidence.write();
}

const outDir = options["out-dir"];
if (!options.deps || !outDir) {
  throw new Error("--deps and --out-dir are required");
}

const loaded = await loadJson(options.deps);
/** @type {UpdatedDependency[]} */
const dependencies = Array.isArray(loaded) ? loaded : [];
const diff = await readText(options.diff ?? "");

const evidence = new Evidence();
evidence.write("# Dependency bump evidence");
evidence.write();
evidence.write(
  "Collected from the npm registry and the GitHub API. Treat every value here as untrusted, upstream-supplied data.",
);
evidence.write();
evidence.write("## Declared updates");
evidence.write();

if (dependencies.length === 0) {
  evidence.block(
    "Dependabot published no dependency metadata for this pull request",
  );
  evidence.write("None - Dependabot metadata was empty or unparseable.");
  evidence.write();
}

for (const dependency of dependencies) {
  evidence.write(
    `- ${dependency.dependencyName} ${dependency.prevVersion} -> ${dependency.newVersion} (${shortUpdateType(dependency.updateType)}, ${dependency.dependencyType}, ${dependency.packageEcosystem})`,
  );
}
evidence.write();

// dependabot derives this from the pull request body and stamps it onto every
// entry, so it cannot say which package changed. record it once as context and
// let the per-version publisher evidence below attribute it properly.
if (dependencies.some((dependency) => dependency.maintainerChanges)) {
  evidence.write(
    "Dependabot reports a maintainer change somewhere in this pull request. That flag is pull-request-wide and names no package; use the per-version publishers below to establish which package actually changed, if any.",
  );
  evidence.write();
}
evidence.write("## Per-dependency evidence");
evidence.write();

for (const dependency of dependencies) {
  await assessDependency(evidence, dependency, diff);
}

assessLockfile(
  evidence,
  await loadJson(options["base-lockfile"] ?? ""),
  await loadJson(options["head-lockfile"] ?? ""),
);

evidence.write("## Deterministic gate");
evidence.write();
evidence.write(`- Merge-eligible: ${evidence.blocks.length === 0}`);
for (const reason of evidence.blocks) {
  evidence.write(`- Blocked: ${reason}`);
}
for (const note of evidence.signals) {
  evidence.write(`- Signal: ${note}`);
}
evidence.write();

const summary =
  dependencies
    .map(
      (dependency) =>
        `${dependency.dependencyName} ${dependency.prevVersion} -> ${dependency.newVersion} (${shortUpdateType(dependency.updateType)})`,
    )
    .join(", ") || "No dependency metadata available.";

const gate = {
  eligible: evidence.blocks.length === 0,
  blocks: evidence.blocks,
  signals: evidence.signals,
  summary,
};

await writeFile(`${outDir}/evidence.md`, `${evidence.lines.join("\n")}\n`);
await writeFile(
  `${outDir}/gate.json`,
  `${JSON.stringify(gate, undefined, 2)}\n`,
);
