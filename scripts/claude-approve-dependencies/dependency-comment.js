/**
 * Render the review comment for a Dependabot pull request and decide the merge.
 *
 * The deterministic gate from dependency-evidence.js and the model's verdict are
 * combined here rather than in the prompt, so the factual half of the comment
 * and the merge decision stay outside the model's control.
 */

import { readFile, writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";

/**
 * The deterministic gate written by dependency-evidence.js.
 *
 * @typedef {object} Gate
 * @property {boolean} [eligible] whether the bump may merge at all
 * @property {string[]} [blocks] reasons the bump may not merge
 * @property {string[]} [signals] anomalies worth reporting but not blocking
 * @property {string} [summary] one-line list of the version changes
 */

/**
 * The model's structured output, validated against the workflow's json-schema.
 *
 * @typedef {object} Verdict
 * @property {string} [verdict] either `clear` or `concerns`
 * @property {string} [summary] short prose on what the evidence shows
 * @property {string[]} [concerns] one line per thing a human must look at
 */

const MARKER = "<!-- claude-dependency-review -->";
const FOOTER = "> AI-generated review by [Claude](https://claude.ai)";
const MAX_SUMMARY_CHARS = 400;
const MAX_BULLET_CHARS = 200;
const MAX_CONCERNS = 6;

const { values: options } = parseArgs({
  options: {
    gate: { type: "string" },
    "assessment-conclusion": { type: "string", default: "" },
    comment: { type: "string" },
    decision: { type: "string" },
  },
});

/** @param {string} path */
async function loadGate(path) {
  try {
    /** @type {Gate} */
    const gate = JSON.parse(await readFile(path, "utf8"));
    return gate;
  } catch {
    return {};
  }
}

/** @param {string | undefined} raw */
function loadVerdict(raw) {
  if (!raw) {
    return;
  }
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) {
      return;
    }
    /** @type {Verdict} */
    const verdict = parsed;
    return verdict;
  } catch {
    return;
  }
}

/**
 * @param {string | undefined} text
 * @param {number} limit
 */
function tidy(text, limit = MAX_SUMMARY_CHARS) {
  const collapsed = (text ?? "").split(/\s+/).filter(Boolean).join(" ");
  return collapsed.length <= limit
    ? collapsed
    : `${collapsed.slice(0, limit).trimEnd()}...`;
}

const {
  gate: gatePath,
  comment: commentPath,
  decision: decisionPath,
} = options;
if (!gatePath || !commentPath || !decisionPath) {
  throw new Error("--gate, --comment and --decision are required");
}

const gate = await loadGate(gatePath);
const verdict = loadVerdict(process.env.STRUCTURED_OUTPUT);
const assessed =
  options["assessment-conclusion"] === "success" && verdict !== undefined;

const eligible = Boolean(gate.eligible);
const blocks = gate.blocks ?? [];
const signals = gate.signals ?? [];
const concerns = verdict?.concerns ?? [];
const flagged = verdict?.verdict === "concerns";

// the model can only ever withhold a merge the gate already allowed.
const merge = assessed && eligible && !flagged;

let heading;
if (flagged || !assessed) {
  heading = "concerns";
} else if (eligible) {
  heading = "clear";
} else {
  heading = "needs review";
}

const modelSummary = assessed
  ? tidy(verdict?.summary)
  : "The automated assessment did not complete.";

const bullets = [
  ...new Set(
    [
      ...blocks,
      ...concerns.slice(0, MAX_CONCERNS),
      ...(merge ? [] : signals),
    ].map((bullet) => tidy(bullet, MAX_BULLET_CHARS)),
  ),
];

const lines = [
  MARKER,
  "",
  `**Dependency review: ${heading}**`,
  "",
  gate.summary ?? "No dependency metadata available.",
  "",
  ...(modelSummary ? [modelSummary, ""] : []),
  ...(bullets.length > 0
    ? [...bullets.map((bullet) => `- ${bullet}`), ""]
    : []),
  merge
    ? "Auto-merge enabled - merges once the required checks pass."
    : "Not merged - needs a human look.",
  "",
  FOOTER,
];

await writeFile(commentPath, `${lines.join("\n")}\n`);
await writeFile(
  decisionPath,
  `${JSON.stringify({ merge, heading }, undefined, 2)}\n`,
);
