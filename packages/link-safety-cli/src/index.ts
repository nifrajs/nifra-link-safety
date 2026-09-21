#!/usr/bin/env bun

import type { LinkSafetyPolicy, LinkSafetyVerdict } from "@nifrajs/link-safety";
import { createLinkSafetyScanner, parseCorpusJsonl } from "@nifrajs/link-safety";
import { createTypeSafeLinkClassifier } from "@nifrajs/link-safety-typesafe";

const DEFAULT_CORPUS_PATH = "fixtures/synthetic-corpus.jsonl";
const DEFAULT_FIXTURES_PATH = "fixtures/synthetic-evaluation.jsonl";
const BOOLEAN_FLAGS = new Set(["stdin", "typesafe", "include-input", "allow-act"]);

interface CliFlags {
  readonly values: ReadonlyMap<string, string>;
  readonly booleans: ReadonlySet<string>;
  readonly positional: readonly string[];
}

interface EvaluationFixture {
  readonly id: string;
  readonly url: string;
  readonly expected: LinkSafetyVerdict;
}

await main();

async function main(): Promise<void> {
  const [command = "help", ...rawArgs] = Bun.argv.slice(2);
  if (command === "help" || command === "--help") {
    printUsage();
    return;
  }
  const flags = parseFlags(rawArgs);
  if (command === "scan") {
    await scanCommand(flags);
    return;
  }
  if (command === "evaluate") {
    await evaluateCommand(flags);
    return;
  }
  throw new Error("unknown command");
}

async function scanCommand(flags: CliFlags): Promise<void> {
  const scanner = await createScanner(flags);
  const inputs =
    flags.booleans.has("stdin") || flags.positional.length === 0
      ? (await Bun.stdin.text()).split(/\r?\n/u).filter((line) => line.trim() !== "")
      : flags.positional;
  if (inputs.length === 0) throw new Error("scan requires a URL or stdin input");
  const policy = readPolicy(flags);
  for (const input of inputs) {
    const result = await scanner.scan(input, { policy });
    console.log(
      JSON.stringify({
        ...(flags.booleans.has("include-input") ? { input } : {}),
        result,
      }),
    );
  }
}

async function evaluateCommand(flags: CliFlags): Promise<void> {
  const corpusPath = flags.values.get("corpus") ?? DEFAULT_CORPUS_PATH;
  const fixturesPath = flags.values.get("fixtures") ?? DEFAULT_FIXTURES_PATH;
  const corpus = parseCorpusJsonl(await Bun.file(corpusPath).text(), {
    version: corpusPath,
  });
  const fixtures = parseFixtures(await Bun.file(fixturesPath).text());
  const scanner = createLinkSafetyScanner({ corpus });
  const counts = new Map<
    LinkSafetyVerdict | "error",
    { total: number; correct: number }
  >();
  let correct = 0;
  for (const fixture of fixtures) {
    const result = await scanner.scan(fixture.url);
    const actual = result.ok ? result.verdict : "error";
    const bucket = counts.get(actual) ?? { total: 0, correct: 0 };
    bucket.total += 1;
    if (actual === fixture.expected) {
      correct += 1;
      bucket.correct += 1;
    }
    counts.set(actual, bucket);
  }
  console.log(
    JSON.stringify({
      total: fixtures.length,
      correct,
      accuracy: fixtures.length === 0 ? 0 : correct / fixtures.length,
      byActualVerdict: Object.fromEntries(counts),
    }),
  );
}

async function createScanner(flags: CliFlags) {
  const corpusPath = flags.values.get("corpus");
  const corpus =
    corpusPath === undefined
      ? undefined
      : parseCorpusJsonl(await Bun.file(corpusPath).text(), { version: corpusPath });
  const classifier = flags.booleans.has("typesafe")
    ? createTypeSafeLinkClassifier({
        ...(Bun.env.TYPESAFE_API_KEY === undefined
          ? {}
          : { apiKey: Bun.env.TYPESAFE_API_KEY }),
        ...(Bun.env.TYPESAFE_MODEL === undefined
          ? {}
          : { model: Bun.env.TYPESAFE_MODEL }),
        ...(Bun.env.TYPESAFE_BASE_URL === undefined
          ? {}
          : { baseUrl: Bun.env.TYPESAFE_BASE_URL }),
      })
    : undefined;
  return createLinkSafetyScanner({
    ...(corpus === undefined ? {} : { corpus }),
    ...(classifier === undefined ? {} : { classifier }),
  });
}

function readPolicy(flags: CliFlags): LinkSafetyPolicy {
  const minimumConfidenceValue = flags.values.get("min-confidence");
  if (minimumConfidenceValue === undefined) {
    return { allowAct: flags.booleans.has("allow-act") };
  }
  const minimumConfidence = Number(minimumConfidenceValue);
  if (!Number.isFinite(minimumConfidence)) {
    throw new Error("--min-confidence must be numeric");
  }
  return {
    allowAct: flags.booleans.has("allow-act"),
    minimumConfidence,
  };
}

function parseFixtures(input: string): readonly EvaluationFixture[] {
  const fixtures: EvaluationFixture[] = [];
  for (const [index, line] of input.split(/\r?\n/u).entries()) {
    if (line.trim() === "") continue;
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      throw new Error(`fixture line ${index + 1} is invalid JSON`);
    }
    if (!isRecord(value)) throw new Error(`fixture line ${index + 1} is invalid`);
    const id = value.id;
    const url = value.url;
    const expected = value.expected;
    if (typeof id !== "string" || typeof url !== "string" || !isVerdict(expected)) {
      throw new Error(`fixture line ${index + 1} is invalid`);
    }
    fixtures.push({ id, url, expected });
  }
  return Object.freeze(fixtures);
}

function parseFlags(args: readonly string[]): CliFlags {
  const values = new Map<string, string>();
  const booleans = new Set<string>();
  const positional: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) continue;
    if (arg.startsWith("--")) {
      const name = arg.slice(2);
      const next = args[index + 1];
      if (!BOOLEAN_FLAGS.has(name) && next !== undefined && !next.startsWith("--")) {
        values.set(name, next);
        index += 1;
      } else {
        booleans.add(name);
      }
    } else {
      positional.push(arg);
    }
  }
  return { values, booleans, positional };
}

function isVerdict(value: unknown): value is LinkSafetyVerdict {
  return (
    value === "benign" ||
    value === "suspicious" ||
    value === "malicious" ||
    value === "unknown"
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function printUsage(): void {
  console.log(
    `Nifra Link Safety\n\nCommands:\n  scan [url...] [--stdin] [--corpus path] [--typesafe] [--allow-act]\n  evaluate [--corpus path] [--fixtures path]\n\nEnvironment for --typesafe:\n  TYPESAFE_API_KEY, TYPESAFE_MODEL, optional TYPESAFE_BASE_URL\n`,
  );
}
