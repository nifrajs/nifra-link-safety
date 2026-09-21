import { normalizeLink } from "./normalize.js";
import type {
  CorpusEntry,
  CorpusExamplesOptions,
  CorpusIndicatorType,
  CorpusLabel,
  CorpusMatch,
  LinkCorpus,
  NormalizedLink,
} from "./types.js";

const MAX_CORPUS_BYTES = 64 * 1024 * 1024;
const MAX_CORPUS_ENTRIES = 100_000;
const MAX_LINE_BYTES = 32 * 1024;
const MAX_ID_LENGTH = 128;
const MAX_INDICATOR_LENGTH = 4096;
const MAX_TEXT_LENGTH = 256;

const LABELS = new Set<CorpusLabel>(["benign", "suspicious", "malicious"]);
const INDICATOR_TYPES = new Set<CorpusIndicatorType>([
  "hostname",
  "hostname_path_prefix",
  "url_prefix",
]);

interface IndexedEntry {
  readonly entry: CorpusEntry;
  readonly host: string;
  readonly pathPrefix?: string;
  readonly canonicalPrefix?: string;
}

export interface MemoryCorpusOptions {
  readonly version?: string;
}

export function createMemoryCorpus(
  entries: readonly unknown[],
  options: MemoryCorpusOptions = {},
): LinkCorpus {
  if (!Array.isArray(entries) || entries.length > MAX_CORPUS_ENTRIES) {
    throw new RangeError("corpus: too many entries");
  }
  const version = validateText(options.version ?? "memory", "version", 128);
  const ids = new Set<string>();
  const indexed: IndexedEntry[] = [];
  for (const [index, raw] of entries.entries()) {
    const entry = validateEntry(raw, index);
    if (ids.has(entry.id)) throw new TypeError("corpus: duplicate entry id");
    ids.add(entry.id);
    indexed.push(indexEntry(entry));
  }

  return Object.freeze({
    version,
    lookup: async (link: NormalizedLink): Promise<readonly CorpusMatch[]> => {
      const matches = indexed
        .filter((item) => matchesLink(item, link))
        .map((item) =>
          Object.freeze({
            entry: item.entry,
            matchType: item.entry.indicatorType,
          }),
        );
      return Object.freeze(matches);
    },
    examples: async (
      link: NormalizedLink,
      exampleOptions: CorpusExamplesOptions = {},
    ): Promise<readonly CorpusEntry[]> => {
      const limit = validateLimit(exampleOptions.limit);
      const hostMatches = indexed
        .filter((item) => item.host === link.hostname)
        .slice(0, limit)
        .map((item) => item.entry);
      return Object.freeze(hostMatches);
    },
  });
}

export function parseCorpusJsonl(
  input: string,
  options: MemoryCorpusOptions = {},
): LinkCorpus {
  if (typeof input !== "string") throw new TypeError("corpus: input is invalid");
  if (new TextEncoder().encode(input).byteLength > MAX_CORPUS_BYTES) {
    throw new RangeError("corpus: input is too large");
  }
  const entries: unknown[] = [];
  for (const [index, line] of input.split(/\r?\n/u).entries()) {
    if (line.trim() === "") continue;
    if (new TextEncoder().encode(line).byteLength > MAX_LINE_BYTES) {
      throw new RangeError(`corpus: line ${index + 1} is too large`);
    }
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      throw new TypeError(`corpus: line ${index + 1} is not valid JSON`);
    }
    entries.push(value);
  }
  return createMemoryCorpus(entries, options);
}

function validateEntry(value: unknown, index: number): CorpusEntry {
  if (!isRecord(value)) throw new TypeError(`corpus: entry ${index + 1} is invalid`);
  const id = validateText(value.id, "entry id", MAX_ID_LENGTH);
  const indicatorType = value.indicatorType;
  if (
    typeof indicatorType !== "string" ||
    !INDICATOR_TYPES.has(indicatorType as CorpusIndicatorType)
  ) {
    throw new TypeError(`corpus: entry ${index + 1} has an invalid indicator type`);
  }
  const indicator = validateText(value.indicator, "indicator", MAX_INDICATOR_LENGTH);
  const label = value.label;
  if (typeof label !== "string" || !LABELS.has(label as CorpusLabel)) {
    throw new TypeError(`corpus: entry ${index + 1} has an invalid label`);
  }
  const category = optionalText(value.category, "category", MAX_TEXT_LENGTH);
  const source = optionalText(value.source, "source", MAX_TEXT_LENGTH);
  const updatedAt = optionalText(value.updatedAt, "updatedAt", 64);
  const entry: CorpusEntry = {
    id,
    indicatorType: indicatorType as CorpusIndicatorType,
    indicator,
    label: label as CorpusLabel,
    ...(category === undefined ? {} : { category }),
    ...(source === undefined ? {} : { source }),
    ...(updatedAt === undefined ? {} : { updatedAt }),
  };
  return Object.freeze(entry);
}

function indexEntry(entry: CorpusEntry): IndexedEntry {
  if (entry.indicatorType === "hostname") {
    return Object.freeze({ entry, host: normalizeHost(entry.indicator) });
  }
  if (entry.indicatorType === "hostname_path_prefix") {
    const slash = entry.indicator.indexOf("/");
    if (slash <= 0) {
      throw new TypeError("corpus: hostname path indicator is invalid");
    }
    const host = normalizeHost(entry.indicator.slice(0, slash));
    const pathPrefix = normalizePathPrefix(entry.indicator.slice(slash));
    return Object.freeze({ entry, host, pathPrefix });
  }
  const normalized = normalizeLink(entry.indicator);
  if (!normalized.ok) throw new TypeError("corpus: URL indicator is invalid");
  return Object.freeze({
    entry,
    host: normalized.link.hostname,
    canonicalPrefix: normalized.link.canonical,
  });
}

function matchesLink(item: IndexedEntry, link: NormalizedLink): boolean {
  if (item.host !== link.hostname) return false;
  if (item.pathPrefix !== undefined && !link.pathname.startsWith(item.pathPrefix)) {
    return false;
  }
  return (
    item.canonicalPrefix === undefined ||
    link.canonical.startsWith(item.canonicalPrefix)
  );
}

function normalizeHost(value: string): string {
  const host = value.trim().toLowerCase().replace(/\.$/u, "");
  if (host.length === 0 || host.includes("/") || host.includes("@")) {
    throw new TypeError("corpus: hostname indicator is invalid");
  }
  return host;
}

function normalizePathPrefix(value: string): string {
  if (!value.startsWith("/") || value.length > 2048) {
    throw new TypeError("corpus: path prefix is invalid");
  }
  return value;
}

function validateText(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string" || value.trim() === "" || value.length > maxLength) {
    throw new TypeError(`corpus: ${label} is invalid`);
  }
  return value;
}

function optionalText(
  value: unknown,
  label: string,
  maxLength: number,
): string | undefined {
  if (value === undefined) return undefined;
  return validateText(value, label, maxLength);
}

function validateLimit(value: number | undefined): number {
  if (value === undefined) return 8;
  if (!Number.isSafeInteger(value) || value < 0 || value > 32) {
    throw new RangeError("corpus: example limit must be between 0 and 32");
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
