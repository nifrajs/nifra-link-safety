import { normalizeLink } from "./normalize.js";
import type {
  CorpusEntry,
  CorpusMatch,
  LinkClassifier,
  LinkClassifierResult,
  LinkSafetyErrorCode,
  LinkSafetyPolicy,
  LinkSafetyReason,
  LinkSafetyVerdict,
  LinkScanEvidence,
  LinkScanFailure,
  LinkScanOptions,
  LinkScanResult,
  LinkScanSuccess,
  NormalizedLink,
} from "./types.js";
import { LINK_SAFETY_ERROR_CODES, LINK_SAFETY_REASONS } from "./types.js";

const DEFAULT_MINIMUM_CONFIDENCE = 0.92;
const ERROR_CODE_SET = new Set<string>(LINK_SAFETY_ERROR_CODES);
const REASON_SET = new Set<string>(LINK_SAFETY_REASONS);

export function createLinkSafetyScanner(defaults: LinkScanOptions = {}): {
  scan(input: unknown, options?: LinkScanOptions): Promise<LinkScanResult>;
} {
  return Object.freeze({
    scan: (input: unknown, options: LinkScanOptions = {}) =>
      scanLink(input, mergeOptions(defaults, options)),
  });
}

export async function scanLink(
  input: unknown,
  options: LinkScanOptions = {},
): Promise<LinkScanResult> {
  const startedAt = Date.now();
  const normalized = normalizeLink(input);
  if (!normalized.ok) return failure(normalized.error, startedAt);
  const signal = options.signal ?? new AbortController().signal;
  if (signal.aborted) return failure("cancelled", startedAt, normalized.link);

  const policyResult = validatePolicy(options.policy);
  if (!policyResult.ok) return failure("policy_invalid", startedAt, normalized.link);
  const policy = policyResult.policy;

  let matches: readonly CorpusMatch[] = [];
  let corpusVersion: string | undefined;
  if (options.corpus !== undefined) {
    if (!isValidCorpus(options.corpus)) {
      return failure("corpus_invalid", startedAt, normalized.link);
    }
    corpusVersion = options.corpus.version;
    try {
      matches = await options.corpus.lookup(normalized.link);
    } catch {
      return failure("corpus_unavailable", startedAt, normalized.link);
    }
  }
  if (signal.aborted) return failure("cancelled", startedAt, normalized.link);

  const deterministic = deterministicClassification(normalized.link, matches);
  const hardMalicious = matches.some((match) => match.entry.label === "malicious");
  let semantic: LinkClassifierResult | undefined;
  let examples: readonly CorpusEntry[] = [];
  if (options.classifier !== undefined && !hardMalicious) {
    if (!isValidClassifier(options.classifier)) {
      return failure("classifier_response_invalid", startedAt, normalized.link);
    }
    if (options.corpus?.examples !== undefined) {
      try {
        examples = await options.corpus.examples(normalized.link, { limit: 8 });
      } catch {
        return failure("corpus_unavailable", startedAt, normalized.link);
      }
    }
    try {
      semantic = validateClassifierResult(
        await options.classifier.classify({
          link: normalized.link,
          matches,
          examples,
          signal,
        }),
      );
    } catch {
      return failure(
        signal.aborted ? "cancelled" : "classifier_unavailable",
        startedAt,
        normalized.link,
      );
    }
    if (!semantic.ok) return failure(semantic.error, startedAt, normalized.link);
  }
  if (signal.aborted) return failure("cancelled", startedAt, normalized.link);

  return combineClassification(
    normalized.link,
    matches,
    semantic?.ok === true ? semantic : undefined,
    deterministic,
    policy,
    corpusVersion,
    options.classifier?.id,
    startedAt,
  );
}

interface DeterministicClassification {
  readonly verdict: LinkSafetyVerdict;
  readonly riskScore: number;
  readonly confidence: number;
  readonly reasons: readonly LinkSafetyReason[];
}

function combineClassification(
  link: NormalizedLink,
  matches: readonly CorpusMatch[],
  semantic: Extract<LinkClassifierResult, { ok: true }> | undefined,
  deterministic: DeterministicClassification,
  policy: Required<LinkSafetyPolicy>,
  corpusVersion: string | undefined,
  classifierId: string | undefined,
  startedAt: number,
): LinkScanSuccess {
  const labels = new Set(matches.map((match) => match.entry.label));
  const conflict = labels.size > 1;
  const reasons = new Set<LinkSafetyReason>(deterministic.reasons);
  let verdict: LinkSafetyVerdict = deterministic.verdict;
  let confidence = deterministic.confidence;
  let riskScore = deterministic.riskScore;
  let provider: string | undefined;
  let model: string | undefined;

  if (semantic !== undefined) {
    provider = semantic.provider ?? classifierId;
    model = semantic.model;
    reasons.add("semantic_classifier");
    for (const reason of semantic.reasons ?? []) reasons.add(reason);
    riskScore = Math.max(riskScore, semantic.riskScore);
    confidence = semantic.confidence;
    verdict = semantic.verdict;
    if (deterministic.verdict === "malicious" || conflict) {
      verdict = conflict ? "suspicious" : "malicious";
    } else if (deterministic.riskScore >= 0.65 && semantic.verdict === "benign") {
      verdict = "suspicious";
    }
  }
  if (conflict) {
    reasons.add("corpus_conflict");
    verdict = "suspicious";
    confidence = Math.min(confidence, 0.5);
  }

  const policyDecision = recommendedAction(
    verdict,
    confidence,
    policy,
    matches,
    conflict,
  );
  const evidence: LinkScanEvidence = Object.freeze({
    ...(corpusVersion === undefined ? {} : { corpusVersion }),
    corpusMatchCount: matches.length,
    ...(provider === undefined ? {} : { provider }),
    ...(model === undefined ? {} : { model }),
    deterministicReasons: Object.freeze([...deterministic.reasons]),
    latencyMs: Math.max(0, Date.now() - startedAt),
  });
  return Object.freeze({
    ok: true,
    link,
    verdict,
    riskScore: clampUnit(riskScore),
    confidence: clampUnit(confidence),
    reasons: Object.freeze([...reasons]),
    recommendedAction: policyDecision.action,
    policyReason: policyDecision.reason,
    evidence,
  });
}

function deterministicClassification(
  link: NormalizedLink,
  matches: readonly CorpusMatch[],
): DeterministicClassification {
  const reasons = new Set<LinkSafetyReason>(link.flags);
  const labels = new Set(matches.map((match) => match.entry.label));
  if (labels.has("malicious")) reasons.add("corpus_malicious_match");
  if (labels.has("suspicious")) reasons.add("corpus_suspicious_match");
  if (labels.has("benign")) reasons.add("corpus_benign_match");
  if (labels.size > 1) reasons.add("corpus_conflict");

  if (labels.size > 1) {
    return {
      verdict: "suspicious",
      riskScore: 0.75,
      confidence: 0.5,
      reasons: [...reasons],
    };
  }
  if (labels.has("malicious")) {
    return { verdict: "malicious", riskScore: 1, confidence: 1, reasons: [...reasons] };
  }
  if (labels.has("suspicious")) {
    return {
      verdict: "suspicious",
      riskScore: 0.75,
      confidence: 1,
      reasons: [...reasons],
    };
  }
  if (labels.has("benign") && link.flags.length === 0) {
    return { verdict: "benign", riskScore: 0.05, confidence: 1, reasons: [...reasons] };
  }

  const riskScore = heuristicRisk(link);
  return {
    verdict: riskScore >= 0.65 ? "suspicious" : "unknown",
    riskScore,
    confidence: riskScore >= 0.65 ? 0.6 : 0,
    reasons: [...reasons],
  };
}

function heuristicRisk(link: NormalizedLink): number {
  const weights: Partial<Record<LinkSafetyReason, number>> = {
    punycode_hostname: 0.3,
    ip_literal: 0.25,
    private_network_candidate: 0.4,
    non_default_port: 0.12,
    long_hostname: 0.12,
    many_subdomains: 0.12,
    encoded_path_separator: 0.3,
    long_path: 0.08,
  };
  return clampUnit(link.flags.reduce((total, flag) => total + (weights[flag] ?? 0), 0));
}

function recommendedAction(
  verdict: LinkSafetyVerdict,
  confidence: number,
  policy: Required<LinkSafetyPolicy>,
  matches: readonly CorpusMatch[],
  conflict: boolean,
): {
  readonly action: "allow" | "review" | "block";
  readonly reason: LinkScanSuccess["policyReason"];
} {
  if (!policy.allowAct) {
    return { action: "review", reason: "automatic_action_not_enabled" };
  }
  if (conflict) return { action: "review", reason: "conflicting_signals" };
  const knownMalicious = matches.some((match) => match.entry.label === "malicious");
  if (
    verdict === "malicious" &&
    (knownMalicious
      ? policy.blockKnownMalicious
      : confidence >= policy.minimumConfidence)
  ) {
    return { action: "block", reason: "passed" };
  }
  if (verdict === "benign" && confidence >= policy.minimumConfidence) {
    return { action: "allow", reason: "passed" };
  }
  if (verdict === "unknown") return { action: "review", reason: "no_reliable_signal" };
  return { action: "review", reason: "confidence_below_threshold" };
}

function validatePolicy(
  policy: LinkSafetyPolicy | undefined,
):
  | { readonly ok: true; readonly policy: Required<LinkSafetyPolicy> }
  | { readonly ok: false } {
  const value = policy ?? {};
  const minimumConfidence = value.minimumConfidence ?? DEFAULT_MINIMUM_CONFIDENCE;
  if (
    typeof minimumConfidence !== "number" ||
    !Number.isFinite(minimumConfidence) ||
    minimumConfidence < 0 ||
    minimumConfidence > 1
  ) {
    return { ok: false };
  }
  return {
    ok: true,
    policy: {
      allowAct: value.allowAct === true,
      minimumConfidence,
      blockKnownMalicious: value.blockKnownMalicious !== false,
    },
  };
}

function validateClassifierResult(result: unknown): LinkClassifierResult {
  if (!isRecord(result) || typeof result.ok !== "boolean") {
    return { ok: false, error: "classifier_response_invalid" };
  }
  if (!result.ok) {
    return {
      ok: false,
      error: isLinkSafetyErrorCode(result.error)
        ? result.error
        : "classifier_response_invalid",
    };
  }
  if (
    result.verdict !== "benign" &&
    result.verdict !== "suspicious" &&
    result.verdict !== "malicious"
  ) {
    return { ok: false, error: "classifier_response_invalid" };
  }
  if (!isUnit(result.riskScore) || !isUnit(result.confidence)) {
    return { ok: false, error: "classifier_response_invalid" };
  }
  const reasons = result.reasons;
  if (
    reasons !== undefined &&
    (!Array.isArray(reasons) ||
      reasons.length > 16 ||
      reasons.some((reason) => !isReason(reason)))
  ) {
    return { ok: false, error: "classifier_response_invalid" };
  }
  return {
    ok: true,
    verdict: result.verdict,
    riskScore: result.riskScore,
    confidence: result.confidence,
    ...(reasons === undefined ? {} : { reasons: Object.freeze([...reasons]) }),
    ...(typeof result.provider === "string" && result.provider.length <= 128
      ? { provider: result.provider }
      : {}),
    ...(typeof result.model === "string" && result.model.length <= 128
      ? { model: result.model }
      : {}),
  };
}

function isValidCorpus(
  value: unknown,
): value is NonNullable<LinkScanOptions["corpus"]> {
  return (
    isRecord(value) &&
    typeof value.version === "string" &&
    typeof value.lookup === "function"
  );
}

function isValidClassifier(value: unknown): value is LinkClassifier {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    value.id.length > 0 &&
    typeof value.classify === "function"
  );
}

function mergeOptions(
  defaults: LinkScanOptions,
  options: LinkScanOptions,
): LinkScanOptions {
  return {
    ...defaults,
    ...options,
    policy: { ...defaults.policy, ...options.policy },
  };
}

function failure(
  error: LinkSafetyErrorCode,
  startedAt: number,
  link?: NormalizedLink,
): LinkScanFailure {
  return Object.freeze({
    ok: false,
    error,
    recommendedAction: "review",
    ...(link === undefined ? {} : { link }),
    latencyMs: Math.max(0, Date.now() - startedAt),
  });
}

function isLinkSafetyErrorCode(value: unknown): value is LinkSafetyErrorCode {
  return typeof value === "string" && ERROR_CODE_SET.has(value);
}

function isReason(value: unknown): value is LinkSafetyReason {
  return typeof value === "string" && REASON_SET.has(value);
}

function isUnit(value: unknown): value is number {
  return (
    typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1
  );
}

function clampUnit(value: number): number {
  return Math.max(0, Math.min(1, Number.isFinite(value) ? value : 0));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
