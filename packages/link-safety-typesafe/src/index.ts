import type { DecisionErrorCode, DecisionProvider } from "@nifrajs/decision";
import { choice, defineDecision, score } from "@nifrajs/decision";
import type { TypeSafeProviderOptions } from "@nifrajs/decision-typesafe";
import { createTypeSafeProvider } from "@nifrajs/decision-typesafe";
import type {
  CorpusEntry,
  LinkClassifier,
  LinkClassifierInput,
  LinkClassifierResult,
  LinkSafetyErrorCode,
  LinkSafetyReason,
} from "@nifrajs/link-safety";
import { normalizeLink } from "@nifrajs/link-safety";
import { t } from "@nifrajs/schema";

const DEFAULT_MINIMUM_CONFIDENCE = 0.92;
const MAX_EXAMPLES = 8;

const linkSafetyState = t.object({
  protocol: t.string({ minLength: 1, maxLength: 5 }),
  hostname: t.string({ minLength: 1, maxLength: 253 }),
  pathname: t.string({ minLength: 1, maxLength: 2048 }),
  featureSummary: t.string({ minLength: 2, maxLength: 8192 }),
  corpusEvidence: t.string({ minLength: 2, maxLength: 16_384 }),
});

const linkSafetyDecision = defineDecision({
  name: "link.safety",
  version: "1.0.0",
  state: linkSafetyState,
  questions: {
    verdict: choice({
      instructions:
        "Classify the normalized URL as benign, suspicious, or malicious. Use suspicious when evidence is mixed or incomplete.",
      criteria: {
        benign: "No meaningful abuse signal is present.",
        suspicious: "The URL needs review because signals are ambiguous or risky.",
        malicious:
          "The URL strongly indicates phishing, malware, or another abuse pattern.",
      },
    }),
    risk: score({
      instructions: "Score the operational risk of allowing this URL to proceed.",
      criteria: ["none", "low", "moderate", "high", "critical"],
    }),
  },
});

export interface TypeSafeLinkClassifierOptions {
  readonly apiKey?: string;
  readonly model?: string;
  readonly baseUrl?: string;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
  readonly minimumConfidence?: number;
  readonly exampleLimit?: number;
  readonly provider?: DecisionProvider;
}

export function createTypeSafeLinkClassifier(
  options: TypeSafeLinkClassifierOptions,
): LinkClassifier {
  const minimumConfidence = options.minimumConfidence ?? DEFAULT_MINIMUM_CONFIDENCE;
  if (
    !Number.isFinite(minimumConfidence) ||
    minimumConfidence < 0 ||
    minimumConfidence > 1
  ) {
    throw new RangeError("typesafe link classifier: minimumConfidence is invalid");
  }
  const exampleLimit = options.exampleLimit ?? MAX_EXAMPLES;
  if (
    !Number.isSafeInteger(exampleLimit) ||
    exampleLimit < 0 ||
    exampleLimit > MAX_EXAMPLES
  ) {
    throw new RangeError("typesafe link classifier: exampleLimit is invalid");
  }

  const provider = options.provider ?? createProvider(options);
  return Object.freeze({
    id: "typesafe",
    classify: async (input: LinkClassifierInput): Promise<LinkClassifierResult> => {
      if (input.signal.aborted) return { ok: false, error: "cancelled" };
      const state = createState(input, exampleLimit);
      const result = await linkSafetyDecision.evaluate(state, {
        provider,
        signal: input.signal,
        policy: {
          allowAct: true,
          minimumConfidence,
          decide: (answers) =>
            answers.verdict.choice === "suspicious" ? "review" : "act",
        },
      });
      if (!result.ok) return { ok: false, error: mapDecisionError(result.error.code) };
      const riskLevels = linkSafetyDecision.questions.risk.criteria;
      const riskScore = result.answers.risk.score / Math.max(1, riskLevels.length - 1);
      const reasons: readonly LinkSafetyReason[] = ["semantic_classifier"];
      return {
        ok: true,
        verdict: result.answers.verdict.choice,
        riskScore,
        confidence: Math.min(
          result.answers.verdict.confidence,
          result.answers.risk.confidence,
        ),
        reasons,
        provider: result.metadata.provider,
        ...(result.metadata.model === undefined
          ? {}
          : { model: result.metadata.model }),
      };
    },
  });
}

function createProvider(options: TypeSafeLinkClassifierOptions): DecisionProvider {
  if (
    typeof options.apiKey !== "string" ||
    options.apiKey.trim() === "" ||
    typeof options.model !== "string" ||
    options.model.trim() === ""
  ) {
    throw new TypeError(
      "typesafe link classifier: apiKey and model are required without a provider",
    );
  }
  const providerOptions: TypeSafeProviderOptions = {
    apiKey: options.apiKey,
    model: options.model,
    ...(options.baseUrl === undefined ? {} : { baseUrl: options.baseUrl }),
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
    ...(options.maxResponseBytes === undefined
      ? {}
      : { maxResponseBytes: options.maxResponseBytes }),
  };
  return createTypeSafeProvider(providerOptions);
}

function createState(
  input: LinkClassifierInput,
  exampleLimit: number,
): {
  readonly protocol: string;
  readonly hostname: string;
  readonly pathname: string;
  readonly featureSummary: string;
  readonly corpusEvidence: string;
} {
  const featureSummary = JSON.stringify({
    protocol: input.link.protocol,
    hostname: input.link.hostname,
    pathname: input.link.pathname,
    flags: input.link.flags,
    hasQuery: input.link.hasQuery,
    queryParameterCount: input.link.queryParameterCount,
    queryLength: input.link.queryLength,
  });
  const corpusEvidence = JSON.stringify({
    matches: input.matches.map((match) => serializeEntry(match.entry)),
    examples: input.examples.slice(0, exampleLimit).map(serializeEntry),
  });
  return {
    protocol: input.link.protocol,
    hostname: input.link.hostname,
    pathname: input.link.pathname,
    featureSummary,
    corpusEvidence,
  };
}

function serializeEntry(entry: CorpusEntry): Record<string, string> {
  const safeIndicator =
    entry.indicatorType === "url_prefix"
      ? normalizeUrlIndicator(entry.indicator)
      : entry.indicator;
  return {
    id: entry.id,
    indicatorType: entry.indicatorType,
    indicator: safeIndicator,
    label: entry.label,
    ...(entry.category === undefined ? {} : { category: entry.category }),
  };
}

function normalizeUrlIndicator(value: string): string {
  const normalized = normalizeLink(value);
  return normalized.ok ? normalized.link.canonical : "invalid-indicator";
}

function mapDecisionError(code: DecisionErrorCode): LinkSafetyErrorCode {
  if (code === "cancelled") return "cancelled";
  if (code === "provider_timeout") return "classifier_timeout";
  if (code === "provider_rate_limited") return "classifier_rate_limited";
  if (code === "provider_unauthorized") return "classifier_unauthorized";
  if (code === "provider_bad_request") return "classifier_response_invalid";
  if (code === "provider_response_invalid") return "classifier_response_invalid";
  if (code === "provider_unavailable") return "classifier_unavailable";
  return "classifier_response_invalid";
}
