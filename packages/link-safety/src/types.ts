export const LINK_SAFETY_VERDICTS = [
  "benign",
  "suspicious",
  "malicious",
  "unknown",
] as const;

export type LinkSafetyVerdict = (typeof LINK_SAFETY_VERDICTS)[number];
export type ClassifiedLinkVerdict = Exclude<LinkSafetyVerdict, "unknown">;

export const LINK_SAFETY_ACTIONS = ["allow", "review", "block"] as const;
export type LinkSafetyAction = (typeof LINK_SAFETY_ACTIONS)[number];

export const LINK_SAFETY_REASONS = [
  "corpus_benign_match",
  "corpus_suspicious_match",
  "corpus_malicious_match",
  "corpus_conflict",
  "punycode_hostname",
  "ip_literal",
  "private_network_candidate",
  "non_default_port",
  "long_hostname",
  "many_subdomains",
  "encoded_path_separator",
  "long_path",
  "query_present",
  "semantic_classifier",
] as const;

export type LinkSafetyReason = (typeof LINK_SAFETY_REASONS)[number];

export const LINK_SAFETY_ERROR_CODES = [
  "invalid_url",
  "corpus_invalid",
  "corpus_unavailable",
  "classifier_unavailable",
  "classifier_timeout",
  "classifier_rate_limited",
  "classifier_unauthorized",
  "classifier_response_invalid",
  "cancelled",
  "policy_invalid",
  "internal",
] as const;

export type LinkSafetyErrorCode = (typeof LINK_SAFETY_ERROR_CODES)[number];

export type CorpusLabel = Exclude<LinkSafetyVerdict, "unknown">;
export type CorpusIndicatorType = "hostname" | "hostname_path_prefix" | "url_prefix";

export interface NormalizedLink {
  readonly protocol: "http" | "https";
  readonly hostname: string;
  readonly port?: number;
  readonly pathname: string;
  readonly canonical: string;
  readonly hasQuery: boolean;
  readonly queryParameterCount: number;
  readonly queryLength: number;
  readonly flags: readonly LinkSafetyReason[];
}

export interface CorpusEntry {
  readonly id: string;
  readonly indicatorType: CorpusIndicatorType;
  readonly indicator: string;
  readonly label: CorpusLabel;
  readonly category?: string;
  readonly source?: string;
  readonly updatedAt?: string;
}

export interface CorpusMatch {
  readonly entry: CorpusEntry;
  readonly matchType: CorpusIndicatorType;
}

export interface CorpusExamplesOptions {
  readonly limit?: number;
}

export interface LinkCorpus {
  readonly version: string;
  lookup(link: NormalizedLink): PromiseLike<readonly CorpusMatch[]>;
  examples?(
    link: NormalizedLink,
    options?: CorpusExamplesOptions,
  ): PromiseLike<readonly CorpusEntry[]>;
}

export interface LinkClassifierInput {
  readonly link: NormalizedLink;
  readonly matches: readonly CorpusMatch[];
  readonly examples: readonly CorpusEntry[];
  readonly signal: AbortSignal;
}

export interface LinkClassifierSuccess {
  readonly ok: true;
  readonly verdict: ClassifiedLinkVerdict;
  readonly riskScore: number;
  readonly confidence: number;
  readonly reasons?: readonly LinkSafetyReason[];
  readonly provider?: string;
  readonly model?: string;
}

export interface LinkClassifierFailure {
  readonly ok: false;
  readonly error: LinkSafetyErrorCode;
}

export type LinkClassifierResult = LinkClassifierSuccess | LinkClassifierFailure;

export interface LinkClassifier {
  readonly id: string;
  classify(input: LinkClassifierInput): PromiseLike<LinkClassifierResult>;
}

export interface LinkSafetyPolicy {
  /** Automatic allow/block recommendations are disabled unless explicitly true. */
  readonly allowAct?: boolean;
  /** Required confidence for semantic recommendations. Defaults to 0.92. */
  readonly minimumConfidence?: number;
  /** An exact malicious corpus match can recommend block when action is enabled. */
  readonly blockKnownMalicious?: boolean;
}

export interface LinkScanOptions {
  readonly corpus?: LinkCorpus;
  readonly classifier?: LinkClassifier;
  readonly policy?: LinkSafetyPolicy;
  readonly signal?: AbortSignal;
}

export interface LinkScanEvidence {
  readonly corpusVersion?: string;
  readonly corpusMatchCount: number;
  readonly provider?: string;
  readonly model?: string;
  readonly deterministicReasons: readonly LinkSafetyReason[];
  readonly latencyMs: number;
}

export interface LinkScanSuccess {
  readonly ok: true;
  readonly link: NormalizedLink;
  readonly verdict: LinkSafetyVerdict;
  readonly riskScore: number;
  readonly confidence: number;
  readonly reasons: readonly LinkSafetyReason[];
  readonly recommendedAction: LinkSafetyAction;
  readonly policyReason:
    | "automatic_action_not_enabled"
    | "confidence_below_threshold"
    | "conflicting_signals"
    | "no_reliable_signal"
    | "passed";
  readonly evidence: LinkScanEvidence;
}

export interface LinkScanFailure {
  readonly ok: false;
  readonly error: LinkSafetyErrorCode;
  readonly recommendedAction: "review";
  readonly link?: NormalizedLink;
  readonly latencyMs: number;
}

export type LinkScanResult = LinkScanSuccess | LinkScanFailure;

export interface LinkSafetyScanner {
  scan(input: unknown, options?: LinkScanOptions): Promise<LinkScanResult>;
}
