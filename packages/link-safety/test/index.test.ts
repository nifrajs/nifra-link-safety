import { describe, expect, test } from "bun:test";
import type { LinkClassifier, LinkClassifierInput } from "../src/index.js";
import {
  createLinkSafetyScanner,
  createMemoryCorpus,
  normalizeLink,
} from "../src/index.js";

describe("link normalization", () => {
  test("omits query values and records bounded query metadata", () => {
    const result = normalizeLink("https://example.test/path?token=secret#fragment");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.link.canonical).toBe("https://example.test/path");
    expect(result.link.queryParameterCount).toBe(1);
    expect(result.link.queryLength).toBeGreaterThan(0);
    expect(JSON.stringify(result.link)).not.toContain("secret");
  });

  test("rejects credentials and unsupported schemes", () => {
    expect(normalizeLink("https://user:password@example.test").ok).toBe(false);
    expect(normalizeLink("javascript:alert(1)").ok).toBe(false);
  });

  test("marks private IP literals without fetching them", () => {
    const result = normalizeLink("http://127.0.0.1:8080/admin");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.link.flags).toContain("ip_literal");
    expect(result.link.flags).toContain("private_network_candidate");
  });
});

describe("corpus and scanner", () => {
  const corpus = createMemoryCorpus(
    [
      {
        id: "known-good",
        indicatorType: "hostname",
        indicator: "docs.example.test",
        label: "benign",
      },
      {
        id: "known-bad",
        indicatorType: "hostname",
        indicator: "login.example.invalid",
        label: "malicious",
      },
      {
        id: "review-prefix",
        indicatorType: "hostname_path_prefix",
        indicator: "redirect.example.invalid/claim",
        label: "suspicious",
      },
    ],
    { version: "fixture-1" },
  );

  test("matches hostname and path-prefix entries", async () => {
    const link = normalizeLink("https://redirect.example.invalid/claim/prize");
    expect(link.ok).toBe(true);
    if (!link.ok) return;
    const matches = await corpus.lookup(link.link);
    expect(matches).toHaveLength(1);
    expect(matches[0]?.entry.label).toBe("suspicious");
  });

  test("defaults to review and blocks only with explicit policy", async () => {
    const scanner = createLinkSafetyScanner({ corpus });
    const review = await scanner.scan("https://login.example.invalid/account");
    expect(review.ok).toBe(true);
    if (!review.ok) return;
    expect(review.verdict).toBe("malicious");
    expect(review.recommendedAction).toBe("review");

    const block = await scanner.scan("https://login.example.invalid/account", {
      policy: { allowAct: true },
    });
    expect(block.ok).toBe(true);
    if (!block.ok) return;
    expect(block.recommendedAction).toBe("block");
  });

  test("unknown links remain reviewable", async () => {
    const scanner = createLinkSafetyScanner({ corpus });
    const result = await scanner.scan("https://unknown.example.test/welcome");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.verdict).toBe("unknown");
    expect(result.recommendedAction).toBe("review");
  });

  test("fails closed on invalid classifier output", async () => {
    const classifier: LinkClassifier = {
      id: "invalid",
      classify: async (_input: LinkClassifierInput) =>
        ({
          ok: true,
          verdict: "benign",
          riskScore: 2,
          confidence: 1,
        }) as never,
    };
    const result = await createLinkSafetyScanner({ classifier }).scan(
      "https://unknown.example.test",
    );
    expect(result).toEqual(
      expect.objectContaining({
        ok: false,
        error: "classifier_response_invalid",
        recommendedAction: "review",
      }),
    );
  });

  test("does not pass query values to the classifier", async () => {
    let received: LinkClassifierInput | undefined;
    const classifier: LinkClassifier = {
      id: "capture",
      classify: async (input) => {
        received = input;
        return {
          ok: true,
          verdict: "benign",
          riskScore: 0.1,
          confidence: 0.99,
        };
      },
    };
    const result = await createLinkSafetyScanner({ classifier }).scan(
      "https://unknown.example.test/?token=secret",
    );
    expect(result.ok).toBe(true);
    expect(JSON.stringify(received)).not.toContain("secret");
  });
});
