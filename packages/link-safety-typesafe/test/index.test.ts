import { expect, test } from "bun:test";
import type {
  DecisionProvider,
  DecisionProviderRequest,
  DecisionProviderResult,
} from "@nifrajs/decision";
import { normalizeLink } from "@nifrajs/link-safety";
import { createTypeSafeLinkClassifier } from "../src/index.js";

test("TypeSafe classifier sends bounded features and maps typed answers", async () => {
  let received: DecisionProviderRequest | undefined;
  const provider: DecisionProvider = {
    id: "fake-typesafe",
    evaluate: async (request): Promise<DecisionProviderResult> => {
      received = request;
      return {
        ok: true,
        answers: {
          verdict: {
            type: "choice",
            choice: "malicious",
            probabilities: { benign: 0.01, suspicious: 0.04, malicious: 0.95 },
            confidence: 0.98,
          },
          risk: {
            type: "score",
            score: 4,
            probabilities: { "0": 0, "1": 0, "2": 0, "3": 0.05, "4": 0.95 },
            confidence: 0.97,
          },
        },
        provider: "fake",
        model: "fixture",
      };
    },
  };
  const link = normalizeLink("https://login.example.invalid/?token=secret");
  expect(link.ok).toBe(true);
  if (!link.ok) return;

  const classifier = createTypeSafeLinkClassifier({ provider });
  const result = await classifier.classify({
    link: link.link,
    matches: [],
    examples: [],
    signal: new AbortController().signal,
  });

  expect(result).toEqual(
    expect.objectContaining({
      ok: true,
      verdict: "malicious",
      riskScore: 1,
      confidence: 0.97,
      provider: "fake",
      model: "fixture",
    }),
  );
  expect(JSON.stringify(received?.state)).not.toContain("secret");
});

test("requires credentials when no provider is injected", () => {
  expect(() => createTypeSafeLinkClassifier({ model: "jev-test" })).toThrow(
    "apiKey and model are required",
  );
});
