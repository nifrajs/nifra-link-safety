import { expect, test } from "bun:test";

test("CLI keeps a URL positional after a boolean flag", async () => {
  const root = new URL("../../..", import.meta.url).pathname;
  const bun = Bun.which("bun") ?? "bun";
  const process = Bun.spawn(
    [
      bun,
      "run",
      "packages/link-safety-cli/src/index.ts",
      "scan",
      "--corpus",
      "fixtures/synthetic-corpus.jsonl",
      "--allow-act",
      "https://login.example.invalid/account",
    ],
    { cwd: root, stdout: "pipe", stderr: "pipe" },
  );
  const output = await new Response(process.stdout).text();
  const error = await new Response(process.stderr).text();
  expect(await process.exited).toBe(0);
  expect(error).toBe("");
  expect(JSON.parse(output).result.recommendedAction).toBe("block");
});
