import type { LinkSafetyErrorCode, LinkSafetyReason, NormalizedLink } from "./types.js";

const MAX_URL_LENGTH = 4096;
const MAX_PATH_LENGTH = 2048;
const MAX_QUERY_LENGTH = 4096;

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^\[[0-9a-f:]+\]$/i;

export type NormalizeResult =
  | { readonly ok: true; readonly link: NormalizedLink }
  | { readonly ok: false; readonly error: LinkSafetyErrorCode };

export function normalizeLink(input: unknown): NormalizeResult {
  if (typeof input !== "string") return { ok: false, error: "invalid_url" };
  const value = input.trim();
  if (value.length === 0 || value.length > MAX_URL_LENGTH) {
    return { ok: false, error: "invalid_url" };
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return { ok: false, error: "invalid_url" };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { ok: false, error: "invalid_url" };
  }
  if (parsed.username || parsed.password || parsed.hostname.length === 0) {
    return { ok: false, error: "invalid_url" };
  }
  if (
    parsed.pathname.length > MAX_PATH_LENGTH ||
    parsed.search.length > MAX_QUERY_LENGTH
  ) {
    return { ok: false, error: "invalid_url" };
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/u, "");
  const pathname = parsed.pathname.length === 0 ? "/" : parsed.pathname;
  const port = parsed.port === "" ? undefined : Number(parsed.port);
  if (port !== undefined && (!Number.isSafeInteger(port) || port < 1 || port > 65535)) {
    return { ok: false, error: "invalid_url" };
  }

  const flags: LinkSafetyReason[] = [];
  if (hostname.includes("xn--")) flags.push("punycode_hostname");
  if (isIpLiteral(hostname)) flags.push("ip_literal");
  if (isPrivateAddress(hostname)) flags.push("private_network_candidate");
  if (port !== undefined && port !== (parsed.protocol === "https:" ? 443 : 80)) {
    flags.push("non_default_port");
  }
  if (hostname.length > 100) flags.push("long_hostname");
  if (hostname.split(".").length > 5) flags.push("many_subdomains");
  if (/%(?:2f|5c)/i.test(pathname)) flags.push("encoded_path_separator");
  if (pathname.length > 1024) flags.push("long_path");
  if (parsed.search.length > 0) flags.push("query_present");

  const canonical = `${parsed.protocol}//${hostname}${
    port === undefined ? "" : `:${port}`
  }${pathname}`;
  return {
    ok: true,
    link: Object.freeze({
      protocol: parsed.protocol === "https:" ? "https" : "http",
      hostname,
      ...(port === undefined ? {} : { port }),
      pathname,
      canonical,
      hasQuery: parsed.search.length > 0,
      queryParameterCount: countQueryParameters(parsed.search),
      queryLength: parsed.search.length,
      flags: Object.freeze(flags),
    }),
  };
}

function countQueryParameters(search: string): number {
  if (search.length === 0) return 0;
  try {
    return [...new URLSearchParams(search)].length;
  } catch {
    return 0;
  }
}

function isIpLiteral(hostname: string): boolean {
  return IPV4.test(hostname) || IPV6.test(hostname);
}

function isPrivateAddress(hostname: string): boolean {
  const unwrapped = hostname.replace(/^\[/, "").replace(/\]$/u, "");
  if (
    unwrapped === "localhost" ||
    unwrapped === "::1" ||
    unwrapped.startsWith("fc") ||
    unwrapped.startsWith("fd") ||
    unwrapped.startsWith("fe80:")
  ) {
    return true;
  }
  if (!IPV4.test(unwrapped)) return false;
  const octets = unwrapped.split(".").map(Number);
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return false;
  }
  const first = octets[0] ?? -1;
  const second = octets[1] ?? -1;
  return (
    first === 10 ||
    first === 127 ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  );
}
