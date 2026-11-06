/**
 * Path normalisation and redaction.
 *
 * normalisePath(): used for grouping/fingerprints. Collapses IDs, hashes and
 *   random tokens to placeholders so e.g. every webhook call
 *   from one integration lands in one fingerprint.
 * redactPath(): used for display. Keeps the shape of the real path but cuts
 *   token-like segments to their first 8 characters, since notifications
 *   pass through third parties.
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX = /^[0-9a-f]{12,}$/i;
const DIGITS = /^\d{3,}$/;
const TOKENISH = /^[A-Za-z0-9_\-.~=+%]{16,}$/;

export type SegmentKind = "uuid" | "hex" | "num" | "token" | "plain";

export function classifySegment(seg: string): SegmentKind {
  if (seg.length === 0) return "plain";
  if (UUID.test(seg)) return "uuid";
  if (HEX.test(seg) && /\d/.test(seg)) return "hex";
  if (DIGITS.test(seg)) return "num";
  if (TOKENISH.test(seg)) {
    // Long segment with a mix of character classes => random token.
    // Plain long words like "configuration" or "authorization-callback"
    // have no digits and are kept.
    const hasDigit = /\d/.test(seg);
    const hasLetter = /[A-Za-z]/.test(seg);
    const hasUpperAndLower = /[a-z]/.test(seg) && /[A-Z]/.test(seg);
    if ((hasDigit && hasLetter) || (hasUpperAndLower && seg.length >= 24)) return "token";
    // Prefixed IDs like "vendor_abcdef0123456789abcd"
    const tail = seg.split(/[_\-.]/).pop() ?? "";
    if (tail.length >= 12 && /\d/.test(tail) && /[A-Za-z]/.test(tail)) return "token";
  }
  return "plain";
}

function splitPath(path: string): string[] {
  const noQuery = path.split(/[?#]/, 1)[0] ?? "";
  return noQuery.split("/");
}

export function normalisePath(path: string): string {
  if (!path) return "/";
  const out = splitPath(path).map((seg) => {
    switch (classifySegment(seg)) {
      case "uuid":
      case "hex":
      case "token":
        return "{id}";
      case "num":
        return "{n}";
      default:
        return seg;
    }
  });
  let joined = out.join("/");
  if (!joined.startsWith("/")) joined = "/" + joined;
  // Collapse repeated slashes that scanners like to send.
  return joined.replace(/\/{2,}/g, "/");
}

export function truncateToken(s: string, keep = 8): string {
  return s.length > keep ? s.slice(0, keep) + "…" : s;
}

export function redactPath(path: string): string {
  if (!path) return "/";
  return splitPath(path)
    .map((seg) => {
      const k = classifySegment(seg);
      return k === "plain" || k === "num" ? seg : truncateToken(seg);
    })
    .join("/");
}

/**
 * Remove anything resembling a credential from free text (audit log values,
 * error messages) before it is put into a notification.
 */
export function redactText(text: string): string {
  return text
    .replace(/(authorization|cookie|set-cookie|x-auth-key|x-auth-email|cf-access-jwt-assertion|cf-access-client-secret)\s*[:=]\s*(?:(?:Bearer|Basic|Token)\s+)?\S+/gi, "$1: [redacted]")
    .replace(/Bearer\s+[A-Za-z0-9._\-~+/=]+/g, "Bearer [redacted]")
    .replace(/[A-Za-z0-9_\-]{32,}/g, (m) => truncateToken(m));
}

/** Convert a simple glob (`*`, `?`) to an anchored, case-insensitive RegExp. */
export function globToRegExp(glob: string): RegExp {
  let re = "";
  for (const ch of glob) {
    if (ch === "*") re += ".*";
    else if (ch === "?") re += ".";
    else re += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`, "i");
}

export function makeMatcher(globs: string[]): (path: string) => boolean {
  const res = globs.map(globToRegExp);
  return (path) => {
    const p = (path.split(/[?#]/, 1)[0] ?? "") || "/";
    return res.some((r) => r.test(p));
  };
}
