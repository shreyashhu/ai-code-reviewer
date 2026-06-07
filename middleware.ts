import { NextRequest, NextResponse } from 'next/server';

// ─── In-memory rate limiter (sliding window) ──────────────────────────────────
// Works correctly for single-instance and containerised deployments.
// For multi-instance / edge / serverless: swap the Map for Upstash Redis:
//   npm install @upstash/ratelimit @upstash/redis
//   https://github.com/upstash/ratelimit
//
// Tuning:
//   WINDOW_MS    — rolling window length in milliseconds
//   MAX_REQUESTS — maximum requests allowed per IP within that window
//   UNKNOWN_MAX  — cap for the shared 'unknown' bucket (TRUST_PROXY=false).
//                  Deliberately low: any single connection that can hit the
//                  server without a trusted proxy header already has network
//                  access, so we keep spend exposure bounded.

const WINDOW_MS    = 60_000; // 1 minute
const MAX_REQUESTS = 60;     // requests per identified IP per window
const UNKNOWN_MAX  = 120;    // requests per window for shared unknown bucket (covers local dev)
const MAX_IPS      = 50_000; // hard cap — prevents OOM under bot floods

type WindowEntry = { count: number; resetAt: number };
const ipWindows = new Map<string, WindowEntry>();

// Periodically purge expired entries so the Map doesn't grow unbounded.
// Runs every 5 minutes; harmless if the timer fires while Node is shutting down.
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of ipWindows) {
    if (now > entry.resetAt) ipWindows.delete(ip);
  }
}, 5 * 60_000);

// ─── IP sanitization ──────────────────────────────────────────────────────────
// Strict allowlist: IPv4 with all four octets in 0–255, or colon-hex IPv6.
// A regex that matches digit count without range-checking passes values like
// "256.0.0.1" or "999.999.999.999" which are not valid IPs.  We parse each
// octet numerically so out-of-range values are rejected unconditionally.
// This is format validation (safe), NOT payload sanitization via replace().
function sanitizeIp(raw: string): string {
  // IPv4 — parse each octet and range-check 0-255
  const v4match = raw.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4match) {
    const octets = v4match.slice(1).map(Number);
    if (octets.every(o => o >= 0 && o <= 255)) return raw;
    return 'unknown'; // out-of-range octets → reject entirely
  }
  // IPv6 — colon-hex only, must contain at least one colon, length 2-39
  if (/^[0-9a-f:]{2,39}$/i.test(raw) && raw.includes(':')) return raw;
  return 'unknown';
}

function getClientIp(req: NextRequest): string {
  // Only trust X-Forwarded-For / X-Real-IP when running behind a proxy that
  // strips attacker-injected headers (e.g. Vercel, Cloudflare). Without this
  // guard, any client can spoof X-Forwarded-For to get a fresh rate-limit window.
  //
  // Set TRUST_PROXY=true in .env.local ONLY when deployed behind a proxy you
  // control that guarantees these headers reflect the real client IP.
  const trustProxy = process.env.TRUST_PROXY === 'true';
  if (trustProxy) {
    const forwarded = req.headers.get('x-forwarded-for');
    if (forwarded) return sanitizeIp(forwarded.split(',')[0].trim());
    const real = req.headers.get('x-real-ip');
    if (real) return sanitizeIp(real.trim());
  }
  // Fail-closed: without a trusted proxy all traffic shares one bucket.
  return 'unknown';
}

// ─── CSRF — same-origin enforcement ──────────────────────────────────────────
// Next.js App Router has no built-in CSRF protection. A browser always sends
// an Origin header on cross-origin POST requests, so we compare it against the
// Host header. Server-to-server callers (no browser) send no Origin and are
// passed through. This is not bypassable from a browser context.
function isSameOrigin(req: NextRequest): boolean {
  const origin = req.headers.get('origin');
  if (!origin) return true; // server-to-server — no browser involved
  const host = req.headers.get('host');
  if (!host) return false;
  try {
    return new URL(origin).host === host;
  } catch {
    return false; // malformed Origin — reject
  }
}

// ─── Security response headers ────────────────────────────────────────────────
function addSecurityHeaders(res: NextResponse): NextResponse {
  res.headers.set('X-Content-Type-Options', 'nosniff');
  res.headers.set('X-Frame-Options', 'DENY');
  res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.headers.set(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=()',
  );
  return res;
}

export function middleware(req: NextRequest) {
  // ── CSRF check (must run before rate limiter to avoid burning quota) ────────
  if (!isSameOrigin(req)) {
    return NextResponse.json({ error: 'Forbidden.' }, { status: 403 });
  }

  const ip  = getClientIp(req);
  const now = Date.now();
  const entry = ipWindows.get(ip);

  // When TRUST_PROXY=false all traffic collapses into the 'unknown' bucket.
  // UNKNOWN_MAX is intentionally lower than a naive "200" to bound API spend
  // while still allowing normal concurrent dev/local usage.
  const effectiveMax = ip === 'unknown' ? UNKNOWN_MAX : MAX_REQUESTS;

  if (!entry || now > entry.resetAt) {
    // Evict oldest entry if the Map is at capacity (prevents OOM under bot floods)
    if (ipWindows.size >= MAX_IPS) {
      const firstKey = ipWindows.keys().next().value;
      if (firstKey !== undefined) ipWindows.delete(firstKey);
    }
    // Start a fresh window for this IP
    ipWindows.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return addSecurityHeaders(NextResponse.next());
  }

  if (entry.count >= effectiveMax) {
    const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
    return NextResponse.json(
      { error: `Rate limit exceeded. Try again in ${retryAfter}s.` },
      {
        status: 429,
        headers: {
          'Retry-After': String(retryAfter),
          'X-RateLimit-Limit': String(effectiveMax),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': String(Math.ceil(entry.resetAt / 1000)),
        },
      }
    );
  }

  entry.count++;
  return addSecurityHeaders(NextResponse.next());
}

// Only apply to the review API endpoint
export const config = {
  matcher: '/api/review',
};
