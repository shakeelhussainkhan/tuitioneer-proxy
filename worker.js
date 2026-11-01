/**
 * TuitioneerAI — hardened Anthropic proxy (Phase A1 security fix).
 *
 * What changed vs the old passthrough:
 *  1. MODEL LOCK — the model is forced server-side to claude-haiku-4-5-20251001.
 *     A client asking for Opus/Sonnet (or any other model) is silently
 *     downgraded. The API bill can no longer be spiked by a crafted request.
 *  2. REQUEST WHITELIST — only `system`, `messages` pass through, and
 *     `max_tokens` is capped. `temperature`, `tools`, `top_p`, `stop_sequences`
 *     etc. are stripped so callers can't change model behaviour.
 *  3. RATE LIMITING — KV-backed per-IP sliding window (default 100 req/hour).
 *     Returns 429 with Retry-After when exceeded.
 *  4. APP KEY — requests must carry `x-tuitioneer-key` matching the
 *     TUITIONEER_APP_KEY secret. This is a shared secret: it stops drive-by
 *     abuse and can be rotated instantly. (Phase B upgrades this to Firebase
 *     ID-token verification.)
 *  5. TIGHTENED CORS — browser origins restricted to tuitioneer.org. Native
 *     apps send no Origin header and are allowed through the app-key check.
 *  6. ABUSE GUARDS — max body 1.5 MB, max 50 messages, system prompt capped.
 *  7. QUIET LOGS — message content is never logged; only status + a hashed IP.
 */

const ALLOWED_MODEL = 'claude-haiku-4-5-20251001';
const MAX_TOKENS_CAP = 500;
const MAX_BODY_BYTES = 1.5 * 1024 * 1024;
const MAX_MESSAGES = 50;
const MAX_SYSTEM_CHARS = 8000;

const RATE_LIMIT = 100; // requests
const RATE_WINDOW_S = 3600; // per hour

const ALLOWED_ORIGINS = new Set([
  'https://tuitioneer.org',
  'https://www.tuitioneer.org',
]);

function corsHeaders(origin) {
  const allow = origin && ALLOWED_ORIGINS.has(origin) ? origin : 'https://tuitioneer.org';
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Tuitioneer-Key',
    'Access-Control-Max-Age': '86400',
  };
}

function json(status, obj, origin) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
  });
}

// FNV-1a hash — for privacy-preserving IP logging.
function hashIp(ip) {
  let h = 0x811c9dc5;
  for (let i = 0; i < ip.length; i++) {
    h ^= ip.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16);
}

async function checkRateLimit(kv, ip) {
  const key = `rl:${ip}`;
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - RATE_WINDOW_S;
  let hits = [];
  try {
    const raw = await kv.get(key);
    if (raw) hits = JSON.parse(raw).filter((t) => t > windowStart);
  } catch (e) {
    // KV hiccup: fail open so a KV outage doesn't take the app down.
    return { limited: false };
  }
  if (hits.length >= RATE_LIMIT) {
    const retryAfter = Math.max(1, hits[0] + RATE_WINDOW_S - now);
    return { limited: true, retryAfter };
  }
  hits.push(now);
  try {
    await kv.put(key, JSON.stringify(hits), { expirationTtl: RATE_WINDOW_S });
  } catch (e) { /* fail open */ }
  return { limited: false };
}

function sanitizeBody(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    return { error: 'Invalid JSON body' };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { error: 'Body must be a JSON object' };
  }

  const system = typeof parsed.system === 'string' ? parsed.system : '';
  if (system.length > MAX_SYSTEM_CHARS) {
    return { error: 'System prompt too long' };
  }

  const messages = Array.isArray(parsed.messages) ? parsed.messages : [];
  if (messages.length === 0) return { error: 'messages[] is required' };
  if (messages.length > MAX_MESSAGES) {
    return { error: `Too many messages (max ${MAX_MESSAGES})` };
  }
  // Keep only role + content from each message; drop anything else.
  // Content blocks are passed through (text + image blocks for homework scan).
  const cleanMessages = messages.map((m) => {
    if (!m || typeof m !== 'object') return null;
    const role = m.role === 'assistant' ? 'assistant' : 'user';
    return { role, content: m.content };
  });
  if (cleanMessages.some((m) => m === null || m.content === undefined)) {
    return { error: 'Malformed messages[]' };
  }

  let maxTokens = parseInt(parsed.max_tokens, 10);
  if (!Number.isFinite(maxTokens) || maxTokens <= 0) maxTokens = 256;
  maxTokens = Math.min(maxTokens, MAX_TOKENS_CAP);

  return {
    body: {
      model: ALLOWED_MODEL, // forced — client value ignored
      max_tokens: maxTokens,
      system,
      messages: cleanMessages,
    },
  };
}

// ── PHASE B1: MODERATION ──
// Self-contained moderation pass on the last user message. Returns null
// when clean, or one of: 'self_harm' | 'abuse_disclosure' |
// 'sexual_content' | 'pii_share'. Lowercase substring / regex matching
// only — deliberately modest, precise lists to avoid false positives
// on normal homework text. Message content is never logged.
const MODERATION_CANNED = {
  // R1 crisis protocol: named, reachable help. Keep in sync with the
  // app's ModerationService.safeResponseFor.
  self_harm:
    "I'm so glad you told me. What you're feeling matters, and you deserve support from people who know how to help. Please talk to a trusted adult or parent right away. You can also call or text 988 any time — free, 24/7 in the US — or find a helpline in your country at findahelpline.org. You don't have to go through this alone. 💜",
  abuse_disclosure:
    "Thank you for trusting me with that — telling someone is a brave and important step. Please tell a trusted adult, like a parent, teacher, or school counsellor, as soon as you can. In the US, Childhelp answers at 1-800-422-4453; in the UK, Childline is 0800 1111 — both free and private. 💜",
  sexual_content:
    "That's not something I can help with — let's keep our chat about learning! What subject would you like to explore today? 🦉",
  pii_share:
    "Thanks for trusting me! You don't need to share private details like that with me — let's keep them just for you and your family. Now, what shall we learn about? 🦉",
};

const SELF_HARM_TERMS = [
  'kill myself',
  'hurt myself',
  'self harm',
  'self-harm',
  'suicide',
  'end my life',
  "don't want to live",
  'dont want to live',
  'cut myself',
  'starve myself',
  'hang myself',
  'suicidal',
  'want to die',
  'wants to die',
  'hurt himself',
  'hurt herself',
  'harm himself',
  'harm herself',
  'kill himself',
  'kill herself',
  'quiero matarme',
  'matarme',
  'quiero morir',
  'no quiero vivir',
  'me quiero morir',
  'marna hai',
  'mujhe marna hai',
  'jeena nahi chahta',
  'jeena nahi chahti',
  'main marna chahta',
  'main marna chahti',
];

const ABUSE_DISCLOSURE_TERMS = [
  'hits me',
  'hitting me',
  'touches me',
  'touched me',
  'hurts me at home',
  'scared of my dad',
  'scared of my mom',
  'scared of my stepdad',
  'scared of my stepmom',
  'beats me',
  'molests',
  'secret touching',
  'hit their kid',
  'hits their kid',
  'hitting their kid',
  'hits their child',
  'me pega',
  'me golpea',
  'marta hai',
  'marti hai',
  'papa marta',
  'baba marta',
];

// Word boundaries so "sex" does not fire on "sextant" / "Essex", etc.
const SEXUAL_CONTENT_RE = /\b(?:porn|naked|nude|sex|penis|vagina|boobs)\b/;

const PII_PATTERNS = [
  // Email address.
  /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/,
  // Phone-number-like: 7+ digits, allowing spaces/dots/dashes/parens
  // and an optional leading + / country code.
  /(?:\+?\d[\s().-]*){7,}\d/,
  /\bmy address is\b/,
  /\bi live at\b/,
  /\bmy school is called\b/,
  /\bmy full name is\b/,
];

// Pen-test hardening (2026-10-31, stream A): the plain substring match
// was defeated by one leet digit ("k1ll mys3lf"), one extra space
// ("kill  myself"), punctuation splits, and any non-English phrasing.
// Match now happens on a normalized form (lowercase, leet folded,
// punctuation -> space, whitespace collapsed) AND a squeezed
// letters-only form, with the term lists normalized the same way.
const LEET_MAP = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's' };

function normalizeForModeration(text) {
  return text
    .toLowerCase()
    .replace(/[013457@$]/g, (c) => LEET_MAP[c])
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function termHit(normalized, squeezed, term) {
  const nt = normalizeForModeration(term);
  return (
    nt.length > 0 &&
    (normalized.includes(nt) || squeezed.includes(nt.replace(/ /g, '')))
  );
}

// Spelled-out email ("samir dot test at example dot com") — matched on
// the normalized token stream.
const OBFUSCATED_EMAIL_RE =
  /\b\w+(?: (?:at|dot) \w+)+ dot (?:com|net|org|io)\b/;

function moderate(text) {
  if (typeof text !== 'string' || text.length === 0) return null;
  const raw = text.toLowerCase();
  const n = normalizeForModeration(text);
  const sq = n.replace(/ /g, '');
  for (const term of SELF_HARM_TERMS) {
    if (termHit(n, sq, term)) return 'self_harm';
  }
  for (const term of ABUSE_DISCLOSURE_TERMS) {
    if (termHit(n, sq, term)) return 'abuse_disclosure';
  }
  if (SEXUAL_CONTENT_RE.test(n)) return 'sexual_content';
  for (const re of PII_PATTERNS) {
    if (re.test(raw) || re.test(n)) return 'pii_share';
  }
  if (OBFUSCATED_EMAIL_RE.test(n)) return 'pii_share';
  return null;
}

// Texts of ALL user messages (pen-test fix: screening only the last
// turn let a flagged disclosure wash out by changing the subject).
// Content may be a plain string, or an array of blocks — concatenate
// the `text` of blocks with type 'text' (image blocks carry no text).
function allUserTexts(messages) {
  const texts = [];
  for (const m of messages) {
    if (!m || m.role !== 'user') continue;
    if (typeof m.content === 'string') {
      texts.push(m.content);
    } else if (Array.isArray(m.content)) {
      texts.push(
        m.content
          .filter((b) => b && b.type === 'text' && typeof b.text === 'string')
          .map((b) => b.text)
          .join(''),
      );
    }
  }
  return texts;
}
// ── END PHASE B1: MODERATION ──

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(origin) });
    }
    if (request.method !== 'POST') {
      return json(405, { error: 'Method not allowed' }, origin);
    }

    // 1. App key check — the compat window opened 2026-10-16 for the
    // keyless v1.0.3 build CLOSED 2026-10-21, when the keyed v1.0.4 went
    // live on the App Store: a missing OR wrong key is rejected (401).
    const appKey = request.headers.get('X-Tuitioneer-Key');
    if (!appKey || appKey !== env.TUITIONEER_APP_KEY) {
      return json(401, { error: 'Unauthorized' }, origin);
    }

    // 2. Rate limit (fail open if KV is unavailable)
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (env.TUITIONEER_RL) {
      const rl = await checkRateLimit(env.TUITIONEER_RL, ip);
      if (rl.limited) {
        console.log(`rate-limited ip=${hashIp(ip)}`);
        const res = json(429, { error: 'Too many requests, slow down.' }, origin);
        res.headers.set('Retry-After', String(rl.retryAfter));
        return res;
      }
    }

    // 3. Read + sanitize body
    const raw = await request.text();
    if (raw.length > MAX_BODY_BYTES) {
      return json(413, { error: 'Request too large' }, origin);
    }
    const { body, error } = sanitizeBody(raw);
    if (error) return json(400, { error }, origin);

    // 3b. PHASE B1: moderation on EVERY user turn in the history. If
    // flagged, do NOT call Anthropic — return a canned Anthropic-shaped
    // response so the app's parser works unchanged. Log only category
    // + hashed IP.
    let category = null;
    for (const t of allUserTexts(body.messages)) {
      category = moderate(t);
      if (category) break;
    }
    if (category) {
      console.log(`moderated category=${category} ip=${hashIp(ip)}`);
      return json(
        200,
        {
          id: 'moderation-intercept',
          type: 'message',
          role: 'assistant',
          model: ALLOWED_MODEL,
          content: [{ type: 'text', text: MODERATION_CANNED[category] }],
          stop_reason: 'end_turn',
          usage: { input_tokens: 0, output_tokens: 0 },
        },
        origin,
      );
    }

    // 4. Forward to Anthropic with the server-side key
    if (!env.ANTHROPIC_API_KEY) {
      return json(500, { error: 'API key not configured' }, origin);
    }
    let upstream;
    try {
      upstream = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json',
        },
        body: JSON.stringify(body),
      });
    } catch (e) {
      console.log(`upstream error ip=${hashIp(ip)}`);
      return json(502, { error: 'Upstream unavailable, try again.' }, origin);
    }

    const data = await upstream.text();
    console.log(`ok=${upstream.ok} status=${upstream.status} ip=${hashIp(ip)}`);
    if (!upstream.ok) {
      // Pen-test fix (F-A2): never relay Anthropic's raw error body —
      // it fingerprints the provider and its validation internals.
      // The upstream status stays in the server log above only.
      if (upstream.status === 429) {
        return json(429, { error: 'Upstream busy, try again.' }, origin);
      }
      if (upstream.status >= 500) {
        return json(502, { error: 'Upstream error, try again.' }, origin);
      }
      return json(400, { error: 'Invalid request' }, origin);
    }
    return new Response(data, {
      status: 200,
      headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
    });
  },
};
