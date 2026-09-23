// Cloudflare Worker entry for bandrproduction.com (Workers Static Assets).
//
// Static files are served directly by the assets binding; this Worker is only
// invoked for requests that don't match a static asset — i.e. /api/quote.
//
// Required Cloudflare env var (Workers > Settings > Variables and Secrets):
//   RESEND_API_KEY  (secret)  — your Resend API key
// Optional (env vars override these defaults):
//   QUOTE_TO      — where leads are delivered (default sales@bandrproduction.com)
//   QUOTE_FROM    — verified Resend sender (default forms@bandrproduction.com)
//   QUOTE_CC      — extra CC recipient(s), comma-separated (default hello@aaron.chat)
//   LEAD_WEBHOOK  — optional URL to POST every lead to (Airtable/Zapier/Make/CRM)
//   DIGEST_TO     — where the weekly Monday digest goes (default hello@aaron.chat)
//
// Optional Cloudflare bindings (dashboard → Settings → Variables/Bindings):
//   LEADS_KV      — KV Namespace binding. When present, every submission is
//                   logged as key `lead:<epoch-ms>` for the weekly digest.
//                   Enable: Workers > KV > Create namespace, then bind to this
//                   Worker as `LEADS_KV`. No code change needed.
//
// Cron: Monday 13:00 UTC (~08:00 CT) → sends the past-7-days lead digest to
// DIGEST_TO. Configured in wrangler.jsonc under `triggers.crons`.
//
// NOTE: the QUOTE_FROM domain must be verified in Resend before delivery
// works. For a quick test before verifying bandrproduction.com, set
// QUOTE_FROM="B&R Productions <onboarding@resend.dev>" (Resend's shared
// sender only delivers to the Resend account owner's own address).

const PHONE = "936-291-7827";

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function clean(v, max) {
  return (v == null ? "" : String(v)).trim().slice(0, max);
}

// File upload constraints — Resend allows ~40MB per email; keep a safety margin.
const MAX_FILE_BYTES = 25 * 1024 * 1024;      // 25 MB per file
const MAX_TOTAL_BYTES = 25 * 1024 * 1024;     // 25 MB combined (Resend cap ~40MB, leave headroom)
const MAX_FILES = 5;
const ALLOWED_EXT = new Set([
  "pdf", "dwg", "dxf", "step", "stp", "iges", "igs", "stl",
  "sldprt", "sldasm", "sldrt", "ipt", "iam", "prt", "x_t", "x_b",
  "zip", "png", "jpg", "jpeg", "gif", "webp", "tif", "tiff",
  "txt", "csv", "xls", "xlsx", "doc", "docx"
]);

function _extOf(name) {
  const s = String(name || "").toLowerCase();
  const i = s.lastIndexOf(".");
  return i > 0 ? s.slice(i + 1) : "";
}

function _bufToB64(buf) {
  // Convert ArrayBuffer to base64 for Resend's attachment.content field.
  const bytes = new Uint8Array(buf);
  let bin = "";
  const CHUNK = 32768;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

async function handleQuote(request, env, ctx) {
  try {
    const ct = request.headers.get("content-type") || "";
    let d = {};
    const attachments = [];
    let totalBytes = 0;
    let uploadError = null;

    if (ct.includes("application/json")) {
      d = await request.json();
    } else {
      const form = await request.formData();
      for (const [k, v] of form.entries()) {
        if (v instanceof File) {
          if (!v.name || v.size === 0) continue;
          if (attachments.length >= MAX_FILES) {
            uploadError = `Maximum ${MAX_FILES} files per submission.`;
            continue;
          }
          const ext = _extOf(v.name);
          if (!ALLOWED_EXT.has(ext)) {
            uploadError = `File type not allowed: .${ext || "(none)"}`;
            continue;
          }
          if (v.size > MAX_FILE_BYTES) {
            uploadError = `File too large: ${v.name} (${Math.round(v.size / 1024 / 1024)}MB, limit 25MB per file)`;
            continue;
          }
          totalBytes += v.size;
          if (totalBytes > MAX_TOTAL_BYTES) {
            uploadError = `Total attachment size exceeds 25MB.`;
            continue;
          }
          const buf = await v.arrayBuffer();
          attachments.push({
            filename: v.name.slice(0, 200),
            content: _bufToB64(buf),
          });
        } else {
          d[k] = v;
        }
      }
    }

    // ---- Anti-spam layer 1: honeypot ----
    // Bots blindly fill every field. Real forms leave _gotcha empty.
    // Silent-accept so bots think they succeeded and don't retry.
    if (clean(d._gotcha, 100)) return json({ ok: true });

    // ---- Anti-spam layer 2: time-gate ----
    // The client stamps _form_loaded_ms on page load. Any submit within
    // 2s is scripted, not human. Silent-accept.
    const loadedMs = parseInt(String(d._form_loaded_ms || "0"), 10);
    if (loadedMs > 0 && (Date.now() - loadedMs) < 2000) return json({ ok: true });

    // ---- Anti-spam layer 3: Origin/Referer must be bandrproduction.com ----
    // Direct-to-API spam usually skips setting Origin or sends bogus values.
    // Only enforce when the header is present at all (some legit clients strip).
    const originOrRef = request.headers.get("origin") || request.headers.get("referer") || "";
    if (originOrRef && !/(^|\.)bandrproduction\.com/i.test(originOrRef)) {
      return json({ ok: true });
    }

    // ---- Anti-spam layer 4: Cloudflare Turnstile ----
    // Only enforced when TURNSTILE_SECRET is set — safe to deploy this code
    // before the widget is provisioned. When enforced, missing/invalid token
    // returns a visible error so a legit user can retry the challenge.
    if (env.TURNSTILE_SECRET) {
      const token = clean(d["cf-turnstile-response"], 4096);
      const ip = request.headers.get("cf-connecting-ip") || "";
      let ts;
      try {
        const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ secret: env.TURNSTILE_SECRET, response: token, remoteip: ip }),
        });
        ts = await r.json();
      } catch (e) {
        console.log("turnstile verify error", e && e.message);
        ts = { success: false };
      }
      if (!ts.success) {
        return json({ ok: false, error: "Please complete the security check and try again." }, 403);
      }
    }

    if (uploadError) {
      return json({ ok: false, error: uploadError }, 400);
    }

    const name = clean(d.name, 200);
    const email = clean(d.email, 200);
    const phone = clean(d.phone, 50);
    const company = clean(d.company, 200);
    const message = clean(d.message, 5000);
    const source = clean(d._source, 100) || "website";

    if (!name || !email || !message) {
      return json({ ok: false, error: "Please fill in your name, email, and project details." }, 400);
    }
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return json({ ok: false, error: "Please enter a valid email address." }, 400);
    }

    // ---- Anti-spam layer 5: content heuristics (silent-drop) ----
    // Every check below is a well-established spam signature. Silent-accept
    // avoids giving bots feedback that they were filtered.
    const msgLC = message.toLowerCase();
    const emailLC = email.toLowerCase();

    // (a) URL count in message — real quote requests rarely include 3+ links.
    const urlCount = (message.match(/https?:\/\/[^\s]+|www\.[^\s]+/gi) || []).length;
    if (urlCount > 2) return json({ ok: true });

    // (b) Cyrillic + CJK dominance — near-zero legit signal for a TX shop.
    const cyrillic = (message.match(/[Ѐ-ӿ]/g) || []).length;
    const cjk = (message.match(/[一-鿿]/g) || []).length;
    if (cyrillic + cjk > 10) return json({ ok: true });

    // (c) Keyword blocklist — the vast majority of B2B form spam.
    const SPAM_KEYWORDS = [
      "seo services", "guaranteed rankings", "backlinks package", "guest post",
      "increase your ranking", "top ranking", "search engine optimization",
      "buy real followers", "casino", "online casino", "crypto trading",
      "cryptocurrency", "bitcoin investment", "forex trading", "cbd oil",
      "vashikaran", "weight loss pills", "adult webcam", "dating site",
      "essay writing service", "porn", "loan offer", "make money fast",
    ];
    if (SPAM_KEYWORDS.some((k) => msgLC.includes(k))) return json({ ok: true });

    // (d) Disposable / burner email domains.
    const DISPOSABLE = [
      "mailinator", "guerrillamail", "tempmail", "10minutemail", "throwaway",
      "yopmail", "trashmail", "sharklasers", "getnada", "maildrop",
      "dispostable", "fakeinbox", "tempinbox", "tempr.email", "disposable",
      "mintemail", "mailnesia", "spam4.me", "mailsac",
    ];
    if (DISPOSABLE.some((dom) => emailLC.includes(dom))) return json({ ok: true });

    const attachmentSummary = attachments.length
      ? `Attachments (${attachments.length}): ${attachments.map((a) => a.filename).join(", ")}`
      : "No attachments";

    const lines = [
      `New submission from the ${source} form on bandrproduction.com`,
      "",
      `Name: ${name}`,
      `Email: ${email}`,
      phone ? `Phone: ${phone}` : null,
      company ? `Company: ${company}` : null,
      "",
      "Project details:",
      message,
      "",
      attachmentSummary,
    ].filter((l) => l !== null);

    if (!env.RESEND_API_KEY) {
      return json({ ok: false, error: "Email is not configured yet." }, 500);
    }

    // CC recipients — QUOTE_CC env var (comma-separated) overrides the default.
    const ccRaw = env.QUOTE_CC != null ? String(env.QUOTE_CC) : "hello@aaron.chat";
    const cc = clean(ccRaw, 500)
      .split(",")
      .map((a) => a.trim())
      .filter(Boolean);

    const payload = {
      from: env.QUOTE_FROM || "B&R Productions Website <forms@bandrproduction.com>",
      to: [env.QUOTE_TO || "sales@bandrproduction.com"],
      reply_to: email,
      subject: `New ${source} request: ${name}${company ? " (" + company + ")" : ""}${attachments.length ? " [" + attachments.length + " attached]" : ""}`,
      text: lines.join("\n"),
    };
    if (cc.length) payload.cc = cc;
    if (attachments.length) payload.attachments = attachments;

    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      console.log("Resend error", res.status, detail);
      return json({ ok: false, error: `We couldn't send your message. Please call ${PHONE}.` }, 502);
    }

    // Fire-and-forget: log to KV + POST to optional external webhook.
    // Both are opportunistic — a KV or webhook failure must not surface to the
    // visitor. ctx.waitUntil lets the Worker return to the browser immediately.
    const attribution = {
      referrer:       clean(d._referrer, 500) || null,
      referrer_host:  clean(d._referrer_host, 200) || null,
      landing_url:    clean(d._landing_url, 500) || null,
      utm_source:     clean(d._utm_source, 100) || null,
      utm_medium:     clean(d._utm_medium, 100) || null,
      utm_campaign:   clean(d._utm_campaign, 200) || null,
      utm_term:       clean(d._utm_term, 200) || null,
      utm_content:    clean(d._utm_content, 200) || null,
      gclid:          clean(d._gclid, 200) || null,
      session_first_seen: clean(d._session_first_seen, 40) || null,
      // Server-side fallback if client-side capture missed
      submit_referer: request.headers.get("referer") || null,
      country:        request.cf?.country || null,
      user_agent:     (request.headers.get("user-agent") || "").slice(0, 300),
    };
    const lead = { ts: Date.now(), name, email, phone, company, message, source, attribution };
    if (ctx && env.LEADS_KV) {
      const key = `lead:${lead.ts}:${Math.floor(Math.random() * 1e6).toString(36)}`;
      ctx.waitUntil(
        env.LEADS_KV.put(key, JSON.stringify(lead), { expirationTtl: 60 * 60 * 24 * 400 }).catch((e) =>
          console.log("KV put failed", e && e.message)
        )
      );
    }
    if (ctx && env.LEAD_WEBHOOK) {
      ctx.waitUntil(
        fetch(env.LEAD_WEBHOOK, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(lead),
        }).catch((e) => console.log("webhook failed", e && e.message))
      );
    }

    return json({ ok: true });
  } catch (err) {
    console.log("quote worker error", err && err.message);
    return json({ ok: false, error: `Something went wrong. Please call ${PHONE}.` }, 500);
  }
}

// ---------------------------------------------------------------------------
// Monday digest — pulls the last 7 days of leads from KV and emails a summary
// to DIGEST_TO. Runs on the cron schedule defined in wrangler.jsonc.
// If LEADS_KV isn't bound yet, sends a "no data yet" note so we notice.
// ---------------------------------------------------------------------------
async function sendWeeklyDigest(env) {
  if (!env.RESEND_API_KEY) {
    console.log("digest skipped: no RESEND_API_KEY");
    return;
  }
  const to = env.DIGEST_TO || "hello@aaron.chat";
  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const leads = [];
  let kvWarning = "";

  if (env.LEADS_KV) {
    let cursor = undefined;
    do {
      const list = await env.LEADS_KV.list({ prefix: "lead:", cursor, limit: 1000 });
      for (const k of list.keys) {
        const ts = parseInt(k.name.split(":")[1] || "0", 10);
        if (ts < cutoff) continue;
        const raw = await env.LEADS_KV.get(k.name);
        if (raw) {
          try { leads.push(JSON.parse(raw)); } catch (_) {}
        }
      }
      cursor = list.list_complete ? undefined : list.cursor;
    } while (cursor);
    leads.sort((a, b) => a.ts - b.ts);
  } else {
    kvWarning = "\nNote: LEADS_KV isn't bound to this Worker yet — bind it in Cloudflare Dashboard (Workers > bandrproduction > Settings > Bindings > KV Namespace) as `LEADS_KV` to start capturing weekly lead history.";
  }

  const lines = [
    `B&R Productions — weekly lead digest (${new Date().toISOString().slice(0, 10)})`,
    `Window: last 7 days.`,
    "",
    `Leads captured: ${leads.length}`,
  ];
  if (leads.length) {
    lines.push("");
    for (const l of leads) {
      const when = new Date(l.ts).toISOString().replace("T", " ").slice(0, 16);
      lines.push(
        `- [${when} UTC] ${l.name || "(no name)"} <${l.email || "(no email)"}>`
        + (l.company ? ` @ ${l.company}` : "")
      );
      if (l.message) {
        lines.push(`    ${String(l.message).replace(/\s+/g, " ").slice(0, 220)}`);
      }
      const a = l.attribution || {};
      const acqBits = [];
      if (a.utm_source)     acqBits.push(`utm=${a.utm_source}${a.utm_medium ? "/" + a.utm_medium : ""}${a.utm_campaign ? " · " + a.utm_campaign : ""}`);
      if (a.gclid)          acqBits.push("google-ads");
      if (a.referrer_host)  acqBits.push(`ref=${a.referrer_host}`);
      if (a.landing_url)    acqBits.push(`landed=${a.landing_url}`);
      if (a.country)        acqBits.push(`geo=${a.country}`);
      if (acqBits.length)   lines.push(`    ↳ ${acqBits.join("  ·  ")}`);
    }
  } else {
    lines.push("");
    lines.push("No new quote-form submissions this week.");
  }
  if (kvWarning) lines.push(kvWarning);

  // ---- Citation progress ----
  if (env.LEADS_KV && typeof DIRECTORIES !== "undefined") {
    const cit = { submitted: [], verified: [], failed: [], pending: [] };
    for (const slug of Object.keys(DIRECTORIES)) {
      const raw = await env.LEADS_KV.get(`citation:${slug}`);
      if (!raw) { cit.pending.push(slug); continue; }
      try {
        const r = JSON.parse(raw);
        if (r.status === "verified" || r.status === "live") cit.verified.push(slug);
        else if (r.status === "submitted") cit.submitted.push(slug);
        else if (r.status === "failed" || r.status === "skipped_captcha") cit.failed.push(slug);
        else cit.pending.push(slug);
      } catch { cit.pending.push(slug); }
    }
    lines.push("");
    lines.push("=== Citation submissions ===");
    lines.push(`  Verified: ${cit.verified.length}  ·  Submitted (awaiting verify): ${cit.submitted.length}  ·  Failed/skipped: ${cit.failed.length}  ·  Pending: ${cit.pending.length}`);
    if (cit.failed.length) {
      lines.push(`  Needs attention: ${cit.failed.join(", ")}`);
    }
    if (cit.pending.length) {
      lines.push(`  Not yet submitted: ${cit.pending.join(", ")}`);
    }
  }

  // ---- Rank snapshot deltas ----
  try {
    const rankLines = await rankDigestLines(env);
    for (const l of rankLines) lines.push(l);
  } catch (e) {
    console.log("digest rank section err", e && e.message);
  }

  lines.push("");
  lines.push("Full site: https://bandrproduction.com");
  lines.push("Quote form: https://bandrproduction.com/about-us/get-a-quote/");
  lines.push("Dashboard: https://bandrproduction.com/dashboard/");

  await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: env.QUOTE_FROM || "B&R Productions Website <forms@bandrproduction.com>",
      to: [to],
      subject: `B&R weekly lead digest — ${leads.length} lead${leads.length === 1 ? "" : "s"}`,
      text: lines.join("\n"),
    }),
  }).catch((e) => console.log("digest send failed", e && e.message));
}

// ---------------------------------------------------------------------------
// Rank snapshot — weekly DataForSEO pull for the tracked-keyword universe.
// Runs on the same Monday cron as sendWeeklyDigest. Requires env secrets:
//   DATAFORSEO_LOGIN, DATAFORSEO_PASSWORD  (Cloudflare Dashboard → Secrets)
// Writes to LEADS_KV under `rank_snapshot:latest` + `rank_snapshot:YYYY-MM-DD`.
// Same grouping/keywords as local rank_tracker.py — keep the two in sync when
// updating.
// ---------------------------------------------------------------------------

const RANK_KEYWORD_GROUPS = {
  "head-terms": [
    "cnc machining services", "cnc machine shop", "precision machining",
    "precision cnc machining", "custom cnc machining", "cnc turning services",
    "cnc milling services", "5 axis machining", "swiss machining",
    "prototype machining", "custom parts manufacturer", "contract manufacturing texas",
  ],
  "materials-high-cpc": [
    "inconel machining", "inconel 718 machining", "monel machining",
    "hastelloy machining", "super duplex machining", "17-4 ph machining",
    "titanium machining services", "nitronic 50 machining",
  ],
  "industries": [
    "oil and gas machine shop", "oilfield machine shop", "aerospace machine shop",
    "defense machine shop", "wellhead components", "downhole tool manufacturer",
    "deep hole drilling services", "gun drilling services",
  ],
  "local-metros": [
    "machine shop houston tx", "houston machine shop", "cnc machining houston",
    "machine shop in san antonio", "san antonio machine shops", "cnc machining san antonio",
    "cnc machine shop dallas", "cnc machining dallas", "austin cnc machining",
    "machine shop conroe tx", "machine shops in conroe", "humble machine shop",
    "machine shops in humble tx", "machine shops in tomball tx", "machine shop tomball tx",
    "machine shops in spring tx", "machine shop fort worth", "machine shop sugar land",
    "machine shop pearland tx",
  ],
  "branded": [
    "b&r productions", "b&r machine shop", "b and r machine shop", "b&r machining",
  ],
};

async function fetchAndSnapshotRanks(env) {
  if (!env.DATAFORSEO_LOGIN || !env.DATAFORSEO_PASSWORD) {
    console.log("rank snapshot skipped: DATAFORSEO_LOGIN/PASSWORD not set");
    return null;
  }
  if (!env.LEADS_KV) {
    console.log("rank snapshot skipped: LEADS_KV not bound");
    return null;
  }
  const auth = "Basic " + btoa(`${env.DATAFORSEO_LOGIN}:${env.DATAFORSEO_PASSWORD}`);
  let items = [];
  try {
    const r = await fetch("https://api.dataforseo.com/v3/dataforseo_labs/google/ranked_keywords/live", {
      method: "POST",
      headers: { Authorization: auth, "Content-Type": "application/json" },
      body: JSON.stringify([{
        target: "bandrproduction.com",
        location_code: 2840,
        language_code: "en",
        limit: 700,
        filters: [["ranked_serp_element.serp_item.rank_group", "<=", 100]],
      }]),
    });
    const data = await r.json();
    items = data?.tasks?.[0]?.result?.[0]?.items || [];
  } catch (e) {
    console.log("rank snapshot fetch failed", e && e.message);
    return null;
  }

  const byKw = {};
  for (const it of items) {
    const kw = String(it?.keyword_data?.keyword || "").toLowerCase();
    if (!kw) continue;
    const se = it?.ranked_serp_element?.serp_item || {};
    const ki = it?.keyword_data?.keyword_info || {};
    byKw[kw] = {
      rank: se.rank_group,
      url: se.url,
      volume: ki.search_volume || 0,
      cpc: Math.round((ki.cpc || 0) * 100) / 100,
    };
  }

  const snapshot = {
    captured_at: new Date().toISOString(),
    target: "bandrproduction.com",
    groups: {},
    summary: {},
  };
  let allTracked = 0, ranking = 0, top10 = 0, pos1120 = 0, addressableVol = 0, capturedVol = 0;
  for (const [group, kws] of Object.entries(RANK_KEYWORD_GROUPS)) {
    const rows = kws.map((kw) => {
      const d = byKw[kw.toLowerCase()] || null;
      const row = {
        keyword: kw,
        rank: d?.rank ?? null,
        url: d?.url ?? null,
        volume: d?.volume || 0,
        cpc: d?.cpc || 0,
      };
      allTracked++;
      addressableVol += row.volume;
      if (row.rank != null) {
        ranking++;
        if (row.rank <= 10) { top10++; capturedVol += row.volume; }
        else if (row.rank <= 20) pos1120++;
      }
      return row;
    });
    snapshot.groups[group] = rows;
  }
  snapshot.summary = {
    total_tracked: allTracked,
    ranking,
    top_10: top10,
    pos_11_20: pos1120,
    unranked: allTracked - ranking,
    total_addressable_volume: addressableVol,
    captured_volume: capturedVol,
  };

  const date = new Date().toISOString().slice(0, 10);
  const prevRaw = await env.LEADS_KV.get("rank_snapshot:latest");
  if (prevRaw) {
    // Preserve the prior "latest" under a dated key BEFORE overwriting.
    try {
      const prev = JSON.parse(prevRaw);
      const prevDate = (prev.captured_at || "").slice(0, 10) || "prev";
      await env.LEADS_KV.put(`rank_snapshot:${prevDate}`, prevRaw, {
        expirationTtl: 60 * 60 * 24 * 365 * 2,   // 2 years
      });
    } catch { /* ignore */ }
  }
  await env.LEADS_KV.put("rank_snapshot:latest", JSON.stringify(snapshot));
  await env.LEADS_KV.put(`rank_snapshot:${date}`, JSON.stringify(snapshot), {
    expirationTtl: 60 * 60 * 24 * 365 * 2,
  });
  console.log(`rank snapshot: ${ranking}/${allTracked} tracked · top10=${top10} · pos11-20=${pos1120} · vol=${capturedVol}/${addressableVol}`);
  return snapshot;
}

// Compute rank-delta text vs the previous snapshot for the weekly digest.
async function rankDigestLines(env) {
  if (!env.LEADS_KV) return [];
  const latestRaw = await env.LEADS_KV.get("rank_snapshot:latest");
  if (!latestRaw) return [];
  const latest = JSON.parse(latestRaw);
  const lines = ["", "=== Rankings (DataForSEO) ==="];
  const s = latest.summary || {};
  lines.push(`  Ranking: ${s.ranking || 0}/${s.total_tracked || 0}  ·  top-10: ${s.top_10 || 0}  ·  pos 11-20: ${s.pos_11_20 || 0}`);
  lines.push(`  Volume captured: ${s.captured_volume || 0} / ${s.total_addressable_volume || 0} monthly searches`);

  // Try to diff against the previous dated snapshot
  const list = await env.LEADS_KV.list({ prefix: "rank_snapshot:", limit: 30 });
  const dated = list.keys
    .map(k => k.name)
    .filter(n => n !== "rank_snapshot:latest")
    .sort()
    .reverse();
  const prevKey = dated.find(k => k.split(":")[1] !== (latest.captured_at || "").slice(0, 10));
  if (!prevKey) return lines;

  const prevRaw = await env.LEADS_KV.get(prevKey);
  if (!prevRaw) return lines;
  let prev;
  try { prev = JSON.parse(prevRaw); } catch { return lines; }
  const prevRanks = {};
  for (const rows of Object.values(prev.groups || {})) {
    for (const r of rows) prevRanks[r.keyword] = r.rank;
  }
  const ups = [], downs = [];
  for (const [group, rows] of Object.entries(latest.groups || {})) {
    for (const r of rows) {
      const was = prevRanks[r.keyword];
      const now = r.rank;
      if (was === now) continue;
      const rec = { kw: r.keyword, group, was, now, vol: r.volume };
      if (was == null && now != null) ups.push({ ...rec, dir: "NEW" });
      else if (was != null && now == null) downs.push({ ...rec, dir: "LOST" });
      else if (now < was) ups.push({ ...rec, dir: "UP" });
      else downs.push({ ...rec, dir: "DOWN" });
    }
  }
  ups.sort((a, b) => (b.vol || 0) - (a.vol || 0));
  downs.sort((a, b) => (b.vol || 0) - (a.vol || 0));
  lines.push(`  vs ${prevKey.split(":")[1]}: ${ups.length} up · ${downs.length} down`);
  for (const u of ups.slice(0, 6)) {
    lines.push(`    ↑ ${u.kw} — ${u.was || "—"} → ${u.now}  (vol ${u.vol})`);
  }
  for (const d of downs.slice(0, 4)) {
    lines.push(`    ↓ ${d.kw} — ${d.was} → ${d.now || "—"}  (vol ${d.vol})`);
  }
  return lines;
}

// ---------------------------------------------------------------------------
// Telemetry — AI bot + AI-referrer detection for AEO tracking.
// Runs on every request; logs aggregate daily counts to LEADS_KV. Zero PII,
// no IPs stored — only per-day, per-bot counters.
// ---------------------------------------------------------------------------

const AI_BOTS = [
  ["GPTBot", "openai-gptbot"],
  ["OAI-SearchBot", "openai-searchbot"],
  ["ChatGPT-User", "openai-chatgpt-user"],
  ["ClaudeBot", "anthropic-claudebot"],
  ["anthropic-ai", "anthropic-ai"],
  ["Claude-Web", "anthropic-claude-web"],
  ["PerplexityBot", "perplexity-bot"],
  ["Perplexity-User", "perplexity-user"],
  ["Google-Extended", "google-extended"],
  ["Googlebot", "google-search"],
  ["Bingbot", "bing-search"],
  ["bingbot", "bing-search"],
  ["CCBot", "common-crawl"],
  ["Bytespider", "bytedance"],
  ["FacebookBot", "meta-ai"],
  ["meta-externalagent", "meta-ai"],
  ["DuckAssistBot", "duckduckgo"],
  ["MistralAI-User", "mistral"],
  ["cohere-ai", "cohere"],
  ["Applebot-Extended", "apple-ai"],
  ["YandexBot", "yandex"],
  ["Amazonbot", "amazon"],
];

const AI_REFERRERS = [
  "chat.openai.com",
  "chatgpt.com",
  "perplexity.ai",
  "claude.ai",
  "gemini.google.com",
  "bard.google.com",
  "copilot.microsoft.com",
  "you.com",
  "phind.com",
  "duckduckgo.com",
];

function detectAiBot(ua) {
  if (!ua) return null;
  for (const [pat, name] of AI_BOTS) if (ua.indexOf(pat) !== -1) return name;
  return null;
}

function detectAiReferrer(ref) {
  if (!ref) return null;
  try {
    const h = new URL(ref).hostname;
    for (const d of AI_REFERRERS) if (h === d || h.endsWith("." + d)) return d;
  } catch (_) {}
  return null;
}

function isContentPath(p) {
  // count page views for HTML docs; skip static/API/admin routes
  if (p.startsWith("/api/")) return false;
  if (p.startsWith("/dashboard")) return false;
  if (p.startsWith("/_next/")) return false;
  if (p.startsWith("/_external/")) return false;
  if (p.startsWith("/cdn-cgi/")) return false;
  if (/\.(png|jpe?g|gif|svg|webp|ico|css|js|woff2?|txt|xml|json|map)$/i.test(p)) return false;
  return true;
}

async function bumpCounter(env, key) {
  const cur = await env.LEADS_KV.get(key);
  const n = cur ? (parseInt(cur, 10) || 0) : 0;
  return env.LEADS_KV.put(key, String(n + 1), { expirationTtl: 60 * 60 * 24 * 120 });
}

async function logTelemetry(request, env, url) {
  if (!env.LEADS_KV) return;
  const ua = request.headers.get("user-agent") || "";
  const ref = request.headers.get("referer") || "";
  const p = url.pathname;
  const bot = detectAiBot(ua);
  const aiRef = detectAiReferrer(ref);
  const isPage = isContentPath(p);
  if (!bot && !aiRef && !isPage) return;
  const day = new Date().toISOString().slice(0, 10);
  const puts = [];
  if (bot) {
    puts.push(bumpCounter(env, `tel:bot:${bot}:${day}`));
    puts.push(env.LEADS_KV.put(`tel:bot:${bot}:last`,
      JSON.stringify({ ts: Date.now(), path: p.slice(0, 200) }),
      { expirationTtl: 60 * 60 * 24 * 120 }));
  }
  if (aiRef) {
    puts.push(bumpCounter(env, `tel:ref:${aiRef}:${day}`));
    puts.push(env.LEADS_KV.put(`tel:ref:${aiRef}:last`,
      JSON.stringify({ ts: Date.now(), path: p.slice(0, 200) }),
      { expirationTtl: 60 * 60 * 24 * 120 }));
  }
  if (isPage && !bot) puts.push(bumpCounter(env, `tel:pv:${day}`));
  await Promise.all(puts);
}

// ---------------------------------------------------------------------------
// Dashboard — SEO + AEO insights UI at /dashboard/.
// Auth via DASHBOARD_TOKEN cookie (see dashboardAuth below).
// Reads aggregates from KV; renders inline.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// External data integrations (SEO/AEO measurement stack).
// Each source is optional — if its secrets aren't set, the endpoint returns
// { ok: true, configured: false, note: "..." } so the dashboard renders a
// helpful "configure me" prompt per source instead of an error.
//
// Required Worker secrets (all optional; add whichever you want):
//   CF_ANALYTICS_TOKEN         — Cloudflare API token (Account Analytics: Read)
//   CF_ACCOUNT_ID              — Cloudflare account ID (32-char hex in dash URL)
//   CF_WEB_ANALYTICS_SITE_TAG  — optional; filters RUM data to one site tag
//                                (dash.cloudflare.com/<account>/web-analytics/<siteTag>)
//   BING_WEBMASTER_KEY         — Bing Webmaster Tools API key
//   BING_SITE_URL              — usually "https://bandrproduction.com/" (default)
//   GSC_SERVICE_ACCOUNT_JSON   — Google Cloud service account JSON key (full blob)
//   GSC_SITE_URL               — usually "sc-domain:bandrproduction.com" (default)
//   GA4_SERVICE_ACCOUNT_JSON   — same or separate GCP service account
//   GA4_PROPERTY_ID            — GA4 property ID (numeric, e.g. "123456789")
//
// The GCP service account email must be added as a User on both the GSC
// property and the GA4 property for the API calls to succeed.
// ---------------------------------------------------------------------------

function b64urlEncode(bytes) {
  const str = typeof bytes === "string"
    ? bytes
    : String.fromCharCode(...new Uint8Array(bytes));
  return btoa(str).replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function importGoogleKey(pkcs8Pem) {
  const raw = pkcs8Pem
    .replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\r|\n/g, "")
    .trim();
  const bin = Uint8Array.from(atob(raw), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "pkcs8",
    bin,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

async function signGoogleJwt(saJson, scope) {
  const sa = typeof saJson === "string" ? JSON.parse(saJson) : saJson;
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT", kid: sa.private_key_id };
  const payload = {
    iss: sa.client_email,
    scope,
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now,
  };
  const input = `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(payload))}`;
  const key = await importGoogleKey(sa.private_key);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(input));
  return `${input}.${b64urlEncode(sig)}`;
}

// Get a Google API access token for the given service account + scope.
// Caches to LEADS_KV when available (55-minute TTL, JSON-serialized).
async function getGoogleToken(env, secretName, scope) {
  const raw = env[secretName];
  if (!raw) throw new Error(`${secretName} not set`);
  const cacheKey = `google:token:${secretName}:${scope}`;
  if (env.LEADS_KV) {
    const hit = await env.LEADS_KV.get(cacheKey);
    if (hit) {
      try {
        const { token, exp } = JSON.parse(hit);
        if (token && exp && exp > Math.floor(Date.now() / 1000) + 60) return token;
      } catch (_) {}
    }
  }
  const jwt = await signGoogleJwt(raw, scope);
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });
  const data = await res.json();
  if (!res.ok || !data.access_token) {
    throw new Error(`Google token exchange failed: ${res.status} ${data.error || JSON.stringify(data).slice(0, 200)}`);
  }
  if (env.LEADS_KV) {
    const exp = Math.floor(Date.now() / 1000) + (data.expires_in || 3600);
    await env.LEADS_KV.put(cacheKey, JSON.stringify({ token: data.access_token, exp }), { expirationTtl: 3300 });
  }
  return data.access_token;
}

// ---- Google Search Console ----
async function gscSummary(env, days) {
  if (!env.GSC_SERVICE_ACCOUNT_JSON) {
    return { ok: true, configured: false, note: "Set GSC_SERVICE_ACCOUNT_JSON (Google Cloud service account JSON) as a Worker Secret. Add its client_email as a User on the GSC property." };
  }
  const site = env.GSC_SITE_URL || "sc-domain:bandrproduction.com";
  const endDate = new Date().toISOString().slice(0, 10);
  const startDate = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
  try {
    const token = await getGoogleToken(env, "GSC_SERVICE_ACCOUNT_JSON", "https://www.googleapis.com/auth/webmasters.readonly");
    const url = `https://searchconsole.googleapis.com/webmasters/v3/sites/${encodeURIComponent(site)}/searchAnalytics/query`;
    async function q(dims) {
      const r = await fetch(url, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ startDate, endDate, dimensions: dims, rowLimit: 25 }),
      });
      const j = await r.json();
      if (!r.ok) throw new Error(`GSC ${r.status}: ${j.error && j.error.message || ""}`);
      return j.rows || [];
    }
    const [queries, pages] = await Promise.all([q(["query"]), q(["page"])]);
    const totClicks = queries.reduce((a, x) => a + (x.clicks || 0), 0);
    const totImp = queries.reduce((a, x) => a + (x.impressions || 0), 0);
    const avgPos = queries.length ? queries.reduce((a, x) => a + (x.position || 0), 0) / queries.length : 0;
    return { ok: true, configured: true, site, days, totals: { clicks: totClicks, impressions: totImp, avgPosition: Number(avgPos.toFixed(1)) }, queries, pages };
  } catch (e) {
    return { ok: false, configured: true, error: String(e && e.message || e) };
  }
}

// ---- GA4 Data API ----
async function ga4Summary(env, days) {
  if (!env.GA4_SERVICE_ACCOUNT_JSON || !env.GA4_PROPERTY_ID) {
    return { ok: true, configured: false, note: "Set GA4_SERVICE_ACCOUNT_JSON (can be the same key as GSC) and GA4_PROPERTY_ID as Worker Secrets. Add the service account client_email as a User on the GA4 property." };
  }
  const endDate = new Date().toISOString().slice(0, 10);
  const startDate = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
  try {
    const token = await getGoogleToken(env, "GA4_SERVICE_ACCOUNT_JSON", "https://www.googleapis.com/auth/analytics.readonly");
    const url = `https://analyticsdata.googleapis.com/v1beta/properties/${env.GA4_PROPERTY_ID}:runReport`;
    async function run(body) {
      const r = await fetch(url, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const j = await r.json();
      if (!r.ok) throw new Error(`GA4 ${r.status}: ${j.error && j.error.message || ""}`);
      return j;
    }
    const [pages, sources, totals] = await Promise.all([
      run({ dateRanges: [{ startDate, endDate }], dimensions: [{ name: "pagePath" }], metrics: [{ name: "screenPageViews" }, { name: "totalUsers" }], orderBys: [{ metric: { metricName: "screenPageViews" }, desc: true }], limit: 25 }),
      run({ dateRanges: [{ startDate, endDate }], dimensions: [{ name: "sessionSource" }], metrics: [{ name: "sessions" }, { name: "totalUsers" }], orderBys: [{ metric: { metricName: "sessions" }, desc: true }], limit: 15 }),
      run({ dateRanges: [{ startDate, endDate }], metrics: [{ name: "sessions" }, { name: "totalUsers" }, { name: "screenPageViews" }, { name: "engagementRate" }] }),
    ]);
    return { ok: true, configured: true, days, propertyId: env.GA4_PROPERTY_ID, totals: (totals.rows || [])[0] || null, pages: pages.rows || [], sources: sources.rows || [] };
  } catch (e) {
    return { ok: false, configured: true, error: String(e && e.message || e) };
  }
}

// ---- Bing Webmaster Tools ----
async function bingSummary(env) {
  if (!env.BING_WEBMASTER_KEY) {
    return { ok: true, configured: false, note: "Set BING_WEBMASTER_KEY as a Worker Secret (Bing Webmaster → Settings → API Access → generate key)." };
  }
  const site = env.BING_SITE_URL || "https://bandrproduction.com/";
  try {
    async function bing(op) {
      const u = `https://ssl.bing.com/webmaster/api.svc/json/${op}?siteUrl=${encodeURIComponent(site)}&apikey=${env.BING_WEBMASTER_KEY}`;
      const r = await fetch(u);
      const j = await r.json();
      if (!r.ok) throw new Error(`Bing ${op} ${r.status}: ${JSON.stringify(j).slice(0, 200)}`);
      return j.d || [];
    }
    const [queries, pages, stats] = await Promise.all([
      bing("GetQueryStats"),
      bing("GetPageStats"),
      bing("GetRankAndTrafficStats"),
    ]);
    return { ok: true, configured: true, site, queries: queries.slice(0, 25), pages: pages.slice(0, 25), stats: stats.slice(0, 30) };
  } catch (e) {
    return { ok: false, configured: true, error: String(e && e.message || e) };
  }
}

// ---- Cloudflare Web Analytics via GraphQL Analytics API ----
// Web Analytics (RUM) data lives under viewer.accounts[], scoped by siteTag
// (the Web Analytics site's 32-char hex — different from Zone ID). Zone-level
// analytics (httpRequestsAdaptiveGroups) is a different product; we use the
// RUM path because that's what the auto-injected beacon populates.
async function cfAnalyticsSummary(env, days) {
  // Accept either CF_ACCOUNT_ID (current name) or CF_ZONE_ID (legacy name
  // from an earlier version of this Worker) as the account tag, so a rename
  // in the code doesn't strand an existing Cloudflare secret.
  const accountTag = env.CF_ACCOUNT_ID || env.CF_ZONE_ID;
  if (!env.CF_ANALYTICS_TOKEN || !accountTag) {
    const missing = [];
    if (!env.CF_ANALYTICS_TOKEN) missing.push("CF_ANALYTICS_TOKEN");
    if (!accountTag) missing.push("CF_ACCOUNT_ID");
    return { ok: true, configured: false, note: "Missing " + missing.join(" + ") + ". Set CF_ANALYTICS_TOKEN (Cloudflare API token with Account Analytics: Read) and CF_ACCOUNT_ID (32-char hex — find it at dash.cloudflare.com, the hash after /<account>/ in any URL) as Worker Secrets. Optionally set CF_WEB_ANALYTICS_SITE_TAG to filter to one site (from dash.cloudflare.com/<account>/web-analytics/<siteTag>)." };
  }
  const end = new Date().toISOString();
  const start = new Date(Date.now() - days * 86400000).toISOString();
  const site = env.CF_WEB_ANALYTICS_SITE_TAG;
  const filterCore = site
    ? `datetime_geq: $start, datetime_leq: $end, siteTag: "${site}"`
    : `datetime_geq: $start, datetime_leq: $end`;
  const query = `query GetRUM($accountTag: String!, $start: Time!, $end: Time!) {
    viewer {
      accounts(filter: {accountTag: $accountTag}) {
        totals: rumPageloadEventsAdaptiveGroups(filter: {${filterCore}}, limit: 1) { count }
        byPath: rumPageloadEventsAdaptiveGroups(filter: {${filterCore}}, orderBy: [count_DESC], limit: 25) {
          count
          dimensions { requestPath }
        }
        byCountry: rumPageloadEventsAdaptiveGroups(filter: {${filterCore}}, orderBy: [count_DESC], limit: 15) {
          count
          dimensions { countryName }
        }
        byDevice: rumPageloadEventsAdaptiveGroups(filter: {${filterCore}}, orderBy: [count_DESC], limit: 5) {
          count
          dimensions { deviceType }
        }
        byReferer: rumPageloadEventsAdaptiveGroups(filter: {${filterCore}}, orderBy: [count_DESC], limit: 15) {
          count
          dimensions { refererHost }
        }
      }
    }
  }`;
  try {
    const r = await fetch("https://api.cloudflare.com/client/v4/graphql", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.CF_ANALYTICS_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ query, variables: { accountTag, start, end } }),
    });
    const j = await r.json();
    if (!r.ok || j.errors) {
      throw new Error(`CF Analytics ${r.status}: ${(j.errors && j.errors[0] && j.errors[0].message) || JSON.stringify(j).slice(0, 200)}`);
    }
    const a = j.data && j.data.viewer && j.data.viewer.accounts && j.data.viewer.accounts[0];
    if (!a) throw new Error("no account data (check CF_ACCOUNT_ID + token permissions)");
    return { ok: true, configured: true, days, siteTag: site || null, totals: (a.totals && a.totals[0]) || null, byPath: a.byPath || [], byCountry: a.byCountry || [], byDevice: a.byDevice || [], byReferer: a.byReferer || [] };
  } catch (e) {
    return { ok: false, configured: true, error: String(e && e.message || e) };
  }
}

// Simple bearer-token auth for the dashboard, gated by a cookie. Visit
// /dashboard/?token=<DASHBOARD_TOKEN> once; sets a 30-day HttpOnly cookie.
const DASHBOARD_COOKIE = "br_dash";
function dashboardAuth(request, env) {
  if (!env.DASHBOARD_TOKEN) return { ok: false, code: 503, msg: "dashboard not configured — set DASHBOARD_TOKEN in Cloudflare" };
  const url = new URL(request.url);
  const tokenParam = url.searchParams.get("token");
  const cookieRaw = request.headers.get("cookie") || "";
  const cookieMatch = cookieRaw.split(/;\s*/).find((c) => c.startsWith(DASHBOARD_COOKIE + "="));
  const cookieToken = cookieMatch ? cookieMatch.split("=", 2)[1] : "";
  if (tokenParam && tokenParam === env.DASHBOARD_TOKEN) return { ok: true, setCookie: true };
  if (cookieToken && cookieToken === env.DASHBOARD_TOKEN) return { ok: true, setCookie: false };
  return { ok: false, code: 401, msg: "unauthorized" };
}

// AEO targets — buyer-intent queries we WANT to be cited/rank for. Static
// list; used in the dashboard to show the aspiration side of AEO measurement.
const AEO_TARGETS = [
  { q: "who does frac pump machining in East Texas", why: "Direct buyer intent, our home turf" },
  { q: "wellhead component machining shop Texas", why: "API 6A category" },
  { q: "Inconel 718 machining shop New Waverly TX", why: "Alloy + geo, high-intent" },
  { q: "Super Duplex 2507 machining Texas", why: "Corrosion-critical, low-competition" },
  { q: "API 6A CNC machining shop", why: "Compliance-signaled buyer" },
  { q: "downhole tool machining Houston area", why: "Regional oilfield services" },
  { q: "CNC machine shop Conroe TX", why: "Local geo, near-shop" },
  { q: "who machines Inconel and Super Duplex in Texas", why: "Alloy-first LLM query pattern" },
  { q: "aerospace CNC machining Texas", why: "Non-O&G diversification" },
  { q: "emergency rig-down CNC machining Texas", why: "Urgency-driven category we own" },
  { q: "reverse engineer discontinued oilfield parts Texas", why: "Sole-source niche we win" },
  { q: "wireline tool machining shop Texas", why: "Wireline service co ICP" },
];

// Auth-wrapped endpoint handlers for the external data sources.
async function endpointGsc(request, env) {
  const auth = dashboardAuth(request, env);
  if (!auth.ok) return json({ ok: false, error: auth.msg }, auth.code);
  const days = Math.max(1, Math.min(parseInt(new URL(request.url).searchParams.get("days") || "28", 10), 90));
  return json(await gscSummary(env, days));
}
async function endpointGa4(request, env) {
  const auth = dashboardAuth(request, env);
  if (!auth.ok) return json({ ok: false, error: auth.msg }, auth.code);
  const days = Math.max(1, Math.min(parseInt(new URL(request.url).searchParams.get("days") || "28", 10), 90));
  return json(await ga4Summary(env, days));
}
async function endpointBing(request, env) {
  const auth = dashboardAuth(request, env);
  if (!auth.ok) return json({ ok: false, error: auth.msg }, auth.code);
  return json(await bingSummary(env));
}
async function endpointCfAnalytics(request, env) {
  const auth = dashboardAuth(request, env);
  if (!auth.ok) return json({ ok: false, error: auth.msg }, auth.code);
  const days = Math.max(1, Math.min(parseInt(new URL(request.url).searchParams.get("days") || "28", 10), 90));
  return json(await cfAnalyticsSummary(env, days));
}

async function dashboardSummary(request, env) {
  const auth = dashboardAuth(request, env);
  if (!auth.ok) return json({ ok: false, error: auth.msg }, auth.code);
  if (!env.LEADS_KV) return json({ ok: true, kv: false, bots: {}, refs: {}, pv: {}, lastBots: {}, lastRefs: {} });
  const url = new URL(request.url);
  const days = Math.max(1, Math.min(parseInt(url.searchParams.get("days") || "30", 10), 90));
  const cutoff = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);

  const bots = {};   // bot -> { total, byDay: {day:n} }
  const refs = {};
  const pv = {};     // day -> count
  const lastBots = {};
  const lastRefs = {};

  async function readAll(prefix, cb) {
    let cursor = undefined;
    do {
      const list = await env.LEADS_KV.list({ prefix, cursor, limit: 1000 });
      for (const k of list.keys) {
        const raw = await env.LEADS_KV.get(k.name);
        if (raw != null) await cb(k.name, raw);
      }
      cursor = list.list_complete ? undefined : list.cursor;
    } while (cursor);
  }

  await readAll("tel:bot:", async (name, raw) => {
    // name = tel:bot:<bot>:<day|last>
    const parts = name.split(":");
    if (parts.length < 4) return;
    const bot = parts[2], tag = parts[3];
    if (tag === "last") { try { lastBots[bot] = JSON.parse(raw); } catch (_) {} return; }
    if (tag < cutoff) return;
    const n = parseInt(raw, 10) || 0;
    if (!bots[bot]) bots[bot] = { total: 0, byDay: {} };
    bots[bot].total += n;
    bots[bot].byDay[tag] = n;
  });
  await readAll("tel:ref:", async (name, raw) => {
    const parts = name.split(":");
    if (parts.length < 4) return;
    const r = parts[2], tag = parts[3];
    if (tag === "last") { try { lastRefs[r] = JSON.parse(raw); } catch (_) {} return; }
    if (tag < cutoff) return;
    const n = parseInt(raw, 10) || 0;
    if (!refs[r]) refs[r] = { total: 0, byDay: {} };
    refs[r].total += n;
    refs[r].byDay[tag] = n;
  });
  await readAll("tel:pv:", async (name, raw) => {
    const day = name.slice("tel:pv:".length);
    if (day < cutoff) return;
    pv[day] = parseInt(raw, 10) || 0;
  });

  return json({
    ok: true, kv: true, days,
    bots, refs, pv, lastBots, lastRefs,
    aeoTargets: AEO_TARGETS,
  });
}

function dashboardUI(request, env) {
  const auth = dashboardAuth(request, env);
  if (!auth.ok) {
    return new Response(
      "<h1>Dashboard</h1><p>" + (auth.msg || "unauthorized") + "</p><p>Visit <code>/dashboard/?token=YOUR_TOKEN</code> once to set the cookie.</p>",
      { status: auth.code, headers: { "Content-Type": "text/html; charset=utf-8" } }
    );
  }
  const headers = { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" };
  if (auth.setCookie) {
    headers["Set-Cookie"] = `${DASHBOARD_COOKIE}=${env.DASHBOARD_TOKEN}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`;
  }
  return new Response(DASHBOARD_HTML, { headers });
}

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>B&R Insights — SEO + AEO Dashboard</title>
<meta name="robots" content="noindex,nofollow"/>
<style>
:root{--brand:#0C74C0;--ink:#0f1e3a;--muted:#4a5568;--bg:#F4F5F6;--card:#fff;--border:#DDE0E4;--green:#1b7a3a;--amber:#b56100;--red:#b00020}
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink);line-height:1.5}
.top{background:#0d0d0d;color:#fff;padding:14px 20px;font-weight:700;display:flex;justify-content:space-between;align-items:center}
.top a{color:#c9d1da;text-decoration:none;font-size:14px;font-weight:400;margin-left:16px}
.top a:hover{color:#fff}
.wrap{max-width:1200px;margin:24px auto;padding:0 20px}
h1{font-size:26px;margin:0 0 4px}
p.sub{color:var(--muted);margin:0 0 22px}
.tabs{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:22px}
.tab{padding:12px 22px;cursor:pointer;font-weight:600;color:var(--muted);border-bottom:3px solid transparent;margin-bottom:-2px}
.tab.active{color:var(--brand);border-bottom-color:var(--brand)}
.panel{display:none}.panel.active{display:block}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-bottom:22px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:18px}
.card h3{margin:0 0 6px;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;font-weight:700}
.card .big{font-size:32px;font-weight:800;color:var(--ink);line-height:1}
.card .sub{font-size:13px;color:var(--muted);margin-top:6px}
.card.wide{grid-column:1/-1}
.card h2{margin:0 0 14px;font-size:18px;color:var(--brand)}
.card h4{margin:20px 0 8px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:9px 6px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.03em;font-weight:600}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.btn{display:inline-block;padding:8px 16px;background:var(--brand);color:#fff;text-decoration:none;font-weight:600;font-size:14px;border-radius:6px;margin:4px 6px 4px 0}
.btn:hover{background:#0a5f9c}
.btn.ghost{background:transparent;color:var(--brand);border:1px solid var(--brand)}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;letter-spacing:.02em;text-transform:uppercase}
.badge.on{background:#e6f4ea;color:var(--green)}
.badge.pending{background:#fef2e6;color:var(--amber)}
.badge.off{background:#fdecea;color:var(--red)}
.note{background:#fef8e6;border:1px solid #f4d78b;padding:12px 14px;border-radius:8px;font-size:14px;color:#6a5100;margin:0 0 18px}
.hint{color:var(--muted);font-size:13px;margin:6px 0 0}
select{padding:6px 10px;border-radius:6px;border:1px solid var(--border);font-size:14px}
small{color:var(--muted)}
</style>
</head>
<body>
<div class="top">
  <div>B&R Insights <span style="opacity:.65;font-weight:400;font-size:13px;margin-left:8px">SEO + AEO</span></div>
  <div><a href="/">← site</a></div>
</div>
<div class="wrap">
  <h1>Where B&R is showing up</h1>
  <p class="sub">SEO (search engines) is measurable via GSC + Bing Webmaster. AEO (AI answer engines) is emerging — we track bot crawls + referral click-throughs + a rotating query check.</p>

  <div class="tabs">
    <div class="tab active" data-panel="seo">SEO</div>
    <div class="tab" data-panel="aeo">AEO</div>
    <div class="tab" data-panel="citations">Citations</div>
    <div class="tab" data-panel="rankings">Rankings</div>
    <div class="tab" data-panel="setup">Setup</div>
  </div>

  <!-- ============ SEO PANEL ============ -->
  <div class="panel active" id="panel-seo">
    <div class="grid">
      <div class="card"><h3>URLs in Sitemap</h3><div class="big" id="urlCount">–</div><div class="sub">Indexed via Google + Bing/Yandex/Naver</div></div>
      <div class="card"><h3>Page views (30d)</h3><div class="big" id="pvTotal">–</div><div class="sub">Worker request log; add CF Web Analytics for full picture</div></div>
      <div class="card"><h3>IndexNow</h3><div class="big" style="font-size:18px;color:var(--green)">Verified</div><div class="sub">Auto-submit on every deploy</div></div>
      <div class="card"><h3>Feeds</h3><div class="big" style="font-size:16px;line-height:1.3">sitemap · rss · feed.json · llms.txt</div><div class="sub">Autodiscovery on every page</div></div>
    </div>

    <div style="margin:22px 0 12px"><label>Window:
      <select id="seoDays"><option value="7">7 days</option><option value="28" selected>28 days</option><option value="90">90 days</option></select>
    </label></div>

    <!-- Google Search Console -->
    <div class="card wide">
      <h2>Google Search Console</h2>
      <div id="gscBox"><small>loading...</small></div>
    </div>

    <!-- GA4 -->
    <div class="card wide">
      <h2>Google Analytics 4</h2>
      <div id="ga4Box"><small>loading...</small></div>
    </div>

    <!-- Bing Webmaster -->
    <div class="card wide">
      <h2>Bing Webmaster</h2>
      <div id="bingBox"><small>loading...</small></div>
    </div>

    <!-- Cloudflare Web Analytics -->
    <div class="card wide">
      <h2>Cloudflare Web Analytics</h2>
      <div id="cfBox"><small>loading...</small></div>
    </div>

    <div class="card wide">
      <h2>Open the underlying tools</h2>
      <a class="btn" href="https://search.google.com/search-console" target="_blank">GSC →</a>
      <a class="btn" href="https://www.bing.com/webmasters/" target="_blank">Bing WMT →</a>
      <a class="btn ghost" href="https://analytics.google.com/" target="_blank">GA4 →</a>
      <a class="btn ghost" href="https://dash.cloudflare.com/" target="_blank">Cloudflare →</a>
    </div>
  </div>

  <!-- ============ AEO PANEL ============ -->
  <div class="panel" id="panel-aeo">
    <p class="note"><strong>AEO measurement is emerging.</strong> Traditional analytics miss most AI-answer traffic because engines answer inline. What we can measure: (1) which AI crawlers are indexing us, (2) any click-throughs from AI referrers, (3) rotating manual query checks. Numbers are proxies, not direct impressions.</p>

    <div class="grid">
      <div class="card"><h3>AI Bot hits <small>(<span id="aeoDays">30</span>d)</small></h3><div class="big" id="botTotal">–</div><div class="sub">GPTBot, ClaudeBot, PerplexityBot, etc.</div></div>
      <div class="card"><h3>AI Referrer clicks <small>(<span id="aeoDays2">30</span>d)</small></h3><div class="big" id="refTotal">–</div><div class="sub">Actual click-throughs from AI answer pages</div></div>
      <div class="card"><h3>Targets we're chasing</h3><div class="big" id="targetCount">–</div><div class="sub">Buyer-intent queries; rotate weekly</div></div>
    </div>

    <div style="margin:0 0 14px"><label>Window:
      <select id="daysSel"><option value="7">7 days</option><option value="30" selected>30 days</option><option value="90">90 days</option></select>
    </label></div>

    <div class="card wide">
      <h2>AI crawlers hitting the site</h2>
      <p style="color:var(--muted);margin:0 0 12px;font-size:14px">Every crawl = your content being ingested for an AI answer engine's index.</p>
      <div id="botsTbl"><small>loading...</small></div>
    </div>

    <div class="card wide">
      <h2>Click-throughs from AI answer pages</h2>
      <p style="color:var(--muted);margin:0 0 12px;font-size:14px">A visitor arriving here after reading an AI answer that mentioned or linked B&R.</p>
      <div id="refsTbl"><small>loading...</small></div>
    </div>

    <div class="card wide">
      <h2>AEO targets — what we're trying for</h2>
      <p style="color:var(--muted);margin:0 0 12px;font-size:14px">Ask ChatGPT / Perplexity / Claude / Gemini / Copilot each of these ~monthly. Note whether B&R appears + is linked. Add findings to the Sunday briefing so we know which content to expand.</p>
      <table><thead><tr><th>Query</th><th>Why we care</th><th>Try it</th></tr></thead>
      <tbody id="targetsTbl"></tbody></table>
    </div>
  </div>

  <!-- ============ CITATIONS PANEL ============ -->
  <div class="panel" id="panel-citations">
    <div class="grid">
      <div class="card"><h3>Total directories</h3><div class="big" id="citTotal">–</div><div class="sub">Automatable via Puppeteer</div></div>
      <div class="card"><h3>Submitted</h3><div class="big" id="citSubmitted" style="color:var(--brand)">–</div><div class="sub">Form filled, awaiting verification</div></div>
      <div class="card"><h3>Verified</h3><div class="big" id="citVerified" style="color:var(--green)">–</div><div class="sub">Auto-clicked verification link</div></div>
      <div class="card"><h3>Failed / skipped</h3><div class="big" id="citFailed" style="color:#b00020">–</div><div class="sub">CAPTCHA, selector miss, or account required</div></div>
    </div>
    <div class="card wide">
      <h2>Per-directory status</h2>
      <p class="sub" style="margin:0 0 12px">Live from <code>LEADS_KV</code> under <code>citation:*</code> keys. To submit or retry, hit <code>/admin/citations/submit</code> or <code>/admin/citations/retry</code> with your <code>ADMIN_TOKEN</code>. See <code>content/CITATIONS_SETUP.md</code>.</p>
      <table>
        <thead><tr><th>Directory</th><th>Tier</th><th>Status</th><th>Submitted</th><th>Verified</th><th>Notes / error</th></tr></thead>
        <tbody id="citTbl"><tr><td colspan="6"><small>Loading…</small></td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- ============ RANKINGS PANEL ============ -->
  <div class="panel" id="panel-rankings">
    <div class="grid">
      <div class="card"><h3>Tracked keywords</h3><div class="big" id="rkTotal">–</div><div class="sub" id="rkAsOf">Weekly snapshot</div></div>
      <div class="card"><h3>Ranking (top 100)</h3><div class="big" id="rkRanking" style="color:var(--brand)">–</div><div class="sub">Anywhere on the first 10 pages</div></div>
      <div class="card"><h3>Top 10</h3><div class="big" id="rkTop10" style="color:var(--green)">–</div><div class="sub" id="rkPos1120">–</div></div>
      <div class="card"><h3>Volume captured</h3><div class="big" id="rkVolCaptured">–</div><div class="sub" id="rkVolAddr">of addressable monthly searches</div></div>
    </div>
    <div class="card wide">
      <h2>Movement since last snapshot <span id="rkPrev" style="font-weight:400;color:var(--muted);font-size:14px"></span></h2>
      <div id="rkDeltasBox"><small>Loading…</small></div>
    </div>
    <div class="card wide">
      <h2>Per-group standings</h2>
      <div id="rkGroupsBox"><small>Loading…</small></div>
      <p class="sub" style="margin-top:16px">Snapshot runs weekly on the Monday cron. Requires Worker secrets <code>DATAFORSEO_LOGIN</code> + <code>DATAFORSEO_PASSWORD</code>. Same keyword universe as <code>rank_tracker.py</code>.</p>
    </div>
  </div>

  <!-- ============ SETUP PANEL ============ -->
  <div class="panel" id="panel-setup">
    <div class="card wide">
      <h2>What's active vs. pending</h2>
      <table>
        <tbody>
          <tr><td>GTM container (GTM-WKQL399K)</td><td><span class="badge on">Firing</span></td><td>GA4 + Google Ads inside</td></tr>
          <tr><td>Sitemap + RSS + JSON Feed</td><td><span class="badge on">Live</span></td><td>Autodiscovery on every page</td></tr>
          <tr><td>IndexNow (Bing/Yandex/Naver)</td><td><span class="badge on">Verified</span></td><td>Auto-submit each deploy</td></tr>
          <tr><td>llms.txt</td><td><span class="badge on">Published</span></td><td>Structured signal for LLM ingestion</td></tr>
          <tr><td>Cloudflare AI Crawl Control</td><td><span class="badge on">Allow</span></td><td>Search + Agent + Training bots all permitted</td></tr>
          <tr><td>Dashboard access</td><td><span class="badge on">Active</span></td><td>DASHBOARD_TOKEN cookie set (you're logged in)</td></tr>
          <tr><td>Google Search Console (verify)</td><td><span class="badge on">Done</span></td><td>Sitemap submitted</td></tr>
          <tr><td>Bing Webmaster Tools (verify)</td><td><span class="badge on">Done</span></td><td>Sitemap submitted</td></tr>
          <tr><td>Cloudflare Web Analytics</td><td><span class="badge on">Enabled</span></td><td>Auto-inject at the edge (no snippet needed)</td></tr>
          <tr><td>Worker AI-bot telemetry (KV)</td><td><span id="kvBadge" class="badge pending">Optional</span></td><td>Bind LEADS_KV to store bot/referrer counters + weekly lead digest history</td></tr>
          <tr><td colspan="3" style="padding-top:22px;font-weight:700;color:var(--brand)">API access to see data live on this dashboard →</td></tr>
          <tr><td><code>CF_ANALYTICS_TOKEN</code> + <code>CF_ACCOUNT_ID</code></td><td><span id="secCf" class="badge pending">Set</span></td><td>Cloudflare API token (Account Analytics: Read) + Account ID (32-char hex from CF dashboard URL). Optional: <code>CF_WEB_ANALYTICS_SITE_TAG</code> to scope to one site (from the Web Analytics URL path). Powers the CF Web Analytics card.</td></tr>
          <tr><td><code>BING_WEBMASTER_KEY</code></td><td><span id="secBing" class="badge pending">Set</span></td><td>Bing Webmaster → Settings → API Access → generate key. Powers the Bing card.</td></tr>
          <tr><td><code>GSC_SERVICE_ACCOUNT_JSON</code></td><td><span id="secGsc" class="badge pending">Set</span></td><td>GCP service account JSON key. Add the service account client_email as a User on the GSC property. Powers the GSC card.</td></tr>
          <tr><td><code>GA4_SERVICE_ACCOUNT_JSON</code> + <code>GA4_PROPERTY_ID</code></td><td><span id="secGa4" class="badge pending">Set</span></td><td>Can be the same GCP service account. Add its client_email as a User on the GA4 property. Powers the GA4 card.</td></tr>
          <tr><td><code>DATAFORSEO_LOGIN</code> + <code>DATAFORSEO_PASSWORD</code></td><td><span id="secDfs" class="badge pending">Set</span></td><td>DataForSEO API creds — powers the Rankings tab + weekly digest rank deltas. Snapshot runs on the Monday 13:00 UTC cron; write to LEADS_KV under <code>rank_snapshot:*</code>. Manual refresh: <code>POST /admin/ranks/refresh</code> with <code>ADMIN_TOKEN</code>.</td></tr>
        </tbody>
      </table>
    </div>

  </div>
</div>

<script>
const $ = (id) => document.getElementById(id);
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  $('panel-' + t.dataset.panel).classList.add('active');
}));
$('daysSel').addEventListener('change', () => load($('daysSel').value));

function fmtDate(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toISOString().slice(0,10);
}
function fmtRel(ts) {
  if (!ts) return '—';
  const d = Math.round((Date.now() - ts) / 86400000);
  return d < 1 ? 'today' : d + 'd ago';
}
function esc(s) { return String(s || '').replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[c])); }

function num(x) { return (x == null ? 0 : Number(x)).toLocaleString(); }
function pct(x) { return (Math.round((x || 0) * 1000) / 10) + '%'; }
function shortPath(p) { return String(p || '').replace(/^https?:\\/\\/[^\\/]+/, ''); }

function renderConfigured(box, note) {
  box.innerHTML = '<div class="note" style="margin:0"><strong>Not configured yet.</strong> ' + esc(note || '') + '</div>';
}
function renderError(box, err) {
  box.innerHTML = '<div class="note" style="background:#fdecea;border-color:#f4b8b8;color:#7a1418"><strong>Error:</strong> ' + esc(err || '') + '</div>';
}

async function loadGsc(days) {
  const box = $('gscBox'); box.innerHTML = '<small>loading GSC...</small>';
  const r = await (await fetch('/dashboard/api/gsc?days=' + days)).json();
  if (r.configured === false) { renderConfigured(box, r.note); $('secGsc').className='badge pending'; $('secGsc').textContent='Set'; return; }
  if (!r.ok) { renderError(box, r.error); $('secGsc').className='badge off'; $('secGsc').textContent='Error'; return; }
  $('secGsc').className='badge on'; $('secGsc').textContent='Live';
  const t = r.totals || {};
  const cards = '<div class="grid">' +
    '<div class="card"><h3>Clicks</h3><div class="big">' + num(t.clicks) + '</div><div class="sub">' + r.days + 'd</div></div>' +
    '<div class="card"><h3>Impressions</h3><div class="big">' + num(t.impressions) + '</div><div class="sub">' + r.days + 'd</div></div>' +
    '<div class="card"><h3>Avg position</h3><div class="big">' + (t.avgPosition || '–') + '</div><div class="sub">Top 25 queries</div></div>' +
    '</div>';
  const qrows = (r.queries || []).map(q => '<tr><td><strong>' + esc(q.keys[0]) + '</strong></td>' +
    '<td class="num">' + num(q.clicks) + '</td><td class="num">' + num(q.impressions) + '</td>' +
    '<td class="num">' + pct(q.ctr) + '</td><td class="num">' + (q.position ? q.position.toFixed(1) : '–') + '</td></tr>').join('');
  const prows = (r.pages || []).map(p => '<tr><td><a href="' + esc(p.keys[0]) + '" target="_blank" style="color:var(--brand);text-decoration:none">' + esc(shortPath(p.keys[0])) + '</a></td>' +
    '<td class="num">' + num(p.clicks) + '</td><td class="num">' + num(p.impressions) + '</td>' +
    '<td class="num">' + pct(p.ctr) + '</td><td class="num">' + (p.position ? p.position.toFixed(1) : '–') + '</td></tr>').join('');
  box.innerHTML = cards +
    '<h4>Top queries</h4>' + (qrows ? '<table><thead><tr><th>Query</th><th class="num">Clicks</th><th class="num">Impr</th><th class="num">CTR</th><th class="num">Pos</th></tr></thead><tbody>'+qrows+'</tbody></table>' : '<small>No query data yet — GSC needs 24–72h after sitemap submission.</small>') +
    '<h4>Top pages</h4>' + (prows ? '<table><thead><tr><th>URL</th><th class="num">Clicks</th><th class="num">Impr</th><th class="num">CTR</th><th class="num">Pos</th></tr></thead><tbody>'+prows+'</tbody></table>' : '<small>No page data yet.</small>');
}

async function loadGa4(days) {
  const box = $('ga4Box'); box.innerHTML = '<small>loading GA4...</small>';
  const r = await (await fetch('/dashboard/api/ga4?days=' + days)).json();
  if (r.configured === false) { renderConfigured(box, r.note); $('secGa4').className='badge pending'; $('secGa4').textContent='Set'; return; }
  if (!r.ok) { renderError(box, r.error); $('secGa4').className='badge off'; $('secGa4').textContent='Error'; return; }
  $('secGa4').className='badge on'; $('secGa4').textContent='Live';
  const t = (r.totals && r.totals.metricValues) || [];
  const cards = '<div class="grid">' +
    '<div class="card"><h3>Sessions</h3><div class="big">' + num(t[0] && t[0].value) + '</div><div class="sub">' + r.days + 'd</div></div>' +
    '<div class="card"><h3>Users</h3><div class="big">' + num(t[1] && t[1].value) + '</div><div class="sub">' + r.days + 'd</div></div>' +
    '<div class="card"><h3>Page views</h3><div class="big">' + num(t[2] && t[2].value) + '</div><div class="sub">' + r.days + 'd</div></div>' +
    '<div class="card"><h3>Engagement</h3><div class="big">' + (t[3] ? pct(parseFloat(t[3].value)) : '–') + '</div><div class="sub">Engaged sessions rate</div></div>' +
    '</div>';
  const prows = (r.pages || []).map(row => {
    const p = row.dimensionValues[0].value, m = row.metricValues;
    return '<tr><td><a href="' + esc(p) + '" target="_blank" style="color:var(--brand);text-decoration:none">' + esc(p) + '</a></td>' +
           '<td class="num">' + num(m[0].value) + '</td><td class="num">' + num(m[1].value) + '</td></tr>';
  }).join('');
  const srows = (r.sources || []).map(row => {
    const s = row.dimensionValues[0].value, m = row.metricValues;
    return '<tr><td><strong>' + esc(s) + '</strong></td><td class="num">' + num(m[0].value) + '</td><td class="num">' + num(m[1].value) + '</td></tr>';
  }).join('');
  box.innerHTML = cards +
    '<h4>Top pages</h4>' + (prows ? '<table><thead><tr><th>URL</th><th class="num">Views</th><th class="num">Users</th></tr></thead><tbody>'+prows+'</tbody></table>' : '<small>No data yet.</small>') +
    '<h4>Traffic sources</h4>' + (srows ? '<table><thead><tr><th>Source</th><th class="num">Sessions</th><th class="num">Users</th></tr></thead><tbody>'+srows+'</tbody></table>' : '<small>No data yet.</small>');
}

async function loadBing(days) {
  const box = $('bingBox'); box.innerHTML = '<small>loading Bing...</small>';
  const r = await (await fetch('/dashboard/api/bing')).json();
  if (r.configured === false) { renderConfigured(box, r.note); $('secBing').className='badge pending'; $('secBing').textContent='Set'; return; }
  if (!r.ok) { renderError(box, r.error); $('secBing').className='badge off'; $('secBing').textContent='Error'; return; }
  $('secBing').className='badge on'; $('secBing').textContent='Live';
  const qrows = (r.queries || []).map(q => '<tr><td><strong>' + esc(q.Query) + '</strong></td>' +
    '<td class="num">' + num(q.Clicks) + '</td><td class="num">' + num(q.Impressions) + '</td>' +
    '<td class="num">' + num(q.AvgClickPosition) + '</td><td class="num">' + num(q.AvgImpressionPosition) + '</td></tr>').join('');
  const prows = (r.pages || []).map(p => '<tr><td><a href="' + esc(p.Query) + '" target="_blank" style="color:var(--brand);text-decoration:none">' + esc(shortPath(p.Query)) + '</a></td>' +
    '<td class="num">' + num(p.Clicks) + '</td><td class="num">' + num(p.Impressions) + '</td></tr>').join('');
  box.innerHTML =
    '<h4>Top queries (Bing)</h4>' + (qrows ? '<table><thead><tr><th>Query</th><th class="num">Clicks</th><th class="num">Impr</th><th class="num">Click Pos</th><th class="num">Impr Pos</th></tr></thead><tbody>'+qrows+'</tbody></table>' : '<small>No query data yet.</small>') +
    '<h4>Top pages</h4>' + (prows ? '<table><thead><tr><th>URL</th><th class="num">Clicks</th><th class="num">Impr</th></tr></thead><tbody>'+prows+'</tbody></table>' : '<small>No page data yet.</small>');
}

async function loadCf(days) {
  const box = $('cfBox'); box.innerHTML = '<small>loading Cloudflare Analytics...</small>';
  const r = await (await fetch('/dashboard/api/cf-analytics?days=' + days)).json();
  if (r.configured === false) { renderConfigured(box, r.note); $('secCf').className='badge pending'; $('secCf').textContent='Set'; return; }
  if (!r.ok) { renderError(box, r.error); $('secCf').className='badge off'; $('secCf').textContent='Error'; return; }
  $('secCf').className='badge on'; $('secCf').textContent='Live';
  const total = (r.totals && r.totals.count) || 0;
  const cards = '<div class="grid">' +
    '<div class="card"><h3>Page views</h3><div class="big">' + num(total) + '</div><div class="sub">' + r.days + 'd, edge-measured</div></div>' +
    '</div>';
  const prows = (r.byPath || []).map(row => '<tr><td><a href="' + esc(row.dimensions.requestPath) + '" target="_blank" style="color:var(--brand);text-decoration:none">' + esc(row.dimensions.requestPath) + '</a></td>' +
    '<td class="num">' + num(row.count) + '</td></tr>').join('');
  const crows = (r.byCountry || []).map(row => '<tr><td>' + esc(row.dimensions.countryName || '?') + '</td><td class="num">' + num(row.count) + '</td></tr>').join('');
  const rrows = (r.byReferer || []).map(row => '<tr><td>' + esc(row.dimensions.refererHost || '(direct)') + '</td><td class="num">' + num(row.count) + '</td></tr>').join('');
  box.innerHTML = cards +
    '<h4>Top pages (real visitors)</h4>' + (prows ? '<table><thead><tr><th>URL</th><th class="num">Views</th></tr></thead><tbody>'+prows+'</tbody></table>' : '<small>No visitor data yet — Cloudflare Web Analytics starts collecting after enable + first page load.</small>') +
    '<h4>By country</h4>' + (crows ? '<table><thead><tr><th>Country</th><th class="num">Views</th></tr></thead><tbody>'+crows+'</tbody></table>' : '<small>No data yet.</small>') +
    '<h4>Top referrers</h4>' + (rrows ? '<table><thead><tr><th>Source</th><th class="num">Views</th></tr></thead><tbody>'+rrows+'</tbody></table>' : '<small>No data yet.</small>');
}

$('seoDays').addEventListener('change', () => { const d = $('seoDays').value; loadGsc(d); loadGa4(d); loadBing(d); loadCf(d); });

async function loadCitations() {
  try {
    const r = await fetch('/dashboard/api/citations');
    const d = await r.json();
    if (!d.ok) {
      $('citTbl').innerHTML = '<tr><td colspan="6"><small>' + (d.error || 'load failed') + '</small></td></tr>';
      return;
    }
    $('citTotal').textContent = d.summary.total;
    $('citSubmitted').textContent = d.summary.submitted;
    $('citVerified').textContent = d.summary.verified;
    $('citFailed').textContent = d.summary.failed + d.summary.pending;
    var badge = function(status){
      var color = 'var(--muted)', bg = '#f4f5f6';
      if (status === 'submitted') { color = 'var(--brand)'; bg = 'rgba(12,116,192,0.10)'; }
      else if (status === 'verified' || status === 'live') { color = 'var(--green)'; bg = 'rgba(27,122,58,0.10)'; }
      else if (status === 'failed') { color = '#b00020'; bg = 'rgba(176,0,32,0.10)'; }
      else if (status === 'skipped_captcha') { color = '#b56100'; bg = 'rgba(181,97,0,0.10)'; }
      return '<span style="display:inline-block;padding:3px 10px;border-radius:12px;color:'+color+';background:'+bg+';font-size:12px;font-weight:600">'+status+'</span>';
    };
    var fmt = function(ts){ return ts ? new Date(ts).toLocaleString() : '—'; };
    var rows = (d.records || []).filter(function(r){ return r && r.directory; }).map(function(r){
      var dir = (d.directories && d.directories[r.directory]) || {};
      var name = dir.name || r.directory;
      return '<tr>'
        + '<td><strong>'+name+'</strong><br><small><a href="'+(r.url||dir.url)+'" target="_blank" rel="noopener">'+(r.url||dir.url||'').replace(/^https?:\\/\\//,'')+'</a></small></td>'
        + '<td>'+r.tier+'</td>'
        + '<td>'+badge(r.status)+'</td>'
        + '<td><small>'+fmt(r.submitted_at)+'</small></td>'
        + '<td><small>'+fmt(r.verified_at)+'</small></td>'
        + '<td><small>'+(r.last_error || r.notes || '—')+'</small></td>'
        + '</tr>';
    }).join('');
    $('citTbl').innerHTML = rows || '<tr><td colspan="6"><small>No records yet — submit via /admin/citations/submit</small></td></tr>';
  } catch (e) {
    $('citTbl').innerHTML = '<tr><td colspan="6"><small>error: '+(e && e.message)+'</small></td></tr>';
  }
}

async function loadRanks() {
  try {
    const r = await fetch('/dashboard/api/ranks');
    const d = await r.json();
    if (!d.ok) {
      $('rkDeltasBox').innerHTML = '<small>' + (d.error || 'load failed — check DATAFORSEO_LOGIN/PASSWORD are set') + '</small>';
      return;
    }
    const latest = d.latest;
    if (!latest) {
      $('rkDeltasBox').innerHTML = '<small>No snapshot yet. First one runs on the next Monday cron. To trigger manually: bind LEADS_KV + set DATAFORSEO_LOGIN/PASSWORD, then hit the /admin/ranks/refresh endpoint (not yet wired) or wait for cron.</small>';
      return;
    }
    const s = latest.summary || {};
    $('rkTotal').textContent = s.total_tracked || 0;
    $('rkRanking').textContent = s.ranking || 0;
    $('rkTop10').textContent = s.top_10 || 0;
    $('rkPos1120').textContent = 'Pos 11-20: ' + (s.pos_11_20 || 0) + ' (near page 1)';
    $('rkVolCaptured').textContent = (s.captured_volume || 0).toLocaleString();
    $('rkVolAddr').textContent = 'of ' + (s.total_addressable_volume || 0).toLocaleString() + ' addressable monthly searches';
    $('rkAsOf').textContent = 'Captured ' + (latest.captured_at || '').slice(0, 10);

    // Deltas
    if (d.prev_date) $('rkPrev').textContent = 'vs ' + d.prev_date;
    if (!d.deltas || !d.deltas.length) {
      $('rkDeltasBox').innerHTML = '<small>No rank changes since ' + (d.prev_date || 'previous snapshot') + '.</small>';
    } else {
      const arrow = { UP: '🟢 ↑', DOWN: '🔴 ↓', NEW: '✨ NEW', LOST: '❌ LOST' };
      const rows = d.deltas.slice(0, 40).map(function(x){
        return '<tr>'
          + '<td>' + (arrow[x.dir] || x.dir) + '</td>'
          + '<td>' + x.keyword + '</td>'
          + '<td><small>' + x.group + '</small></td>'
          + '<td>' + (x.was || '—') + '</td>'
          + '<td><strong>' + (x.now || '—') + '</strong></td>'
          + '<td>' + (x.volume || 0) + '</td>'
          + '</tr>';
      }).join('');
      $('rkDeltasBox').innerHTML = '<table><thead><tr><th>Δ</th><th>Keyword</th><th>Group</th><th>Was</th><th>Now</th><th>Vol</th></tr></thead><tbody>' + rows + '</tbody></table>';
    }

    // Per-group table
    const groupHtml = Object.entries(latest.groups || {}).map(function(entry){
      const group = entry[0], rows = entry[1];
      const sorted = rows.slice().sort(function(a, b){
        const ar = a.rank == null ? 9999 : a.rank;
        const br = b.rank == null ? 9999 : b.rank;
        return ar - br;
      });
      const trs = sorted.map(function(r){
        return '<tr><td>' + r.keyword + '</td><td>' + (r.rank == null ? '—' : r.rank) + '</td><td>' + (r.volume || 0) + '</td><td>$' + (r.cpc || 0) + '</td><td><small>' + (r.url ? r.url.replace('https://bandrproduction.com','') : '—') + '</small></td></tr>';
      }).join('');
      return '<h3 style="margin-top:20px;color:var(--brand)">' + group + '</h3>'
        + '<table><thead><tr><th>Keyword</th><th>Rank</th><th>Vol</th><th>CPC</th><th>Landing URL</th></tr></thead><tbody>' + trs + '</tbody></table>';
    }).join('');
    $('rkGroupsBox').innerHTML = groupHtml;
  } catch (e) {
    $('rkDeltasBox').innerHTML = '<small>error: ' + (e && e.message) + '</small>';
  }
}

async function load(days) {
  days = days || 30;
  $('aeoDays').textContent = days; $('aeoDays2').textContent = days;
  const seoDays = $('seoDays').value;
  loadGsc(seoDays); loadGa4(seoDays); loadBing(seoDays); loadCf(seoDays); loadCitations(); loadRanks();
  const r = await fetch('/dashboard/api/summary?days=' + days);
  const d = await r.json();
  if (!d.ok) { alert(d.error || 'load failed'); return; }
  if (!d.kv) { $('kvBadge').className = 'badge off'; $('kvBadge').textContent = 'not bound'; }
  else { $('kvBadge').className = 'badge on'; $('kvBadge').textContent = 'active'; }

  // SEO cards — fetch actual sitemap URL count on each dashboard load so it stays fresh.
  $('urlCount').textContent = '…';
  fetch('/sitemap.xml', {cache: 'no-store'})
    .then(function(r){ return r.text(); })
    .then(function(xml){
      var m = xml.match(/<loc>/g);
      $('urlCount').textContent = m ? m.length : '—';
    })
    .catch(function(){ $('urlCount').textContent = '—'; });
  const pvTotal = Object.values(d.pv || {}).reduce((a,b) => a + b, 0);
  $('pvTotal').textContent = pvTotal || (d.kv ? '0' : '—');

  // AEO cards
  const botTotal = Object.values(d.bots || {}).reduce((a,b) => a + (b.total||0), 0);
  const refTotal = Object.values(d.refs || {}).reduce((a,b) => a + (b.total||0), 0);
  $('botTotal').textContent = botTotal || (d.kv ? '0' : '—');
  $('refTotal').textContent = refTotal || (d.kv ? '0' : '—');
  $('targetCount').textContent = (d.aeoTargets || []).length;

  // Bots table
  const botsEntries = Object.entries(d.bots || {}).sort((a,b) => b[1].total - a[1].total);
  if (!botsEntries.length) {
    $('botsTbl').innerHTML = '<small>' + (d.kv ? 'No AI bot hits recorded yet in this window. New crawls will appear here.' : 'LEADS_KV not bound — bind it in the Worker settings to start capturing.') + '</small>';
  } else {
    const rows = botsEntries.map(([bot, s]) => {
      const last = d.lastBots[bot];
      return '<tr><td><strong>' + esc(bot) + '</strong></td>' +
             '<td class="num">' + s.total + '</td>' +
             '<td><small>' + fmtRel(last && last.ts) + '</small></td>' +
             '<td><small>' + esc((last && last.path) || '') + '</small></td></tr>';
    }).join('');
    $('botsTbl').innerHTML = '<table><thead><tr><th>Crawler</th><th class="num">Hits</th><th>Last seen</th><th>Last URL</th></tr></thead><tbody>' + rows + '</tbody></table>';
  }

  // Refs table
  const refsEntries = Object.entries(d.refs || {}).sort((a,b) => b[1].total - a[1].total);
  if (!refsEntries.length) {
    $('refsTbl').innerHTML = '<small>' + (d.kv ? 'No AI-referrer clicks in this window. When someone clicks through from ChatGPT/Perplexity/Claude/etc., they show here.' : 'Bind LEADS_KV to start capturing.') + '</small>';
  } else {
    const rows = refsEntries.map(([r, s]) => {
      const last = d.lastRefs[r];
      return '<tr><td><strong>' + esc(r) + '</strong></td>' +
             '<td class="num">' + s.total + '</td>' +
             '<td><small>' + fmtRel(last && last.ts) + '</small></td>' +
             '<td><small>' + esc((last && last.path) || '') + '</small></td></tr>';
    }).join('');
    $('refsTbl').innerHTML = '<table><thead><tr><th>Source</th><th class="num">Clicks</th><th>Last seen</th><th>Landed on</th></tr></thead><tbody>' + rows + '</tbody></table>';
  }

  // Targets
  const targets = d.aeoTargets || [];
  $('targetsTbl').innerHTML = targets.map(t => {
    const q = encodeURIComponent(t.q);
    return '<tr><td><strong>' + esc(t.q) + '</strong></td>' +
           '<td><small>' + esc(t.why) + '</small></td>' +
           '<td>' +
             '<a class="btn ghost" style="padding:4px 10px;font-size:12px;margin:2px" href="https://www.perplexity.ai/?q=' + q + '" target="_blank">Perplexity</a>' +
             '<a class="btn ghost" style="padding:4px 10px;font-size:12px;margin:2px" href="https://chatgpt.com/?q=' + q + '" target="_blank">ChatGPT</a>' +
             '<a class="btn ghost" style="padding:4px 10px;font-size:12px;margin:2px" href="https://claude.ai/new?q=' + q + '" target="_blank">Claude</a>' +
             '<a class="btn ghost" style="padding:4px 10px;font-size:12px;margin:2px" href="https://www.google.com/search?q=' + q + '&udm=50" target="_blank">Google AI</a>' +
           '</td></tr>';
  }).join('');
}
load(30);
</script>
</body>
</html>`;

// ===========================================================================
// CITATION SUBMISSION STACK (Phase 2)
// ===========================================================================
// Auto-submits B&R's NAP data to ~13 automatable B2B/local directories via
// Cloudflare Browser Rendering (Puppeteer). Each adapter targets one
// directory's form. Skipped-by-design (CAPTCHA/phone-verify): GBP, Yelp, BBB,
// FB, Apple, LinkedIn, Bing Places, ThomasNet — those require humans.
//
// State is persisted in LEADS_KV under `citation:<slug>` keys.
// Inbound verification emails are handled by inboundEmail() (Email Routing).
//
// Setup once in Cloudflare dashboard (Aaron does this):
//   1. Workers Paid plan
//   2. Enable Browser Rendering; binding name: MYBROWSER
//   3. Cloudflare Email Routing → create citations@bandrproduction.com
//      → route to this Worker (email_routing binding)
//   4. Set ADMIN_TOKEN secret (any 32-char random string)
//   5. Install @cloudflare/puppeteer in the worker package.json:
//      npm install --save-dev @cloudflare/puppeteer
//   6. Optional: create R2 bucket bandr-citations for screenshots

// The canonical NAP for every submission — sourced from
// content/citation-submission-package.md and locked to prevent drift.
const NAP = {
  name:        "B&R Productions",
  street:      "5909 Farm to Market Road 1374",
  city:        "New Waverly",
  state:       "TX",
  postal:      "77358",
  country:     "US",
  phone:       "(936) 291-7827",
  phone_e164:  "+19362917827",
  email:       "sales@bandrproduction.com",
  citations_email: "citations@bandrproduction.com",
  website:     "https://bandrproduction.com",
  founded:     1994,
  hours:       "Mon-Fri 9:00am-5:00pm CT",
  category_primary: "Machine Shop",
  category_alt:     ["Manufacturer", "Metal Fabricator", "Precision Machining Service"],
  desc_60:     "Precision CNC machining · New Waverly TX · Since 1994",
  desc_120:    "Precision CNC machining shop in New Waverly, TX. Oil & gas, aerospace, defense — since 1994.",
  desc_240:    "Precision CNC machining shop in New Waverly, Texas. Since 1994, we've served oil & gas, aerospace, defense, and industrial customers with expert machining of Inconel, Super Duplex, 17-4 PH, titanium, and other exotic alloys.",
  desc_500:    "Precision CNC machining shop in New Waverly, Texas since 1994. Serving oil & gas, aerospace, military & defense, and industrial customers with expert machining of exotic alloys including Inconel, Super Duplex 2507, 17-4 PH, titanium, and Monel. 10 CNC machines including Fadal VMC, Hwacheon lathes, Samsung SL series, and UNISIG deep-hole drilling. Family-run, straight-talk lead times, full material traceability. Emergency rig-down capability.",
};

// Directory registry — one entry per adapter. `automated: true` = we run it
// via Puppeteer. `automated: "semi"` = form works but human still finishes.
// `automated: false` = manual only, tracked here but not touched by the Worker.
const DIRECTORIES = {
  "industrynet":         { name: "IndustryNet",         url: "https://industrynet.com/marketing/add/", automated: true,  tier: 2 },
  "macraes":             { name: "MacRAE's Blue Book",  url: "https://www.macraesbluebook.com/getlisted/form1.cfm", automated: true, tier: 2 },
  "globalspec":          { name: "GlobalSpec",          url: "https://www.globalspec.com/supplier/RegisterSupplier", automated: true, tier: 2 },
  "manufacturingnet":    { name: "Manufacturing.net",   url: "https://www.manufacturing.net/", automated: true, tier: 2 },
  "productionmachining": { name: "ProductionMachining", url: "https://www.productionmachining.com/directory", automated: true, tier: 2 },
  "jobshop":             { name: "Jobshop.com",         url: "https://www.jobshop.com/",  automated: true,  tier: 2 },
  "manta":               { name: "Manta",               url: "https://www.manta.com/",     automated: true,  tier: 3 },
  "hotfrog":             { name: "Hotfrog",             url: "https://www.hotfrog.com/AddYourCompany",  automated: true,  tier: 3 },
  "brownbook":           { name: "Brownbook",           url: "https://www.brownbook.net/business/free-listing/", automated: true, tier: 3 },
  "merchantcircle":      { name: "MerchantCircle",      url: "https://www.merchantcircle.com/business/register", automated: true, tier: 3 },
  "cylex":               { name: "Cylex",               url: "https://www.us-info.com/",  automated: true,  tier: 3 },
  "showmelocal":         { name: "ShowMeLocal",         url: "https://www.showmelocal.com/business-registration.aspx", automated: true, tier: 3 },
  "localdotcom":         { name: "Local.com",           url: "https://www.local.com/",     automated: true,  tier: 3 },
};

// Simple auth check for admin endpoints
function _adminAuth(request, env) {
  const t = request.headers.get("x-admin-token") || new URL(request.url).searchParams.get("token");
  if (!env.ADMIN_TOKEN || t !== env.ADMIN_TOKEN) {
    return { ok: false, response: json({ ok: false, error: "unauthorized" }, 401) };
  }
  return { ok: true };
}

// Load or default the per-directory state record. Never returns null — a
// missing/unparsable KV entry falls back to the default shape so downstream
// renderers can safely read fields.
function _defaultCitRecord(slug) {
  return {
    directory: slug,
    tier: DIRECTORIES[slug]?.tier || 3,
    url: DIRECTORIES[slug]?.url,
    status: "pending",
    submitted_at: null,
    verified_at: null,
    live_at: null,
    submission_id: null,
    verification_url: null,
    listing_url: null,
    screenshot: null,
    notes: "",
    method: DIRECTORIES[slug]?.automated ? "automated" : "manual",
    attempts: 0,
    last_error: null,
    captcha_solves: 0,      // # of times 2Captcha was invoked
    captcha_cost: 0,        // cumulative USD spent solving CAPTCHAs
  };
}
async function _loadCit(env, slug) {
  const def = _defaultCitRecord(slug);
  if (!env.LEADS_KV) return def;
  try {
    const raw = await env.LEADS_KV.get(`citation:${slug}`);
    if (!raw) return def;
    const parsed = JSON.parse(raw);
    return { ...def, ...parsed };
  } catch {
    return def;
  }
}
async function _saveCit(env, rec) {
  if (!env.LEADS_KV) return;
  await env.LEADS_KV.put(`citation:${rec.directory}`, JSON.stringify(rec));
}

// GET /admin/citations/status?token=… — full snapshot for a UI to render
async function citationsStatus(request, env) {
  const auth = _adminAuth(request, env); if (!auth.ok) return auth.response;
  const out = [];
  for (const slug of Object.keys(DIRECTORIES)) {
    out.push(await _loadCit(env, slug));
  }
  return json({ ok: true, directories: DIRECTORIES, records: out });
}

// GET /dashboard/api/ranks — latest snapshot + list of prior dated snapshots
async function ranksForDashboard(request, env) {
  const auth = dashboardAuth(request, env);
  if (!auth.ok) return json({ ok: false, error: auth.msg || "unauthorized" }, auth.code || 401);
  if (!env.LEADS_KV) return json({ ok: false, error: "LEADS_KV not bound" });

  const latestRaw = await env.LEADS_KV.get("rank_snapshot:latest");
  let latest = null;
  if (latestRaw) { try { latest = JSON.parse(latestRaw); } catch { /* ignore */ } }

  // List dated snapshots (excluding the "latest" pointer)
  const list = await env.LEADS_KV.list({ prefix: "rank_snapshot:", limit: 60 });
  const history = list.keys
    .map(k => k.name.split(":")[1])
    .filter(d => d && d !== "latest")
    .sort()
    .reverse();

  // Compute deltas vs the most recent PRIOR dated snapshot
  let deltas = null, prevDate = null;
  if (latest) {
    const latestDate = (latest.captured_at || "").slice(0, 10);
    prevDate = history.find(d => d !== latestDate);
    if (prevDate) {
      const prevRaw = await env.LEADS_KV.get(`rank_snapshot:${prevDate}`);
      if (prevRaw) {
        try {
          const prev = JSON.parse(prevRaw);
          const prevRanks = {};
          for (const rows of Object.values(prev.groups || {})) {
            for (const r of rows) prevRanks[r.keyword] = r.rank;
          }
          deltas = [];
          for (const [group, rows] of Object.entries(latest.groups || {})) {
            for (const r of rows) {
              const was = prevRanks[r.keyword];
              const now = r.rank;
              if (was === now) continue;
              let dir;
              if (was == null && now != null) dir = "NEW";
              else if (was != null && now == null) dir = "LOST";
              else if (now < was) dir = "UP";
              else dir = "DOWN";
              deltas.push({ group, keyword: r.keyword, was: was ?? null, now: now ?? null, volume: r.volume || 0, dir });
            }
          }
          const order = { UP: 0, NEW: 1, DOWN: 2, LOST: 3 };
          deltas.sort((a, b) => (order[a.dir] - order[b.dir]) || ((b.volume || 0) - (a.volume || 0)));
        } catch { /* ignore */ }
      }
    }
  }
  return json({ ok: true, latest, history, prev_date: prevDate, deltas });
}

// POST /admin/review-requests/generate — pull recent quote-form leads from
// LEADS_KV, generate a filled review-request email (Template A) per lead.
// Returns copy-pasteable text Aaron can paste into his email client. Also
// stores per-lead "review_ask_sent_at" so we don't ask the same customer
// again within 90 days. Requires ADMIN_TOKEN.
// Query params:
//   ?days=N     — pull leads from last N days (default 30, max 400)
//   ?force=1    — ignore the 90-day dedupe and generate even if asked recently
// GET /admin/leads/list?token=X&days=N&min_score=0
// Read-only dump of every lead captured to LEADS_KV, with a per-lead
// substance score so real leads sort ahead of spam. Zero side effects.
// Uses the same heuristics the live spam filter uses in handleQuote,
// but scores rather than blocks (so historical leads captured BEFORE
// spam filters landed still get evaluated).
async function leadsList(request, env) {
  const auth = _adminAuth(request, env); if (!auth.ok) return auth.response;
  if (!env.LEADS_KV) return json({ ok: false, error: "LEADS_KV not bound" }, 400);
  const url = new URL(request.url);
  const days = Math.min(400, Math.max(1, parseInt(url.searchParams.get("days") || "400", 10)));
  const minScore = parseInt(url.searchParams.get("min_score") || "-999", 10);
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;

  const leads = [];
  let cursor = undefined;
  do {
    const list = await env.LEADS_KV.list({ prefix: "lead:", cursor, limit: 1000 });
    for (const k of list.keys) {
      const ts = parseInt(k.name.split(":")[1] || "0", 10);
      if (ts < cutoff) continue;
      const raw = await env.LEADS_KV.get(k.name);
      if (!raw) continue;
      try {
        const l = JSON.parse(raw);
        leads.push({ ...l, _key: k.name });
      } catch { /* skip malformed */ }
    }
    cursor = list.list_complete ? undefined : list.cursor;
  } while (cursor);

  const SPAM_KEYWORDS = [
    "seo services","guaranteed rankings","backlinks package","guest post",
    "increase your ranking","top ranking","search engine optimization",
    "buy real followers","casino","online casino","crypto trading","cryptocurrency",
    "bitcoin investment","forex trading","cbd oil","vashikaran","weight loss pills",
    "adult webcam","dating site","essay writing service","porn","loan offer",
    "make money fast","viagra","cialis",
  ];
  const DISPOSABLE = [
    "mailinator","guerrillamail","tempmail","10minutemail","throwaway","yopmail",
    "trashmail","sharklasers","getnada","maildrop","dispostable","fakeinbox",
    "tempinbox","tempr.email","disposable","mintemail","mailnesia","spam4.me","mailsac",
  ];
  const FREE_EMAIL = ["gmail.com","yahoo.com","hotmail.com","outlook.com","aol.com","icloud.com","proton.me","protonmail.com"];

  function score(l) {
    let s = 50;                  // baseline neutral
    const reasons = [];
    const msg = String(l.message || "");
    const msgLC = msg.toLowerCase();
    const email = String(l.email || "").toLowerCase();
    const name = String(l.name || "").trim();
    const company = String(l.company || "").trim();
    const phone = String(l.phone || "").trim();

    // Boost signals (real-lead indicators)
    if (name.split(/\s+/).length >= 2) { s += 10; reasons.push("+10 full name"); }
    if (company) { s += 15; reasons.push("+15 company"); }
    if (phone && phone.replace(/\D/g,"").length >= 10) { s += 15; reasons.push("+15 phone"); }
    if (msg.length >= 40) { s += 10; reasons.push("+10 msg≥40ch"); }
    if (msg.length >= 200) { s += 10; reasons.push("+10 msg≥200ch"); }
    // Machine-shop-relevant vocabulary in message
    const shopVocab = /\b(quote|rfq|tolerance|inconel|titanium|stainless|hastelloy|monel|super\s*duplex|17-4|4140|4340|6061|7075|machining|milling|turning|cnc|fixture|prototype|production|part|drawing|print|step|iges|dxf|dwg|first\s*article|cmm|mtr|api|aerospace|defense|oilfield|frac|wellhead|downhole|drill|drilling|deep\s*hole|thread|surface\s*finish|ppap|itar|dfars|as9100|nadcap)\b/gi;
    const vocabHits = (msg.match(shopVocab) || []).length;
    if (vocabHits >= 1) { s += 15; reasons.push(`+15 shop-vocab×${vocabHits}`); }
    if (vocabHits >= 4) { s += 10; reasons.push("+10 vocab-dense"); }
    // Business-email plus
    const emailDomain = email.split("@")[1] || "";
    if (email && !FREE_EMAIL.includes(emailDomain)) { s += 10; reasons.push("+10 biz-email"); }

    // Penalty signals (spam-lead indicators)
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) { s -= 40; reasons.push("−40 bad email"); }
    if (!name) { s -= 20; reasons.push("−20 no name"); }
    if (!msg) { s -= 20; reasons.push("−20 no message"); }
    // URL flood
    const urlCount = (msg.match(/https?:\/\/[^\s]+|www\.[^\s]+/gi) || []).length;
    if (urlCount >= 1) { s -= 15 * urlCount; reasons.push(`−${15*urlCount} url×${urlCount}`); }
    // Cyrillic/CJK dominance (near-zero legit for a TX CNC shop)
    const cyrillic = (msg.match(/[Ѐ-ӿ]/g) || []).length;
    const cjk = (msg.match(/[一-鿿]/g) || []).length;
    if (cyrillic + cjk > 5) { s -= 40; reasons.push(`−40 cyrillic/cjk×${cyrillic+cjk}`); }
    // Spam keywords
    const keywordHits = SPAM_KEYWORDS.filter(k => msgLC.includes(k));
    if (keywordHits.length) { s -= 30 * keywordHits.length; reasons.push(`−${30*keywordHits.length} spam-kw: ${keywordHits.join(",")}`); }
    // Disposable email domain
    if (DISPOSABLE.some(d => emailDomain.includes(d))) { s -= 50; reasons.push("−50 disposable-email"); }
    // Honeypot / time-gate signals (if the lead carries a _gotcha or _form_loaded_ms trigger note)
    if (l._spam_reason) { s -= 40; reasons.push(`−40 spam_reason: ${l._spam_reason}`); }
    // All-caps shouting message
    if (msg.length >= 40 && msg === msg.toUpperCase()) { s -= 15; reasons.push("−15 all-caps"); }
    // Suspicious name patterns (single word, non-alpha)
    if (name && !/\s/.test(name) && name.length < 4) { s -= 15; reasons.push("−15 tiny-name"); }
    // Message is a pure email or URL
    if (msg && /^[\s\S]{1,100}$/.test(msg) && /^(https?:\/\/|www\.|\S+@\S+)/i.test(msg.trim())) {
      s -= 25; reasons.push("−25 msg-is-link/email");
    }

    return { score: s, reasons };
  }

  const scored = leads.map((l) => {
    const { score: s, reasons } = score(l);
    const first_seen_iso = new Date(l.ts).toISOString();
    return {
      score: s,
      verdict: s >= 80 ? "REAL" : (s >= 50 ? "PROBABLY-REAL" : (s >= 20 ? "SUSPICIOUS" : "SPAM")),
      first_seen: first_seen_iso,
      first_seen_local: new Date(l.ts).toString().slice(0, 24),
      name: l.name || null,
      email: l.email || null,
      phone: l.phone || null,
      company: l.company || null,
      source: l.source || null,
      message: l.message || null,
      message_len: (l.message || "").length,
      review_ask_sent_at: l.review_ask_sent_at || null,
      attribution: l.attribution || null,
      scoring: reasons,
    };
  });

  scored.sort((a, b) => b.score - a.score || (new Date(b.first_seen) - new Date(a.first_seen)));
  const filtered = scored.filter(x => x.score >= minScore);
  const summary = {
    total: scored.length,
    real: scored.filter(x => x.verdict === "REAL").length,
    probably_real: scored.filter(x => x.verdict === "PROBABLY-REAL").length,
    suspicious: scored.filter(x => x.verdict === "SUSPICIOUS").length,
    spam: scored.filter(x => x.verdict === "SPAM").length,
    window_days: days,
    oldest: scored.length ? scored[scored.length - 1].first_seen : null,
    newest: scored.length ? scored[0].first_seen : null,
  };

  return json({ ok: true, summary, leads: filtered });
}

async function reviewRequestGenerate(request, env) {
  const auth = _adminAuth(request, env); if (!auth.ok) return auth.response;
  if (!env.LEADS_KV) return json({ ok: false, error: "LEADS_KV not bound" }, 400);
  const url = new URL(request.url);
  const days = Math.min(400, Math.max(1, parseInt(url.searchParams.get("days") || "30", 10)));
  const force = url.searchParams.get("force") === "1";
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
  const skipRecent = Date.now() - 90 * 24 * 60 * 60 * 1000;

  const leads = [];
  let cursor = undefined;
  do {
    const list = await env.LEADS_KV.list({ prefix: "lead:", cursor, limit: 1000 });
    for (const k of list.keys) {
      const ts = parseInt(k.name.split(":")[1] || "0", 10);
      if (ts < cutoff) continue;
      const raw = await env.LEADS_KV.get(k.name);
      if (!raw) continue;
      try {
        const l = JSON.parse(raw);
        if (!l || !l.email || !l.name) continue;   // need both to personalize
        if (!force && l.review_ask_sent_at && l.review_ask_sent_at > skipRecent) continue;
        leads.push({ ...l, _key: k.name });
      } catch { /* skip */ }
    }
    cursor = list.list_complete ? undefined : list.cursor;
  } while (cursor);
  leads.sort((a, b) => b.ts - a.ts);

  const gbpLink = env.GBP_REVIEW_LINK || "https://g.page/r/YOUR_GBP_REVIEW_LINK_HERE/review";
  const tpLink = "https://www.trustpilot.com/evaluate/bandrproduction.com";
  const liLink = "https://www.linkedin.com/company/br-productions/";

  const drafts = leads.map((l) => {
    const first = (l.name || "").trim().split(/\s+/)[0] || "";
    const jobHint = l.message
      ? l.message.split(/\s+/).slice(0, 12).join(" ")
      : "recent work";
    const bodyLines = [
      `Hey ${first},`,
      "",
      "Aaron here from B&R Productions.",
      "",
      `Wanted to say thanks again for the ${jobHint}${l.company ? ` — appreciate the trust from ${l.company}` : ""}.`,
      "",
      "I'll get straight to it — the way small machine shops like ours get found by new customers is reviews. Google and industry directories decide who to show first based partly on who has real customer feedback and who doesn't.",
      "",
      "If you have 60 seconds, would you drop us a short review on any of these?",
      "",
      `  • Google (biggest lever): ${gbpLink}`,
      `  • Trustpilot: ${tpLink}`,
      `  • LinkedIn: ${liLink}`,
      "",
      "Pick whichever one takes the least time. Even a single sentence helps.",
      "",
      "No pressure at all — I know your day is full. But if you're willing, it means a lot.",
      "",
      "Thanks either way, and let me know when you have the next job.",
      "",
      "Aaron Phillips",
      "B&R Productions",
      "(936) 291-7827",
      "5909 FM 1374, New Waverly TX",
    ];
    const subject = `Quick favor — 60 seconds if you have it, ${first}`;
    return {
      to: l.email,
      to_name: l.name,
      company: l.company || null,
      job_hint: jobHint,
      lead_ts: l.ts,
      lead_age_days: Math.round((Date.now() - l.ts) / (24 * 60 * 60 * 1000)),
      subject,
      body: bodyLines.join("\n"),
      _key: l._key,
    };
  });

  // Mark as asked (opportunistic; only when NOT in force mode — force runs are dry-runs from Aaron's perspective)
  if (!force) {
    for (const d of drafts) {
      const raw = await env.LEADS_KV.get(d._key);
      if (!raw) continue;
      try {
        const l = JSON.parse(raw);
        l.review_ask_sent_at = Date.now();
        await env.LEADS_KV.put(d._key, JSON.stringify(l), { expirationTtl: 60 * 60 * 24 * 400 });
      } catch { /* ignore */ }
    }
  }

  // Strip internal keys before returning
  const out = drafts.map(({ _key, ...rest }) => rest);
  return json({
    ok: true,
    days_window: days,
    force,
    count: out.length,
    gbp_link_used: gbpLink,
    note: gbpLink.includes("YOUR_GBP_REVIEW_LINK_HERE")
      ? "Set the GBP_REVIEW_LINK Worker env var to the real Google review shortlink (from GBP → 'Get more reviews' → Share review form)."
      : null,
    drafts: out,
  });
}

// GET /dashboard/api/citations — read-only, cookie-auth (piggybacks dashboard)
async function citationsForDashboard(request, env) {
  const auth = dashboardAuth(request, env);
  if (!auth.ok) return json({ ok: false, error: auth.msg || "unauthorized" }, auth.code || 401);
  const records = [];
  for (const slug of Object.keys(DIRECTORIES)) {
    const rec = await _loadCit(env, slug);
    // _loadCit never returns null now, but belt+suspenders — enforce shape
    if (rec && rec.directory) records.push(rec);
  }
  const summary = {
    total:     records.length,
    submitted: records.filter(r => r.status === "submitted").length,
    verified:  records.filter(r => r.status === "verified" || r.status === "live").length,
    live:      records.filter(r => r.status === "live").length,
    failed:    records.filter(r => r.status === "failed" || r.status === "skipped_captcha").length,
    pending:   records.filter(r => r.status === "pending").length,
  };
  return json({ ok: true, summary, records });
}

// POST /admin/citations/submit — kick off a submission run.
// Body: {"slug": "industrynet"}  OR  {"all": true} for the whole batch.
// Optional: {"sync": true}  — await the submission and return the result
//                             synchronously (useful for debugging + single
//                             submissions; adds ~30-60s to the HTTP response).
async function citationsSubmit(request, env, ctx) {
  const auth = _adminAuth(request, env); if (!auth.ok) return auth.response;
  const body = await request.json().catch(() => ({}));
  const slugs = body.all
    ? Object.entries(DIRECTORIES).filter(([, d]) => d.automated === true).map(([s]) => s)
    : (body.slug ? [body.slug] : []);
  if (!slugs.length) return json({ ok: false, error: "supply slug or all:true" }, 400);

  // Sync mode — useful for debugging. Awaits the batch and includes final
  // records in the response. Only supported for single-slug submissions
  // (batches would blow past the 30s Worker CPU limit).
  if (body.sync && slugs.length === 1) {
    try {
      await _submitOne(env, slugs[0]);
      const rec = await _loadCit(env, slugs[0]);
      return json({ ok: true, sync: true, record: rec });
    } catch (e) {
      return json({
        ok: false,
        sync: true,
        error: (e && e.message) || String(e),
        stack: (e && e.stack) || null,
      }, 500);
    }
  }

  // Async mode — fire-and-forget; caller gets an immediate response.
  ctx.waitUntil(_runBatch(env, slugs));
  return json({ ok: true, queued: slugs });
}

// GET /admin/citations/diag — one-shot diagnostic. Shows binding state
// without running any submission. Auth-gated.
async function citationsDiag(request, env) {
  const auth = _adminAuth(request, env); if (!auth.ok) return auth.response;
  const info = {
    ok: true,
    bindings: {
      LEADS_KV:        !!env.LEADS_KV,
      MYBROWSER:       !!env.MYBROWSER,
      ADMIN_TOKEN:     !!env.ADMIN_TOKEN,
      RESEND_API_KEY:  !!env.RESEND_API_KEY,
      CAPTCHA_API_KEY: !!env.CAPTCHA_API_KEY,
    },
    puppeteer: { available: false, error: null },
    kv_test: { read: null, write: null, roundtrip: null },
    directories_count: Object.keys(DIRECTORIES).length,
    twocaptcha: null,
  };
  // 2Captcha balance
  if (env.CAPTCHA_API_KEY) {
    info.twocaptcha = await _2captchaBalance(env);
  }
  // Try dynamic import of puppeteer
  try {
    const p = await import("@cloudflare/puppeteer");
    info.puppeteer.available = !!(p && (p.default || p.launch));
  } catch (e) {
    info.puppeteer.error = (e && e.message) || String(e);
  }
  // KV round-trip
  if (env.LEADS_KV) {
    const key = "diag:" + Date.now();
    try {
      await env.LEADS_KV.put(key, "hello");
      info.kv_test.write = "ok";
      info.kv_test.read = await env.LEADS_KV.get(key);
      info.kv_test.roundtrip = (info.kv_test.read === "hello");
      await env.LEADS_KV.delete(key);
    } catch (e) {
      info.kv_test.error = (e && e.message) || String(e);
    }
  }
  return json(info);
}

// POST /admin/citations/retry {"slug": "industrynet"} — reset + resubmit
async function citationsRetry(request, env, ctx) {
  const auth = _adminAuth(request, env); if (!auth.ok) return auth.response;
  const body = await request.json().catch(() => ({}));
  if (!body.slug) return json({ ok: false, error: "supply slug" }, 400);
  const rec = await _loadCit(env, body.slug);
  if (!rec) return json({ ok: false, error: "unknown directory" }, 404);
  rec.status = "pending"; rec.last_error = null;
  await _saveCit(env, rec);
  ctx.waitUntil(_runBatch(env, [body.slug]));
  return json({ ok: true, retrying: body.slug });
}

async function _runBatch(env, slugs) {
  for (const slug of slugs) {
    try { await _submitOne(env, slug); }
    catch (e) { console.log("submit failed", slug, e && e.message); }
    // Small delay between submissions so we don't hammer directories from
    // the same egress IP in rapid succession.
    await new Promise(r => setTimeout(r, 3000));
  }
}

async function _submitOne(env, slug) {
  const dir = DIRECTORIES[slug];
  if (!dir || !dir.automated) return;
  const rec = await _loadCit(env, slug);
  rec.attempts = (rec.attempts || 0) + 1;
  rec.last_error = null;

  if (!env.MYBROWSER) {
    rec.status = "failed";
    rec.last_error = "MYBROWSER binding missing — enable Browser Rendering in CF dashboard";
    await _saveCit(env, rec);
    return;
  }

  const puppeteer = await import("@cloudflare/puppeteer").catch(() => null);
  if (!puppeteer) {
    rec.status = "failed";
    rec.last_error = "@cloudflare/puppeteer not installed — run: npm i --save-dev @cloudflare/puppeteer";
    await _saveCit(env, rec);
    return;
  }

  let browser;
  try {
    browser = await puppeteer.launch(env.MYBROWSER);
    const page = await browser.newPage();
    await page.setUserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36");

    const adapter = ADAPTERS[slug];
    if (!adapter) throw new Error("no adapter for " + slug);

    // Every adapter returns {ok, submission_id?, listing_url?, notes?} OR
    // {ok:false, captcha:true, error} to skip cleanly on anti-bot walls.
    const result = await adapter(page, NAP, env, rec);

    // Screenshot proof
    if (env.CITATIONS_R2 && result.ok) {
      try {
        const png = await page.screenshot({ fullPage: false });
        const key = `${slug}-${Date.now()}.png`;
        await env.CITATIONS_R2.put(key, png, { httpMetadata: { contentType: "image/png" } });
        rec.screenshot = `r2://${key}`;
      } catch {}
    }

    if (result.ok) {
      rec.status = "submitted";
      rec.submitted_at = new Date().toISOString();
      rec.submission_id = result.submission_id || null;
      rec.listing_url   = result.listing_url || null;
      rec.notes         = result.notes || "";
    } else if (result.captcha) {
      rec.status = "skipped_captcha";
      // Preserve the specific error from _tryCaptchaOrBail — the generic
      // "manual submission" fallback hides why the solve failed.
      rec.last_error = result.error || "CAPTCHA / anti-bot wall — needs manual submission";
    } else {
      rec.status = "failed";
      rec.last_error = result.error || "adapter returned not-ok";
    }
  } catch (e) {
    rec.status = "failed";
    rec.last_error = (e && e.message) || String(e);
  } finally {
    try { if (browser) await browser.close(); } catch {}
    await _saveCit(env, rec);
  }
}

// ---- Small Puppeteer helpers used across adapters ------------------------
// Returns { type, sitekey } if a CAPTCHA is present, else null.
// Types: "recaptcha_v2" | "recaptcha_v3" | "turnstile" | "hcaptcha" | "unknown"
async function _detectCaptcha(page) {
  try {
    const info = await page.evaluate(() => {
      // Turnstile (Cloudflare)
      const t = document.querySelector('.cf-turnstile[data-sitekey], [data-sitekey][data-callback], iframe[src*="challenges.cloudflare.com"]');
      if (t) {
        const key = t.getAttribute("data-sitekey");
        if (key) return { type: "turnstile", sitekey: key };
        const iframe = document.querySelector('iframe[src*="challenges.cloudflare.com"]');
        if (iframe) {
          const m = iframe.src.match(/[?&]k=([^&]+)/);
          if (m) return { type: "turnstile", sitekey: m[1] };
        }
      }
      // reCAPTCHA v2
      const r2 = document.querySelector('.g-recaptcha[data-sitekey], [data-sitekey][data-callback]');
      if (r2) return { type: "recaptcha_v2", sitekey: r2.getAttribute("data-sitekey") };
      const rIframe = document.querySelector('iframe[src*="google.com/recaptcha"]');
      if (rIframe) {
        const m = rIframe.src.match(/[?&]k=([^&]+)/);
        if (m) return { type: "recaptcha_v2", sitekey: m[1] };
      }
      // reCAPTCHA v3 — invisible; look for grecaptcha.execute in scripts
      const scripts = Array.from(document.scripts).map(s => s.textContent).join("\n");
      const v3 = scripts.match(/grecaptcha\.execute\(['"]([^'"]+)['"]/);
      if (v3) return { type: "recaptcha_v3", sitekey: v3[1] };
      // hCaptcha
      const h = document.querySelector('.h-captcha[data-sitekey], [data-hcaptcha-widget-id]');
      if (h) return { type: "hcaptcha", sitekey: h.getAttribute("data-sitekey") };
      const hIframe = document.querySelector('iframe[src*="hcaptcha.com"]');
      if (hIframe) {
        const m = hIframe.src.match(/[?&]sitekey=([^&]+)/);
        if (m) return { type: "hcaptcha", sitekey: m[1] };
      }
      // Cloudflare Managed Challenge (bot-verification interstitial —
      // NOT a solvable widget). Detects the /cdn-cgi/challenge-platform/
      // script or the cf-browser-verification marker.
      const cfChallenge = document.querySelector('script[src*="/cdn-cgi/challenge-platform/"], #cf-content, .cf-browser-verification');
      if (cfChallenge) return { type: "cf-managed-challenge", sitekey: null };
      // No detectable widget on the page. Don't false-positive on stray
      // "captcha" text in privacy policies / footers — return null.
      return null;
    });
    return info;
  } catch { return null; }
}

// 2Captcha solver — sends CAPTCHA to the API, polls for result, returns token.
// Cost per solve (as of 2026): ~$0.001-$0.003 per Turnstile/reCAPTCHA v2/hCaptcha,
// ~$0.002 per reCAPTCHA v3. $10 credit ≈ 3000-5000 solves.
// Returns { ok: true, token, cost, solveTimeSec } OR { ok: false, error }.
async function _solveCaptcha(env, captcha, pageUrl) {
  if (!env.CAPTCHA_API_KEY) {
    return { ok: false, error: "CAPTCHA_API_KEY not set — see CITATIONS_SETUP.md" };
  }
  if (!captcha || !captcha.sitekey) {
    return { ok: false, error: `unknown captcha type: ${captcha && captcha.type}` };
  }

  // Map our types to 2Captcha method params
  const map = {
    turnstile:    { method: "turnstile",     sitekeyField: "sitekey" },
    recaptcha_v2: { method: "userrecaptcha", sitekeyField: "googlekey" },
    recaptcha_v3: { method: "userrecaptcha", sitekeyField: "googlekey", extras: { version: "v3", min_score: 0.3, action: "verify" } },
    hcaptcha:     { method: "hcaptcha",      sitekeyField: "sitekey" },
  };
  const cfg = map[captcha.type];
  if (!cfg) return { ok: false, error: `unsupported captcha type: ${captcha.type}` };

  // 1) Submit task
  const submitParams = new URLSearchParams({
    key:  env.CAPTCHA_API_KEY,
    method: cfg.method,
    [cfg.sitekeyField]: captcha.sitekey,
    pageurl: pageUrl,
    json: "1",
  });
  if (cfg.extras) for (const [k, v] of Object.entries(cfg.extras)) submitParams.set(k, String(v));

  const startTime = Date.now();
  let submitRes;
  try {
    submitRes = await fetch("https://2captcha.com/in.php?" + submitParams.toString());
  } catch (e) {
    return { ok: false, error: `2captcha submit network error: ${(e && e.message) || e}` };
  }
  const submitJson = await submitRes.json().catch(() => ({}));
  if (submitJson.status !== 1) {
    return { ok: false, error: `2captcha submit failed: ${submitJson.request || "unknown"}` };
  }
  const taskId = submitJson.request;

  // 2) Poll for result — up to 120 seconds
  const pollParams = new URLSearchParams({
    key: env.CAPTCHA_API_KEY,
    action: "get",
    id: taskId,
    json: "1",
  });
  await new Promise(r => setTimeout(r, 15000)); // Initial wait (recommended by 2Captcha)
  for (let attempt = 0; attempt < 20; attempt++) {
    const pollRes = await fetch("https://2captcha.com/res.php?" + pollParams.toString());
    const pollJson = await pollRes.json().catch(() => ({}));
    if (pollJson.status === 1 && pollJson.request) {
      const solveTimeSec = ((Date.now() - startTime) / 1000).toFixed(1);
      // Cost typically ~$0.001-$0.003 per solve; 2Captcha returns exact cost via
      // /res.php action=getbalance. We estimate here to keep the code simple.
      const costEst = captcha.type === "recaptcha_v3" ? 0.002 : 0.001;
      return {
        ok: true,
        token: pollJson.request,
        type: captcha.type,
        cost: costEst,
        solveTimeSec: Number(solveTimeSec),
      };
    }
    if (pollJson.request && pollJson.request !== "CAPCHA_NOT_READY") {
      return { ok: false, error: `2captcha error: ${pollJson.request}` };
    }
    await new Promise(r => setTimeout(r, 5000)); // Poll every 5s
  }
  return { ok: false, error: "2captcha solve timeout (>120s)" };
}

// Inject the solved token into the page + fire the appropriate callback so
// the form thinks the CAPTCHA was completed normally.
async function _injectCaptchaToken(page, captcha, token) {
  return await page.evaluate((cap, tok) => {
    try {
      if (cap.type === "turnstile") {
        // Turnstile stores its token in an <input name="cf-turnstile-response">
        // and typically fires a data-callback function on completion.
        const input = document.querySelector('[name="cf-turnstile-response"]') ||
                      document.querySelector('input[name*="turnstile"]');
        if (input) { input.value = tok; }
        const holder = document.querySelector('.cf-turnstile[data-callback]');
        if (holder) {
          const cb = holder.getAttribute("data-callback");
          if (cb && typeof window[cb] === "function") window[cb](tok);
        }
        return true;
      }
      if (cap.type === "recaptcha_v2" || cap.type === "recaptcha_v3") {
        const ta = document.querySelector('#g-recaptcha-response, textarea[name="g-recaptcha-response"]');
        if (ta) { ta.style.display = "block"; ta.value = tok; ta.innerHTML = tok; }
        // v2 sites often expect a callback set via data-callback
        const holder = document.querySelector('.g-recaptcha[data-callback]');
        if (holder) {
          const cb = holder.getAttribute("data-callback");
          if (cb && typeof window[cb] === "function") window[cb](tok);
        }
        return true;
      }
      if (cap.type === "hcaptcha") {
        const inputs = document.querySelectorAll('[name="h-captcha-response"], [name="g-recaptcha-response"]');
        inputs.forEach(i => { i.value = tok; });
        return true;
      }
      return false;
    } catch (e) { return false; }
  }, captcha, token);
}

// Called by adapters instead of `return {ok:false, captcha:true}`.
// Tries to solve; if it works, injects token and lets the adapter continue.
// Returns { proceed: true } if solved, or { proceed: false, ...bailInfo } if not.
// Also stamps rec.detected_captcha_type + rec.detected_sitekey for debugging.
async function _tryCaptchaOrBail(env, page, captcha, pageUrl, rec) {
  // Surface what we saw on the page, even if we bail
  rec.detected_captcha_type = captcha ? captcha.type : null;
  rec.detected_sitekey      = captcha ? (captcha.sitekey || null) : null;

  if (!env.CAPTCHA_API_KEY) {
    return { proceed: false, ok: false, captcha: true, error: "CAPTCHA detected; CAPTCHA_API_KEY not set" };
  }
  if (!captcha || !captcha.sitekey) {
    return { proceed: false, ok: false, captcha: true, error: `Detected CAPTCHA but couldn't extract sitekey (type=${captcha && captcha.type})` };
  }
  const solve = await _solveCaptcha(env, captcha, pageUrl);
  if (!solve.ok) {
    return { proceed: false, ok: false, captcha: true, error: `2captcha: ${solve.error}` };
  }
  const injected = await _injectCaptchaToken(page, captcha, solve.token);
  if (!injected) {
    return { proceed: false, ok: false, captcha: true, error: "solved but token injection failed" };
  }
  // Attach solve metadata to the record so we track cost + performance
  rec.captcha_solves = (rec.captcha_solves || 0) + 1;
  rec.captcha_cost   = (rec.captcha_cost   || 0) + (solve.cost || 0);
  rec.notes = ((rec.notes || "") + ` [${captcha.type} solved in ${solve.solveTimeSec}s, ~$${solve.cost}]`).trim();
  return { proceed: true };
}

async function _2captchaBalance(env) {
  if (!env.CAPTCHA_API_KEY) return { ok: false, error: "no key" };
  try {
    const r = await fetch(`https://2captcha.com/res.php?key=${env.CAPTCHA_API_KEY}&action=getbalance&json=1`);
    const j = await r.json();
    if (j.status === 1) return { ok: true, balance_usd: Number(j.request) };
    return { ok: false, error: String(j.request || "unknown") };
  } catch (e) {
    return { ok: false, error: (e && e.message) || String(e) };
  }
}
async function _safeType(page, selectors, value) {
  // Try each selector in order; type into the first one that exists.
  for (const sel of (Array.isArray(selectors) ? selectors : [selectors])) {
    try {
      const el = await page.$(sel);
      if (el) { await el.type(value, { delay: 15 }); return true; }
    } catch {}
  }
  return false;
}
async function _safeClick(page, selectors) {
  for (const sel of (Array.isArray(selectors) ? selectors : [selectors])) {
    try {
      const el = await page.$(sel);
      if (el) { await el.click(); return true; }
    } catch {}
  }
  return false;
}
async function _selectByText(page, selector, text) {
  try {
    return await page.evaluate((sel, txt) => {
      const s = document.querySelector(sel);
      if (!s) return false;
      const opt = Array.from(s.options).find(o =>
        o.text.toLowerCase().includes(txt.toLowerCase()) ||
        o.value.toLowerCase().includes(txt.toLowerCase())
      );
      if (!opt) return false;
      s.value = opt.value; s.dispatchEvent(new Event("change", { bubbles: true }));
      return true;
    }, selector, text);
  } catch { return false; }
}

// ---------------------------------------------------------------------------
// ADAPTERS — one per directory. Each returns:
//   {ok: true, submission_id?, listing_url?, notes?}
//   OR {ok: false, captcha: true} to bail on anti-bot walls
//   OR {ok: false, error: "…"}
//
// Selectors are best-guess based on typical B2B directory form patterns.
// Each adapter needs first-run verification against the live site; when a
// selector doesn't match, add the actual one and re-run. Adapters share the
// helpers above so most just need to declare their field map.
// ---------------------------------------------------------------------------
const ADAPTERS = {
  industrynet: async (page, n, env, rec) => {
    await page.goto(DIRECTORIES.industrynet.url, { waitUntil: "networkidle0", timeout: 45000 });
    { const cap = await _detectCaptcha(page); if (cap) { const s = await _tryCaptchaOrBail(env, page, cap, page.url(), rec); if (!s.proceed) return s; } }
    await _safeType(page, ['input[name="company"]', "#company"], n.name);
    await _safeType(page, ['input[name="address1"]', 'input[name="street"]'], n.street);
    await _safeType(page, ['input[name="city"]'], n.city);
    await _selectByText(page, 'select[name="state"]', n.state);
    await _safeType(page, ['input[name="zip"]', 'input[name="postal"]'], n.postal);
    await _safeType(page, ['input[name="phone"]'], n.phone);
    await _safeType(page, ['input[name="email"]'], n.citations_email);
    await _safeType(page, ['input[name="url"]', 'input[name="website"]'], n.website);
    await _safeType(page, ['textarea[name="description"]', 'textarea[name="about"]'], n.desc_500);
    const submitted = await _safeClick(page, ['button[type="submit"]', 'input[type="submit"]']);
    if (!submitted) return { ok: false, error: "submit button not found" };
    await page.waitForNetworkIdle({ timeout: 15000 }).catch(() => {});
    return { ok: true, notes: "Auto-submitted; expect email confirmation" };
  },

  macraes: async (page, n, env, rec) => {
    await page.goto(DIRECTORIES.macraes.url, { waitUntil: "networkidle0", timeout: 45000 });
    { const cap = await _detectCaptcha(page); if (cap) { const s = await _tryCaptchaOrBail(env, page, cap, page.url(), rec); if (!s.proceed) return s; } }
    await _safeType(page, ['input[name="CompanyName"]', 'input[name="company"]'], n.name);
    await _safeType(page, ['input[name="Contact"]', 'input[name="contact"]'], "B&R Productions Sales");
    await _safeType(page, ['input[name="Address"]'], n.street);
    await _safeType(page, ['input[name="City"]'], n.city);
    await _selectByText(page, 'select[name="Province"], select[name="State"]', n.state);
    await _safeType(page, ['input[name="PostalCode"]', 'input[name="Zip"]'], n.postal);
    await _safeType(page, ['input[name="Phone"]'], n.phone);
    await _safeType(page, ['input[name="Email"]'], n.citations_email);
    await _safeType(page, ['input[name="Website"]'], n.website);
    await _safeType(page, ['textarea[name="Description"]', 'textarea[name="Products"]'], n.desc_500);
    const submitted = await _safeClick(page, ['input[type="submit"]', 'button[type="submit"]']);
    if (!submitted) return { ok: false, error: "submit button not found" };
    await page.waitForNetworkIdle({ timeout: 15000 }).catch(() => {});
    return { ok: true, notes: "Auto-submitted to MacRAE's Blue Book" };
  },

  globalspec: async (page, n, env, rec) => {
    await page.goto(DIRECTORIES.globalspec.url, { waitUntil: "networkidle0", timeout: 45000 });
    { const cap = await _detectCaptcha(page); if (cap) { const s = await _tryCaptchaOrBail(env, page, cap, page.url(), rec); if (!s.proceed) return s; } }
    await _safeType(page, ['input[name="CompanyName"]', 'input[name="company"]'], n.name);
    await _safeType(page, ['input[name="StreetAddress"]', 'input[name="address"]'], n.street);
    await _safeType(page, ['input[name="City"]'], n.city);
    await _selectByText(page, 'select[name="State"]', n.state);
    await _safeType(page, ['input[name="Zip"]', 'input[name="ZipCode"]'], n.postal);
    await _safeType(page, ['input[name="Phone"]'], n.phone);
    await _safeType(page, ['input[name="Email"]'], n.citations_email);
    await _safeType(page, ['input[name="Website"]', 'input[name="Url"]'], n.website);
    await _safeType(page, ['textarea[name="Description"]'], n.desc_500);
    const submitted = await _safeClick(page, ['button[type="submit"]', 'input[type="submit"]']);
    if (!submitted) return { ok: false, error: "submit button not found" };
    return { ok: true, notes: "Auto-submitted to GlobalSpec/Engineering360" };
  },

  manufacturingnet: async (page, n, env, rec) => {
    // Manufacturing.net supplier form varies. Best-effort field map.
    await page.goto(DIRECTORIES.manufacturingnet.url + "advertise", { waitUntil: "networkidle0", timeout: 45000 });
    { const cap = await _detectCaptcha(page); if (cap) { const s = await _tryCaptchaOrBail(env, page, cap, page.url(), rec); if (!s.proceed) return s; } }
    await _safeType(page, ['input[name="company"]'], n.name);
    await _safeType(page, ['input[name="phone"]'], n.phone);
    await _safeType(page, ['input[name="email"]'], n.citations_email);
    await _safeType(page, ['input[name="website"]'], n.website);
    await _safeType(page, ['textarea[name="message"]', 'textarea[name="description"]'],
      `Please list B&R Productions in your supplier directory. ${n.desc_500}`);
    const submitted = await _safeClick(page, ['button[type="submit"]', 'input[type="submit"]']);
    if (!submitted) return { ok: false, error: "submit button not found" };
    return { ok: true, notes: "Manufacturing.net contact form; expect editorial review" };
  },

  productionmachining: async (page, n, env, rec) => {
    await page.goto(DIRECTORIES.productionmachining.url, { waitUntil: "networkidle0", timeout: 45000 });
    { const cap = await _detectCaptcha(page); if (cap) { const s = await _tryCaptchaOrBail(env, page, cap, page.url(), rec); if (!s.proceed) return s; } }
    // ProductionMachining is a Gardner Business Media property — likely
    // uses their shared directory form. Try common Gardner selectors.
    await _safeType(page, ['input[name="companyName"]', '#companyName'], n.name);
    await _safeType(page, ['input[name="address1"]'], n.street);
    await _safeType(page, ['input[name="city"]'], n.city);
    await _selectByText(page, 'select[name="state"]', n.state);
    await _safeType(page, ['input[name="zip"]'], n.postal);
    await _safeType(page, ['input[name="phone"]'], n.phone);
    await _safeType(page, ['input[name="email"]'], n.citations_email);
    await _safeType(page, ['input[name="website"]', 'input[name="url"]'], n.website);
    await _safeType(page, ['textarea[name="description"]'], n.desc_500);
    const submitted = await _safeClick(page, ['button[type="submit"]', 'input[type="submit"]']);
    if (!submitted) return { ok: false, error: "submit button not found" };
    return { ok: true, notes: "Auto-submitted to ProductionMachining directory" };
  },

  jobshop: async (page, n, env, rec) => {
    // Jobshop.com uses a "Contact Us" style form for listings.
    await page.goto(DIRECTORIES.jobshop.url + "contact", { waitUntil: "networkidle0", timeout: 45000 });
    { const cap = await _detectCaptcha(page); if (cap) { const s = await _tryCaptchaOrBail(env, page, cap, page.url(), rec); if (!s.proceed) return s; } }
    await _safeType(page, ['input[name="name"]'], "B&R Productions");
    await _safeType(page, ['input[name="company"]'], n.name);
    await _safeType(page, ['input[name="email"]'], n.citations_email);
    await _safeType(page, ['input[name="phone"]'], n.phone);
    await _safeType(page, ['textarea[name="message"]', 'textarea[name="comments"]'],
      `Please add B&R Productions to Jobshop.com. ${n.desc_500}`);
    const submitted = await _safeClick(page, ['button[type="submit"]', 'input[type="submit"]']);
    if (!submitted) return { ok: false, error: "submit button not found" };
    return { ok: true, notes: "Jobshop.com contact form; expect editorial review" };
  },

  manta: async (page, n, env, rec) => {
    // Manta requires account creation. Skip if signup wall present.
    await page.goto("https://www.manta.com/business/add-a-business", { waitUntil: "networkidle0", timeout: 45000 });
    { const cap = await _detectCaptcha(page); if (cap) { const s = await _tryCaptchaOrBail(env, page, cap, page.url(), rec); if (!s.proceed) return s; } }
    if ((await page.content()).toLowerCase().includes("sign in") ||
        (await page.content()).toLowerCase().includes("create account")) {
      return { ok: false, captcha: true, error: "Manta requires account signup — manual submit" };
    }
    await _safeType(page, ['input[name="business_name"]', 'input[name="companyName"]'], n.name);
    await _safeType(page, ['input[name="address"]'], n.street);
    await _safeType(page, ['input[name="city"]'], n.city);
    await _selectByText(page, 'select[name="state"]', n.state);
    await _safeType(page, ['input[name="zip"]'], n.postal);
    await _safeType(page, ['input[name="phone"]'], n.phone);
    await _safeType(page, ['input[name="email"]'], n.citations_email);
    await _safeType(page, ['input[name="website"]'], n.website);
    await _safeType(page, ['textarea[name="description"]'], n.desc_500);
    const submitted = await _safeClick(page, ['button[type="submit"]', 'input[type="submit"]']);
    if (!submitted) return { ok: false, error: "submit button not found" };
    return { ok: true, notes: "Auto-submitted to Manta" };
  },

  hotfrog: async (page, n, env, rec) => {
    await page.goto(DIRECTORIES.hotfrog.url, { waitUntil: "networkidle0", timeout: 45000 });
    { const cap = await _detectCaptcha(page); if (cap) { const s = await _tryCaptchaOrBail(env, page, cap, page.url(), rec); if (!s.proceed) return s; } }
    await _safeType(page, ['input[name="companyName"]', 'input[name="company_name"]'], n.name);
    await _safeType(page, ['input[name="address"]'], n.street);
    await _safeType(page, ['input[name="city"]'], n.city);
    await _selectByText(page, 'select[name="state"]', n.state);
    await _safeType(page, ['input[name="zip"]', 'input[name="postcode"]'], n.postal);
    await _safeType(page, ['input[name="phone"]'], n.phone);
    await _safeType(page, ['input[name="email"]'], n.citations_email);
    await _safeType(page, ['input[name="website"]'], n.website);
    await _safeType(page, ['textarea[name="description"]', 'textarea[name="about"]'], n.desc_500);
    const submitted = await _safeClick(page, ['button[type="submit"]']);
    if (!submitted) return { ok: false, error: "submit button not found" };
    return { ok: true, notes: "Auto-submitted to Hotfrog" };
  },

  brownbook: async (page, n, env, rec) => {
    await page.goto(DIRECTORIES.brownbook.url, { waitUntil: "networkidle0", timeout: 45000 });
    { const cap = await _detectCaptcha(page); if (cap) { const s = await _tryCaptchaOrBail(env, page, cap, page.url(), rec); if (!s.proceed) return s; } }
    await _safeType(page, ['input[name="business_name"]', 'input[name="name"]'], n.name);
    await _safeType(page, ['input[name="address"]'], n.street);
    await _safeType(page, ['input[name="city"]'], n.city);
    await _safeType(page, ['input[name="state"]'], n.state);
    await _safeType(page, ['input[name="postal"]', 'input[name="zip"]'], n.postal);
    await _safeType(page, ['input[name="phone"]'], n.phone);
    await _safeType(page, ['input[name="email"]'], n.citations_email);
    await _safeType(page, ['input[name="website"]', 'input[name="url"]'], n.website);
    await _safeType(page, ['textarea[name="description"]'], n.desc_500);
    const submitted = await _safeClick(page, ['button[type="submit"]', 'input[type="submit"]']);
    if (!submitted) return { ok: false, error: "submit button not found" };
    return { ok: true, notes: "Auto-submitted to Brownbook" };
  },

  merchantcircle: async (page, n, env, rec) => {
    await page.goto(DIRECTORIES.merchantcircle.url, { waitUntil: "networkidle0", timeout: 45000 });
    { const cap = await _detectCaptcha(page); if (cap) { const s = await _tryCaptchaOrBail(env, page, cap, page.url(), rec); if (!s.proceed) return s; } }
    if ((await page.content()).toLowerCase().includes("sign up") &&
        !(await page.$('input[name="business_name"]'))) {
      return { ok: false, captcha: true, error: "MerchantCircle requires signup — manual" };
    }
    await _safeType(page, ['input[name="business_name"]', 'input[name="company"]'], n.name);
    await _safeType(page, ['input[name="email"]'], n.citations_email);
    await _safeType(page, ['input[name="phone"]'], n.phone);
    await _safeType(page, ['input[name="address"]'], n.street);
    await _safeType(page, ['input[name="city"]'], n.city);
    await _selectByText(page, 'select[name="state"]', n.state);
    await _safeType(page, ['input[name="zip"]'], n.postal);
    await _safeType(page, ['input[name="website"]'], n.website);
    await _safeType(page, ['textarea[name="description"]'], n.desc_500);
    const submitted = await _safeClick(page, ['button[type="submit"]', 'input[type="submit"]']);
    if (!submitted) return { ok: false, error: "submit button not found" };
    return { ok: true, notes: "Auto-submitted to MerchantCircle" };
  },

  cylex: async (page, n, env, rec) => {
    await page.goto(DIRECTORIES.cylex.url, { waitUntil: "networkidle0", timeout: 45000 });
    { const cap = await _detectCaptcha(page); if (cap) { const s = await _tryCaptchaOrBail(env, page, cap, page.url(), rec); if (!s.proceed) return s; } }
    await _safeType(page, ['input[name="companyname"]', 'input[name="name"]'], n.name);
    await _safeType(page, ['input[name="street"]', 'input[name="address"]'], n.street);
    await _safeType(page, ['input[name="city"]'], n.city);
    await _safeType(page, ['input[name="state"]'], n.state);
    await _safeType(page, ['input[name="zip"]', 'input[name="postal"]'], n.postal);
    await _safeType(page, ['input[name="phone"]'], n.phone);
    await _safeType(page, ['input[name="email"]'], n.citations_email);
    await _safeType(page, ['input[name="url"]', 'input[name="website"]'], n.website);
    await _safeType(page, ['textarea[name="description"]', 'textarea[name="about"]'], n.desc_500);
    const submitted = await _safeClick(page, ['button[type="submit"]', 'input[type="submit"]']);
    if (!submitted) return { ok: false, error: "submit button not found" };
    return { ok: true, notes: "Auto-submitted to Cylex/US-Info" };
  },

  showmelocal: async (page, n, env, rec) => {
    await page.goto(DIRECTORIES.showmelocal.url, { waitUntil: "networkidle0", timeout: 45000 });
    { const cap = await _detectCaptcha(page); if (cap) { const s = await _tryCaptchaOrBail(env, page, cap, page.url(), rec); if (!s.proceed) return s; } }
    await _safeType(page, ['input[name="companyName"]', 'input[name="business_name"]'], n.name);
    await _safeType(page, ['input[name="address"]'], n.street);
    await _safeType(page, ['input[name="city"]'], n.city);
    await _selectByText(page, 'select[name="state"]', n.state);
    await _safeType(page, ['input[name="zip"]'], n.postal);
    await _safeType(page, ['input[name="phone"]'], n.phone);
    await _safeType(page, ['input[name="email"]'], n.citations_email);
    await _safeType(page, ['input[name="website"]'], n.website);
    await _safeType(page, ['textarea[name="description"]'], n.desc_500);
    const submitted = await _safeClick(page, ['button[type="submit"]', 'input[type="submit"]']);
    if (!submitted) return { ok: false, error: "submit button not found" };
    return { ok: true, notes: "Auto-submitted to ShowMeLocal" };
  },

  localdotcom: async (page, n, env, rec) => {
    await page.goto(DIRECTORIES.localdotcom.url + "add-business", { waitUntil: "networkidle0", timeout: 45000 });
    { const cap = await _detectCaptcha(page); if (cap) { const s = await _tryCaptchaOrBail(env, page, cap, page.url(), rec); if (!s.proceed) return s; } }
    await _safeType(page, ['input[name="businessName"]', 'input[name="name"]'], n.name);
    await _safeType(page, ['input[name="address"]'], n.street);
    await _safeType(page, ['input[name="city"]'], n.city);
    await _selectByText(page, 'select[name="state"]', n.state);
    await _safeType(page, ['input[name="zip"]'], n.postal);
    await _safeType(page, ['input[name="phone"]'], n.phone);
    await _safeType(page, ['input[name="email"]'], n.citations_email);
    await _safeType(page, ['input[name="website"]'], n.website);
    await _safeType(page, ['textarea[name="description"]'], n.desc_500);
    const submitted = await _safeClick(page, ['button[type="submit"]', 'input[type="submit"]']);
    if (!submitted) return { ok: false, error: "submit button not found" };
    return { ok: true, notes: "Auto-submitted to Local.com" };
  },
};

// ---------------------------------------------------------------------------
// Inbound email handler — Cloudflare Email Routing → this Worker.
// Parses the message, extracts verification links, auto-clicks them if the
// link's hostname matches a known directory pattern.
// ---------------------------------------------------------------------------
async function inboundEmail(message, env, ctx) {
  try {
    const raw = await new Response(message.raw).text();
    const from = message.from || "";
    const subject = message.headers.get("subject") || "";

    // Extract verification URLs — any absolute http(s) link
    const links = Array.from(raw.matchAll(/https?:\/\/[^\s"<>]+/g)).map(m => m[0]);

    // Only auto-click links matching a known directory's domain
    const knownHosts = Object.values(DIRECTORIES).map(d => {
      try { return new URL(d.url).hostname.replace(/^www\./, ""); } catch { return ""; }
    }).filter(Boolean);

    const clicked = [];
    for (const link of links) {
      let host = "";
      try { host = new URL(link).hostname.replace(/^www\./, ""); } catch { continue; }
      const match = knownHosts.find(h => host === h || host.endsWith("." + h));
      if (!match) continue;
      // Skip obviously non-verification links
      if (/unsubscribe|opt.?out|privacy|terms/i.test(link)) continue;
      // Only click links that look like verification/confirm URLs
      if (!/verify|confirm|activate|validate|approve|opt.?in|register/i.test(link)) continue;

      try {
        const r = await fetch(link, { method: "GET", redirect: "follow" });
        clicked.push({ link, status: r.status });
        // Attempt to update the matching directory's record
        const slug = Object.entries(DIRECTORIES).find(([, d]) => {
          try { return new URL(d.url).hostname.replace(/^www\./, "").endsWith(match); }
          catch { return false; }
        });
        if (slug && env.LEADS_KV) {
          const rec = await _loadCit(env, slug[0]);
          if (rec) {
            rec.status = "verified";
            rec.verified_at = new Date().toISOString();
            rec.verification_url = link;
            rec.notes = (rec.notes || "") + ` Auto-verified via inbound email from ${from}.`;
            await _saveCit(env, rec);
          }
        }
      } catch (e) {
        clicked.push({ link, error: (e && e.message) || String(e) });
      }
    }

    // Log the inbound email itself
    if (env.LEADS_KV) {
      const key = `email:${Date.now()}:${Math.floor(Math.random() * 1e6).toString(36)}`;
      await env.LEADS_KV.put(key, JSON.stringify({
        from, subject,
        received_at: new Date().toISOString(),
        links_found: links.length,
        auto_clicked: clicked,
      }), { expirationTtl: 60 * 60 * 24 * 90 });
    }

    // Optionally forward the raw message on to sales@ so a human sees it
    if (message.forward && env.INBOUND_FORWARD_TO) {
      await message.forward(env.INBOUND_FORWARD_TO);
    }
  } catch (e) {
    console.log("inboundEmail error", (e && e.message) || String(e));
  }
}

// ===========================================================================
// END CITATION SUBMISSION STACK
// ===========================================================================

// Legacy blog/category URLs that 404 today but still carry external
// backlinks (found via DataForSEO backlink audit). Permanent 301s to the
// closest live equivalent so that link equity isn't lost. Keyed without a
// trailing slash; matched against the path with any trailing slash
// stripped, so both /foo and /foo/ hit the same entry.
const LEGACY_REDIRECTS = {
  "/blog/the-role-of-cnc-machining-in-the-oil-and-gas-industry--why-precision-matters": "/industries/oil-gas-cnc-machining/",
  "/blog/understanding-cnc-machining--a-guide-for-the-oil---gas-industry": "/industries/oil-gas-cnc-machining/",
  "/blog/expert-insights--material-selection-for-cnc-machining-in-defense-applications": "/industries/military-defense-cnc-machining/",
  "/blog/how-to-ensure-precision-in-aerospace-cnc-machining": "/industries/aerospace-cnc-machining/",
  "/blog/custom-machined-parts--how-b-r-productions-ensures-quality-and-precision": "/",
  "/blog/comparing-cnc-machine-shops--what-sets-b-r-productions-apart": "/about-us/",
  "/aerospace": "/industries/aerospace-cnc-machining/",
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p = url.pathname;
    // Legacy-URL 301s (Phase 5 SEO fix) — run this before anything else so
    // it short-circuits both the trailing-slash canonicalizer below and the
    // static-asset lookup that would otherwise 404.
    {
      const bare = p.endsWith("/") && p !== "/" ? p.slice(0, -1) : p;
      const dest = LEGACY_REDIRECTS[bare];
      if (dest) {
        return Response.redirect(url.origin + dest + url.search, 301);
      }
    }
    // Trailing-slash canonicalization: our sitemap uses trailing slashes on
    // directory-style URLs, but Google/GA4 was seeing both /foo and /foo/ as
    // distinct pages (splits link equity + analytics). 301-redirect the
    // no-slash form to the trailing-slash form. Skip: root, API/admin paths,
    // and anything with a file extension.
    if (p !== "/" && !p.endsWith("/") && !p.startsWith("/api/") && !p.startsWith("/admin/") && !p.startsWith("/dashboard") && !p.startsWith("/cdn-cgi/") && !/\.[a-z0-9]+$/i.test(p)) {
      return Response.redirect(url.origin + p + "/" + url.search, 301);
    }
    // /robots.txt — served directly by the Worker so Cloudflare's
    // "Managed robots.txt" AI-blocking injection can't override it.
    // Aaron's AEO strategy is to WELCOME AI crawlers so we can be cited
    // by ChatGPT/Claude/Perplexity/Google AI. A single Allow rule + sitemap
    // pointer is the correct minimum.
    if (p === "/robots.txt") {
      return new Response(
        "User-agent: *\nAllow: /\n\nSitemap: https://bandrproduction.com/sitemap.xml\n",
        { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=3600" } }
      );
    }
    // Quote form endpoint
    if (p === "/api/quote") {
      if (request.method === "POST") return handleQuote(request, env, ctx);
      return json({ ok: false, error: "Method not allowed" }, 405);
    }
    // Dashboard UI + summary API
    if (p === "/dashboard" || p === "/dashboard/") return dashboardUI(request, env);
    if (p === "/dashboard/api/summary"      && request.method === "GET") return dashboardSummary(request, env);
    if (p === "/dashboard/api/gsc"          && request.method === "GET") return endpointGsc(request, env);
    if (p === "/dashboard/api/ga4"          && request.method === "GET") return endpointGa4(request, env);
    if (p === "/dashboard/api/bing"         && request.method === "GET") return endpointBing(request, env);
    if (p === "/dashboard/api/cf-analytics" && request.method === "GET") return endpointCfAnalytics(request, env);

    // ---- Citation submission stack (Phase 2) --------------------------------
    // Build marker — proves latest deploy is live. Returns build ID + git sha (if set).
    if (p === "/admin/citations/build" && request.method === "GET") {
      return json({
        ok: true,
        build_marker: "BUILD-v6-2026-08-17-heyaaronmarketing",
        deployed_at: new Date().toISOString(),
        env_git_sha: env.CF_PAGES_COMMIT_SHA || null,
      });
    }
    if (p === "/admin/citations/status" && request.method === "GET")    return citationsStatus(request, env);
    if (p === "/admin/citations/submit" && request.method === "POST")   return citationsSubmit(request, env, ctx);
    if (p === "/admin/citations/retry"  && request.method === "POST")   return citationsRetry(request, env, ctx);
    if (p === "/admin/citations/diag"   && request.method === "GET")    return citationsDiag(request, env);
    if (p === "/dashboard/api/citations" && request.method === "GET")   return citationsForDashboard(request, env);
    if (p === "/dashboard/api/ranks"     && request.method === "GET")   return ranksForDashboard(request, env);
    if (p === "/admin/review-requests/generate" && request.method === "POST") return reviewRequestGenerate(request, env);
    if (p === "/admin/leads/list"        && request.method === "GET")  return leadsList(request, env);
    if (p === "/admin/ranks/refresh"     && request.method === "POST") {
      const a = _adminAuth(request, env); if (!a.ok) return a.response;
      ctx.waitUntil((async () => {
        const snap = await fetchAndSnapshotRanks(env).catch((e) => console.log("manual snap err", e && e.message));
        console.log("manual rank snap done", snap && snap.summary);
      })());
      return json({ ok: true, queued: true, note: "snapshot running in background; check /dashboard/api/ranks in ~30-60s" });
    }
    // Log telemetry (AI bot + AI referrer + page views) — async, doesn't
    // delay the response.
    ctx.waitUntil(logTelemetry(request, env, url).catch(() => {}));
    // Fallback: serve static assets (normally handled before the Worker runs).
    return env.ASSETS.fetch(request);
  },
  async scheduled(event, env, ctx) {
    // Weekly Monday: (1) snapshot ranks first so the digest includes the new
    // deltas, (2) send the digest.
    ctx.waitUntil((async () => {
      await fetchAndSnapshotRanks(env).catch((e) => console.log("rank snapshot err", e && e.message));
      await sendWeeklyDigest(env);
    })());
  },
  // Cloudflare Email Routing → route to Worker with `email` handler.
  // Handles inbound verification emails from directory submissions —
  // parses the message, extracts URLs, auto-clicks any that match a known
  // directory hostname and look like verification links.
  async email(message, env, ctx) {
    ctx.waitUntil(inboundEmail(message, env, ctx));
  },
};
