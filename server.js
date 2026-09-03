require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { nanoid, customAlphabet } = require('nanoid');
const tls = require('tls');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// Readable password generator (no ambiguous chars like 0/O, 1/l/I)
const generatePassword = customAlphabet('ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789', 10);

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------
const useSsl = process.env.DATABASE_SSL !== 'false';
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: useSsl ? { rejectUnauthorized: false } : false
});

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS clients (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE,
      password_hash TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS cards (
      id SERIAL PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      client_name TEXT,
      target_url TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await pool.query(`ALTER TABLE cards ALTER COLUMN client_name DROP NOT NULL;`);
  await pool.query(`ALTER TABLE cards ADD COLUMN IF NOT EXISTS client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE;`);
  await pool.query(`ALTER TABLE cards ADD COLUMN IF NOT EXISTS label TEXT;`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS scans (
      id SERIAL PRIMARY KEY,
      card_code TEXT NOT NULL REFERENCES cards(code) ON DELETE CASCADE,
      scanned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      user_agent TEXT,
      referrer TEXT
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sites (
      id SERIAL PRIMARY KEY,
      client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      url TEXT NOT NULL,
      label TEXT,
      last_checked_at TIMESTAMPTZ,
      last_status TEXT,
      last_status_code INTEGER,
      ssl_expires_at TIMESTAMPTZ,
      ssl_alerted_for TIMESTAMPTZ,
      consecutive_failures INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // One-time backfill: turn old free-text client_name values into real client rows.
  // Idempotent — once client_id is set on a card, it's skipped on future runs.
  await pool.query(`
    DO $$
    DECLARE r RECORD;
    DECLARE new_id INTEGER;
    BEGIN
      FOR r IN SELECT DISTINCT client_name FROM cards WHERE client_id IS NULL AND client_name IS NOT NULL LOOP
        INSERT INTO clients (name) VALUES (r.client_name) RETURNING id INTO new_id;
        UPDATE cards SET client_id = new_id WHERE client_name = r.client_name AND client_id IS NULL;
      END LOOP;
    END $$;
  `);
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 8 }
}));

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  res.redirect('/admin/login');
}
function requireClient(req, res, next) {
  if (req.session && req.session.clientId) return next();
  res.redirect('/client/login');
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function classifyDevice(ua) {
  if (!ua) return 'Neznámé';
  if (/ipad|tablet/i.test(ua)) return 'Tablet';
  if (/mobile|android|iphone/i.test(ua)) return 'Mobil';
  return 'Počítač';
}

function csvEscape(v) {
  const s = v === null || v === undefined ? '' : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
function toCsv(headers, rows) {
  const lines = [headers.map(csvEscape).join(',')];
  for (const row of rows) lines.push(row.map(csvEscape).join(','));
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Uptime/SSL checking — runs inline when a dashboard page is loaded, rather
// than on a separate scheduled job. Sites are only re-checked if their last
// check is older than SITE_CHECK_INTERVAL_MINUTES, so a normal page visit
// stays fast; only a "stale" site triggers a real network check.
// ---------------------------------------------------------------------------
function checkHttp(url) {
  return new Promise((resolve) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    fetch(url, { signal: controller.signal, redirect: 'follow' })
      .then((res) => { clearTimeout(timeout); resolve({ up: res.status < 500, status: res.status }); })
      .catch(() => { clearTimeout(timeout); resolve({ up: false, status: null }); });
  });
}

function checkSsl(hostname) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = tls.connect(443, hostname, { servername: hostname, timeout: 6000 }, () => {
      const cert = socket.getPeerCertificate();
      settled = true;
      socket.end();
      resolve(cert && cert.valid_to ? new Date(cert.valid_to) : null);
    });
    socket.on('error', () => { if (!settled) { settled = true; resolve(null); } });
    socket.on('timeout', () => { if (!settled) { settled = true; socket.destroy(); resolve(null); } });
  });
}

async function sendAlertEmail(subject, text) {
  if (!process.env.SMTP_HOST || !process.env.ALERT_EMAIL_TO) return;
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });
    await transporter.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to: process.env.ALERT_EMAIL_TO, subject, text });
  } catch (err) {
    console.error('Failed to send alert email:', err.message);
  }
}

async function checkOneSite(site) {
  let hostname;
  try { hostname = new URL(site.url).hostname; } catch { return; }

  const httpResult = await checkHttp(site.url);
  const sslExpiry = site.url.startsWith('https') ? await checkSsl(hostname) : null;

  const wasUp = site.last_status === 'up';
  const nowUp = httpResult.up;
  const daysLeft = sslExpiry ? Math.floor((sslExpiry - new Date()) / (1000 * 60 * 60 * 24)) : null;
  const alreadyAlertedForThisCert = sslExpiry && site.ssl_alerted_for && new Date(site.ssl_alerted_for).getTime() === sslExpiry.getTime();

  await pool.query(
    `UPDATE sites SET last_checked_at = now(), last_status = $1, last_status_code = $2,
     ssl_expires_at = $3, consecutive_failures = $4 WHERE id = $5`,
    [nowUp ? 'up' : 'down', httpResult.status, sslExpiry, nowUp ? 0 : (site.consecutive_failures || 0) + 1, site.id]
  );

  if (wasUp && !nowUp) {
    sendAlertEmail(
      `⚠️ Web nedostupný: ${site.client_name}`,
      `Web ${site.url} (klient ${site.client_name}) neodpovídá (status: ${httpResult.status || 'timeout'}).`
    ).catch(() => {});
  }
  if (sslExpiry && daysLeft !== null && daysLeft <= 14 && !alreadyAlertedForThisCert) {
    sendAlertEmail(
      `⏰ SSL certifikát brzy vyprší: ${site.client_name}`,
      `Certifikát pro ${site.url} (klient ${site.client_name}) vyprší za ${daysLeft} dní.`
    ).catch(() => {});
    await pool.query('UPDATE sites SET ssl_alerted_for = $1 WHERE id = $2', [sslExpiry, site.id]);
  }
}

// Called at the top of a dashboard page load. Only actually hits the network
// for sites whose last check is older than the interval — cheap on repeat visits.
async function refreshStaleSites(clientId) {
  const intervalMinutes = Number(process.env.SITE_CHECK_INTERVAL_MINUTES || 10);
  const { rows: staleSites } = await pool.query(
    `SELECT s.*, c.name AS client_name FROM sites s
     JOIN clients c ON c.id = s.client_id
     WHERE s.client_id = $1
       AND (s.last_checked_at IS NULL OR s.last_checked_at < now() - ($2 || ' minutes')::interval)`,
    [clientId, intervalMinutes]
  );
  if (!staleSites.length) return;
  await Promise.all(staleSites.map((site) => checkOneSite(site).catch((err) => console.error('Site check failed:', site.url, err.message))));
}

function renderSiteRow(site, deletable) {
  const statusBadge = !site.last_checked_at
    ? '<span class="badge" style="background:rgba(28,46,34,0.08); color:var(--ink-soft);">Čeká na první kontrolu</span>'
    : site.last_status === 'up'
      ? '<span class="badge badge-up">Běží ✅</span>'
      : '<span class="badge badge-down">Nedostupný ⚠️</span>';

  let sslLabel = '—';
  if (site.ssl_expires_at) {
    const daysLeft = Math.floor((new Date(site.ssl_expires_at) - new Date()) / (1000 * 60 * 60 * 24));
    sslLabel = daysLeft < 0
      ? '<span class="error">vypršel</span>'
      : (daysLeft <= 14 ? `<span class="error">${daysLeft} dní</span>` : `${daysLeft} dní`);
  }

  return `<tr>
    <td>${escapeHtml(site.label || 'Web')}</td>
    <td><a href="${escapeHtml(site.url)}" target="_blank" rel="noopener">${escapeHtml(site.url)}</a></td>
    <td>${statusBadge}</td>
    <td>${sslLabel}</td>
    ${deletable ? `<td><form method="POST" action="/admin/sites/${site.id}/delete" onsubmit="return confirm('Přestat sledovat tento web?');" style="margin:0;"><button type="submit" class="btn-danger-outline">Smazat</button></form></td>` : '<td></td>'}
  </tr>`;
}

// Calls the Anthropic API to draft a few reply options for a Google review.
// Requires ANTHROPIC_API_KEY to be set — this is a separate API key from
// console.anthropic.com, not a claude.ai login. Returns an array of plain-text drafts.
async function draftReviewReplies(reviewText, rating, businessName) {
  if (!process.env.ANTHROPIC_API_KEY) {
    const err = new Error('AI funkce zatím není nastavená (chybí ANTHROPIC_API_KEY).');
    err.code = 'NO_API_KEY';
    throw err;
  }

  const trimmedReview = String(reviewText || '').slice(0, 2000);
  const ratingLine = rating ? `Hodnocení: ${rating}/5 hvězdiček.` : '';

  const prompt = `Jsi asistent, který pomáhá majiteli firmy "${businessName}" odpovídat na Google recenze v češtině.
${ratingLine}
Recenze od zákazníka:
"""
${trimmedReview}
"""

Napiš přesně 3 varianty odpovědi na tuto recenzi. Odpovědi musí být:
- v češtině, přátelské a profesionální
- krátké (2-4 věty)
- přiměřené sentimentu recenze (poděkuj za pozitivní, u negativní se omluv a nabídni řešení mimo veřejnou diskuzi, bez obhajování se)
- podepsané jménem firmy na konci

Odpověz POUZE JSON polem tří řetězců, nic jiného, žádné markdown ani vysvětlení. Příklad formátu: ["odpověď 1", "odpověď 2", "odpověď 3"]`;

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': process.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 700,
      messages: [{ role: 'user', content: prompt }]
    })
  });

  if (!response.ok) {
    const bodyText = await response.text().catch(() => '');
    console.error('Anthropic API error:', response.status, bodyText);
    throw new Error('Volání AI se nepodařilo.');
  }

  const data = await response.json();
  const textBlock = (data.content || []).find((b) => b.type === 'text');
  if (!textBlock) throw new Error('AI nevrátila žádný text.');

  let drafts;
  try {
    drafts = JSON.parse(textBlock.text.trim());
  } catch {
    // Fallback if the model didn't return clean JSON: split into non-empty lines.
    drafts = textBlock.text.split('\n').map((l) => l.trim()).filter(Boolean);
  }
  if (!Array.isArray(drafts) || !drafts.length) throw new Error('Nepodařilo se zpracovat odpověď AI.');
  return drafts.slice(0, 3);
}

// ---------------------------------------------------------------------------
// Shared layout
// ---------------------------------------------------------------------------
function renderLayout(title, bodyHtml, opts = {}) {
  const logoutHref = opts.logoutHref || null;
  const brandLabel = opts.brandLabel || 'recenzePro';
  return `<!DOCTYPE html>
<html lang="cs">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Fraunces:wght@600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root { --forest:#1F3A2E; --forest-dark:#142720; --gold:#B8863B; --bg:#F0F4EC; --ink:#1C2E22; --ink-soft:#435049; --line:rgba(28,46,34,0.12); --danger:#B14B3D; }
  * { box-sizing: border-box; }
  body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--ink); margin: 0; padding: 0 0 60px; }
  .brandbar { background:#fff; border-bottom:1px solid var(--line); padding:16px 24px; display:flex; justify-content:space-between; align-items:center; margin-bottom:32px; }
  .brandbar .logo { font-family:'Fraunces',serif; font-weight:600; font-size:1.2rem; color:var(--forest-dark); }
  .brandbar .logo span { color: var(--gold); }
  .brandbar a.logout { font-size:0.85rem; color:var(--ink-soft); }
  .wrap { max-width: 960px; margin: 0 auto; padding: 0 20px; }
  .card { background: #fff; border: 1px solid var(--line); border-radius: 14px; padding: 26px; margin-bottom: 24px; }
  .top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px; }
  h1 { font-family:'Fraunces',serif; font-size: 1.5rem; margin: 0 0 4px; color: var(--forest-dark); }
  h2 { font-family:'Fraunces',serif; font-size: 1.1rem; margin: 0; color: var(--forest-dark); }
  p.lead { color: var(--ink-soft); margin: 0 0 20px; font-size: 0.92rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--line); font-size: 0.88rem; }
  th { color: var(--ink-soft); font-weight: 600; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; }
  input, select, button { font: inherit; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--line); }
  button { background: var(--forest); color: #fff; border: none; cursor: pointer; }
  button.btn-danger-outline { background:none; border:1px solid rgba(177,75,61,0.4); color:var(--danger); padding:6px 12px; font-size:0.85rem; }
  a { color: var(--forest); }
  code { background: rgba(28,46,34,0.06); padding: 2px 6px; border-radius: 4px; }
  .error { color: var(--danger); }
  .success-box { background: rgba(31,58,46,0.06); border: 1px solid var(--forest); border-radius: 10px; padding: 16px 20px; margin-bottom: 20px; }
  .stats { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 24px; }
  .stat { background: #fff; border: 1px solid var(--line); border-radius: 12px; padding: 16px 20px; min-width: 150px; flex: 1; }
  .stat .label { font-size: 0.72rem; color: var(--ink-soft); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }
  .stat .value { font-family:'Fraunces',serif; font-size: 1.6rem; color: var(--forest-dark); }
  .badge { display:inline-block; padding: 2px 9px; border-radius: 999px; font-size: 0.78rem; font-weight: 600; margin-left: 6px; }
  .badge-up { background: rgba(31,58,46,0.08); color: var(--forest); }
  .badge-down { background: rgba(177,75,61,0.08); color: var(--danger); }
  .charts-row { display:flex; gap:20px; flex-wrap:wrap; }
  .charts-row .card { flex: 1; min-width: 280px; }
  .center-card { max-width: 380px; margin: 60px auto 0; }
</style>
</head>
<body>
<div class="brandbar">
  <div class="logo">recenze<span>Pro</span> ${escapeHtml(brandLabel !== 'recenzePro' ? '· ' + brandLabel : '')}</div>
  ${logoutHref ? `<a class="logout" href="${logoutHref}">Odhlásit se</a>` : ''}
</div>
<div class="wrap">${bodyHtml}</div>
</body>
</html>`;
}

function statCard(label, value) {
  return `<div class="stat"><div class="label">${escapeHtml(label)}</div><div class="value">${value}</div></div>`;
}

function pctChangeBadge(thisMonth, lastMonth) {
  if (lastMonth === 0) {
    if (thisMonth === 0) return '';
    return `<span class="badge badge-up">nový růst</span>`;
  }
  const pct = Math.round(((thisMonth - lastMonth) / lastMonth) * 100);
  if (pct >= 0) return `<span class="badge badge-up">+${pct} % oproti minulému měsíci</span>`;
  return `<span class="badge badge-down">${pct} % oproti minulému měsíci</span>`;
}

// Renders the shared "cards + chart + device breakdown" dashboard body for a given client_id.
// opts.sitesEditable: show add/delete controls for monitored sites (admin view only)
// opts.reviewDraftEndpoint: where the AI reply-drafting form should POST to
async function renderClientDashboardBody(clientId, clientName, exportHref, opts = {}) {
  const sitesEditable = !!opts.sitesEditable;
  const reviewDraftEndpoint = opts.reviewDraftEndpoint || '/client/reviews/draft';
  const cardsResult = await pool.query(`
    SELECT c.code, c.label, c.target_url, c.created_at,
      COUNT(s.id) AS total_scans,
      COUNT(s.id) FILTER (WHERE s.scanned_at > now() - interval '7 days') AS scans_7d
    FROM cards c
    LEFT JOIN scans s ON s.card_code = c.code
    WHERE c.client_id = $1
    GROUP BY c.id
    ORDER BY c.created_at DESC
  `, [clientId]);

  const dailyResult = await pool.query(`
    SELECT to_char(date_trunc('day', s.scanned_at), 'YYYY-MM-DD') AS day, COUNT(*) AS count
    FROM scans s JOIN cards c ON c.code = s.card_code
    WHERE c.client_id = $1 AND s.scanned_at > now() - interval '30 days'
    GROUP BY 1 ORDER BY 1
  `, [clientId]);

  const monthResult = await pool.query(`
    SELECT
      COUNT(*) FILTER (WHERE s.scanned_at >= date_trunc('month', now())) AS this_month,
      COUNT(*) FILTER (WHERE s.scanned_at >= date_trunc('month', now()) - interval '1 month'
                         AND s.scanned_at < date_trunc('month', now())) AS last_month,
      COUNT(*) AS all_time
    FROM scans s JOIN cards c ON c.code = s.card_code
    WHERE c.client_id = $1
  `, [clientId]);

  const uaResult = await pool.query(`
    SELECT s.user_agent
    FROM scans s JOIN cards c ON c.code = s.card_code
    WHERE c.client_id = $1
  `, [clientId]);

  const deviceCounts = { Mobil: 0, Počítač: 0, Tablet: 0, Neznámé: 0 };
  uaResult.rows.forEach((r) => { deviceCounts[classifyDevice(r.user_agent)]++; });

  await refreshStaleSites(clientId);
  const sitesResult = await pool.query('SELECT * FROM sites WHERE client_id = $1 ORDER BY created_at', [clientId]);

  const thisMonth = Number(monthResult.rows[0].this_month);
  const lastMonth = Number(monthResult.rows[0].last_month);
  const allTime = Number(monthResult.rows[0].all_time);

  const cardRows = cardsResult.rows.map((r) => `
    <tr>
      <td>${escapeHtml(r.label || 'Kartička')}</td>
      <td><code>${escapeHtml(r.code)}</code></td>
      <td>${r.total_scans}</td>
      <td>${r.scans_7d}</td>
      ${sitesEditable ? `<td><form method="POST" action="/admin/cards/${encodeURIComponent(r.code)}/delete" onsubmit="return confirm('Smazat kartičku ' + ${JSON.stringify(r.label || 'bez označení')} + ' včetně všech jejích skenů? Tohle nejde vrátit zpět.');" style="margin:0;"><button type="submit" class="btn-danger-outline">Smazat</button></form></td>` : ''}
    </tr>
  `).join('');

  const chartLabels = JSON.stringify(dailyResult.rows.map((r) => r.day));
  const chartData = JSON.stringify(dailyResult.rows.map((r) => Number(r.count)));
  const deviceLabels = JSON.stringify(Object.keys(deviceCounts));
  const deviceData = JSON.stringify(Object.values(deviceCounts));

  return `
    <div class="top">
      <div>
        <h1>Přehled skenů — ${escapeHtml(clientName)}</h1>
        <p class="lead" style="margin:0;">Kolikrát lidé naskenovali vaše kartičky a co se dělo dál.</p>
      </div>
      <a href="${exportHref}" style="align-self:center;">Stáhnout CSV</a>
    </div>

    <div class="stats">
      ${statCard('Skeny celkem', allTime)}
      ${statCard('Tento měsíc', thisMonth + ' ' + pctChangeBadge(thisMonth, lastMonth))}
      ${statCard('Minulý měsíc', lastMonth)}
      ${statCard('Aktivních kartiček', cardsResult.rows.length)}
    </div>

    <div class="charts-row">
      <div class="card">
        <h2>Skeny za posledních 30 dní</h2>
        <p class="lead">Vidíte, jestli zájem roste, klesá, nebo je stabilní.</p>
        <canvas id="trendChart" height="140"></canvas>
      </div>
      <div class="card" style="max-width:280px;">
        <h2>Z jakého zařízení skenují</h2>
        <p class="lead">Většina lidí skenuje mobilem, tak se dá čekat.</p>
        <canvas id="deviceChart" height="200"></canvas>
      </div>
    </div>

    <div class="card">
      <h2>Vaše kartičky</h2>
      <table style="margin-top:12px;">
        <thead><tr><th>Kartička</th><th>Kód</th><th>Skeny celkem</th><th>Za 7 dní</th>${sitesEditable ? '<th></th>' : ''}</tr></thead>
        <tbody>${cardRows || `<tr><td colspan="${sitesEditable ? 5 : 4}">Zatím žádné kartičky.</td></tr>`}</tbody>
      </table>
    </div>

    <div class="card">
      <h2>Stav webu</h2>
      <p class="lead">Hlídáme, jestli web běží a jestli SSL certifikát brzy nevyprší.</p>
      <table style="margin-top:12px;">
        <thead><tr><th>Web</th><th>Adresa</th><th>Stav</th><th>SSL platnost</th><th></th></tr></thead>
        <tbody>${sitesResult.rows.map((s) => renderSiteRow(s, sitesEditable)).join('') || `<tr><td colspan="5">${sitesEditable ? 'Zatím žádný sledovaný web.' : 'Zatím nic nesledujeme.'}</td></tr>`}</tbody>
      </table>
      ${sitesEditable ? `
        <form method="POST" action="/admin/clients/${clientId}/sites" style="display:flex; gap:8px; align-items:flex-end; flex-wrap:wrap; margin-top:16px;">
          <label style="min-width:160px;">Označení <span style="font-weight:400;">(nepovinné)</span><br><input type="text" name="label" style="width:100%" placeholder="např. Hlavní web"></label>
          <label style="flex:1; min-width:220px;">URL webu<br><input type="url" name="url" required style="width:100%" placeholder="https://klientuvweb.cz"></label>
          <button type="submit">+ Přidat web ke sledování</button>
        </form>
      ` : ''}
    </div>

    <div class="card">
      <h2>Návrh odpovědi na recenzi (AI)</h2>
      <p class="lead">Vložte text recenze, kterou jste dostali, a nechte si navrhnout 3 varianty odpovědi.</p>
      <label>Text recenze<br><textarea id="reviewText" rows="4" style="width:100%; font:inherit; padding:10px 12px; border-radius:8px; border:1px solid var(--line);" placeholder="Vložte sem recenzi zákazníka..."></textarea></label>
      <div style="display:flex; gap:10px; align-items:flex-end; margin-top:10px; flex-wrap:wrap;">
        <label>Hvězdičky <span style="font-weight:400;">(nepovinné)</span><br>
          <select id="reviewRating" style="min-width:120px;">
            <option value="">—</option>
            <option value="1">1</option><option value="2">2</option><option value="3">3</option><option value="4">4</option><option value="5">5</option>
          </select>
        </label>
        <button type="button" id="draftBtn">Navrhnout odpovědi</button>
      </div>
      <div id="draftError" class="error" style="margin-top:10px; display:none;"></div>
      <div id="draftResults" style="margin-top:16px; display:flex; flex-direction:column; gap:10px;"></div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
    <script>
      new Chart(document.getElementById('trendChart'), {
        type: 'line',
        data: { labels: ${chartLabels}, datasets: [{ label: 'Skeny', data: ${chartData}, borderColor: '#1F3A2E', backgroundColor: 'rgba(31,58,46,0.1)', tension: 0.25, fill: true }] },
        options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
      });
      new Chart(document.getElementById('deviceChart'), {
        type: 'doughnut',
        data: { labels: ${deviceLabels}, datasets: [{ data: ${deviceData}, backgroundColor: ['#1F3A2E', '#B8863B', '#6b8f7a', '#c9c9c9'] }] },
        options: { plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 } } } } }
      });

      document.getElementById('draftBtn').addEventListener('click', async function () {
        var btn = this;
        var text = document.getElementById('reviewText').value.trim();
        var rating = document.getElementById('reviewRating').value;
        var errorBox = document.getElementById('draftError');
        var resultsBox = document.getElementById('draftResults');
        errorBox.style.display = 'none';
        resultsBox.innerHTML = '';
        if (!text) { errorBox.textContent = 'Vložte prosím text recenze.'; errorBox.style.display = 'block'; return; }

        btn.disabled = true;
        var original = btn.textContent;
        btn.textContent = 'Přemýšlím...';

        try {
          var res = await fetch('${reviewDraftEndpoint}', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ review_text: text, rating: rating })
          });
          var data = await res.json();
          if (!res.ok) throw new Error(data.error || 'Něco se pokazilo.');

          data.drafts.forEach(function (draft, i) {
            var box = document.createElement('div');
            box.style.cssText = 'border:1px solid var(--line); border-radius:10px; padding:14px 16px;';
            var p = document.createElement('p');
            p.style.cssText = 'margin:0 0 10px; white-space:pre-wrap; font-size:0.92rem;';
            p.textContent = draft;
            var copyBtn = document.createElement('button');
            copyBtn.type = 'button';
            copyBtn.textContent = 'Kopírovat';
            copyBtn.style.cssText = 'background:#fff; color:#1F3A2E; border:1px solid rgba(28,46,34,0.2); font-size:0.82rem; padding:6px 12px;';
            copyBtn.addEventListener('click', function () {
              navigator.clipboard.writeText(draft);
              copyBtn.textContent = 'Zkopírováno ✓';
              setTimeout(function () { copyBtn.textContent = 'Kopírovat'; }, 1500);
            });
            box.appendChild(p);
            box.appendChild(copyBtn);
            resultsBox.appendChild(box);
          });
        } catch (err) {
          errorBox.textContent = err.message || 'Něco se pokazilo.';
          errorBox.style.display = 'block';
        } finally {
          btn.disabled = false;
          btn.textContent = original;
        }
      });
    </script>
  `;
}

async function sendScansCsv(res, clientId) {
  const result = await pool.query(`
    SELECT c.label, c.code, s.scanned_at, s.user_agent, s.referrer
    FROM scans s JOIN cards c ON c.code = s.card_code
    WHERE c.client_id = $1
    ORDER BY s.scanned_at DESC
  `, [clientId]);
  const csv = toCsv(
    ['Kartička', 'Kód', 'Čas skenu', 'Zařízení', 'Referrer'],
    result.rows.map((r) => [r.label || 'Kartička', r.code, r.scanned_at.toISOString(), classifyDevice(r.user_agent), r.referrer || ''])
  );
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="skeny.csv"');
  res.send(csv);
}

// ---------------------------------------------------------------------------
// Public redirect + logging endpoint — this is what the NFC/QR card points to
// ---------------------------------------------------------------------------
app.get('/r/:code', async (req, res) => {
  const { code } = req.params;
  try {
    const result = await pool.query('SELECT * FROM cards WHERE code = $1', [code]);
    if (!result.rows.length) return res.status(404).send('Kartička nenalezena.');
    const card = result.rows[0];

    pool.query(
      'INSERT INTO scans (card_code, user_agent, referrer) VALUES ($1, $2, $3)',
      [code, req.headers['user-agent'] || null, req.headers['referer'] || null]
    ).catch((err) => console.error('Failed to log scan:', err));

    res.redirect(302, card.target_url);
  } catch (err) {
    console.error(err);
    res.status(500).send('Něco se pokazilo.');
  }
});

app.get('/', (req, res) => {
  res.send(renderLayout('recenzePro tracker', `
    <div class="card center-card">
      <h1>recenzePro tracker</h1>
      <p class="lead">Vyberte si přihlášení.</p>
      <p><a href="/admin/login">→ Přihlášení pro recenzePro (admin)</a></p>
      <p><a href="/client/login">→ Přihlášení pro klienty</a></p>
    </div>
  `));
});

// =============================================================================
// ADMIN
// =============================================================================
app.get('/admin/login', (req, res) => {
  res.send(renderLayout('Přihlášení — admin', `
    <div class="card center-card">
      <h1>Přihlášení do administrace</h1>
      <form method="POST" action="/admin/login">
        <p><input type="password" name="password" placeholder="Heslo" required style="width:100%"></p>
        <p><button type="submit">Přihlásit se</button></p>
      </form>
      ${req.query.error ? '<p class="error">Špatné heslo.</p>' : ''}
    </div>
  `));
});

app.post('/admin/login', (req, res) => {
  if (req.body.password && req.body.password === process.env.ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    return res.redirect('/admin');
  }
  res.redirect('/admin/login?error=1');
});

app.get('/admin/logout', (req, res) => { req.session.destroy(() => res.redirect('/admin/login')); });

// Overview: all clients
app.get('/admin', requireAdmin, async (req, res) => {
  const result = await pool.query(`
    SELECT cl.id, cl.name, cl.email,
      COUNT(DISTINCT c.id) AS card_count,
      COUNT(s.id) AS total_scans,
      COUNT(s.id) FILTER (WHERE s.scanned_at > now() - interval '30 days') AS scans_30d
    FROM clients cl
    LEFT JOIN cards c ON c.client_id = cl.id
    LEFT JOIN scans s ON s.card_code = c.code
    GROUP BY cl.id
    ORDER BY cl.created_at DESC
  `);

  const rows = result.rows.map((r) => `
    <tr>
      <td><a href="/admin/clients/${r.id}">${escapeHtml(r.name)}</a></td>
      <td>${escapeHtml(r.email || '—')}</td>
      <td>${r.card_count}</td>
      <td>${r.scans_30d}</td>
      <td>${r.total_scans}</td>
    </tr>
  `).join('');

  res.send(renderLayout('Přehled klientů', `
    <div class="top">
      <h1>Klienti</h1>
      <div style="display:flex; gap:10px;">
        <a href="/admin/clients/new"><button type="button">+ Přidat klienta</button></a>
        <a href="/admin/cards/new"><button type="button" style="background:#fff; color:#1F3A2E; border:1px solid rgba(28,46,34,0.2);">+ Přidat kartičku</button></a>
      </div>
    </div>
    <div class="card">
      <table>
        <thead><tr><th>Klient</th><th>E-mail</th><th>Kartičky</th><th>Skeny (30 dní)</th><th>Skeny celkem</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="5">Zatím žádní klienti.</td></tr>'}</tbody>
      </table>
    </div>
  `, { logoutHref: '/admin/logout' }));
});

// New client
app.get('/admin/clients/new', requireAdmin, (req, res) => {
  res.send(renderLayout('Nový klient', `
    <div class="card" style="max-width:480px;">
      <h1>Přidat nového klienta</h1>
      <form method="POST" action="/admin/clients">
        <p><label>Jméno firmy<br><input type="text" name="name" required style="width:100%"></label></p>
        <p><label>E-mail (pro přihlášení)<br><input type="email" name="email" required style="width:100%"></label></p>
        <p><button type="submit">Vytvořit</button></p>
      </form>
      <p><a href="/admin">&larr; zpět</a></p>
    </div>
  `, { logoutHref: '/admin/logout' }));
});

app.post('/admin/clients', requireAdmin, async (req, res) => {
  const name = (req.body.name || '').trim();
  const email = (req.body.email || '').trim().toLowerCase();
  if (!name || !email) return res.redirect('/admin/clients/new');

  const password = generatePassword();
  const hash = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      'INSERT INTO clients (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id',
      [name, email, hash]
    );
    res.send(renderLayout('Klient vytvořen', `
      <div class="card" style="max-width:480px;">
        <h1>Klient vytvořen ✓</h1>
        <div class="success-box">
          <p style="margin:0 0 8px;">Pošlete klientovi tyto přihlašovací údaje (heslo se znovu nezobrazí, ale kdykoliv jde vygenerovat nové):</p>
          <p style="margin:0;"><strong>Přihlášení:</strong> ${req.protocol}://${req.get('host')}/client/login</p>
          <p style="margin:0;"><strong>E-mail:</strong> ${escapeHtml(email)}</p>
          <p style="margin:0;"><strong>Heslo:</strong> <code>${escapeHtml(password)}</code></p>
        </div>
        <p><a href="/admin/cards/new?client_id=${result.rows[0].id}">+ Přidat kartičku pro tohoto klienta</a></p>
        <p><a href="/admin">&larr; zpět na přehled</a></p>
      </div>
    `, { logoutHref: '/admin/logout' }));
  } catch (err) {
    console.error(err);
    res.send(renderLayout('Chyba', `<div class="card"><p class="error">Tenhle e-mail už je použitý.</p><a href="/admin/clients/new">&larr; zpět</a></div>`, { logoutHref: '/admin/logout' }));
  }
});

// Client detail (admin view)
app.get('/admin/clients/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const clientResult = await pool.query('SELECT * FROM clients WHERE id = $1', [id]);
  if (!clientResult.rows.length) return res.status(404).send('Klient nenalezen.');
  const client = clientResult.rows[0];

  const body = await renderClientDashboardBody(id, client.name, `/admin/clients/${id}/export.csv`, {
    sitesEditable: true,
    reviewDraftEndpoint: `/admin/clients/${id}/reviews/draft`
  });

  res.send(renderLayout(`Klient — ${client.name}`, `
    <p><a href="/admin">&larr; zpět na přehled klientů</a></p>
    ${body}
    <div class="card">
      <div class="top" style="margin:0;">
        <h2>Správa</h2>
      </div>
      ${!client.email ? `
        <div class="success-box" style="border-color:#B8863B; background:rgba(184,134,59,0.08); margin-bottom:16px;">
          <p style="margin:0;"><strong>Tento klient ještě nemá přihlašovací údaje.</strong> Nastavte e-mail níže, heslo se vygeneruje automaticky.</p>
        </div>
      ` : `<p class="lead">E-mail pro přihlášení: <strong>${escapeHtml(client.email)}</strong></p>`}

      <form method="POST" action="/admin/clients/${client.id}/set-login" style="display:flex; gap:8px; align-items:flex-end; flex-wrap:wrap; margin-bottom:16px;">
        <label style="flex:1; min-width:220px;">E-mail pro přihlášení<br>
          <input type="email" name="email" value="${escapeHtml(client.email || '')}" required style="width:100%">
        </label>
        <button type="submit">${client.email ? 'Uložit a vygenerovat nové heslo' : 'Nastavit a vygenerovat heslo'}</button>
      </form>

      <div style="display:flex; gap:10px; flex-wrap:wrap;">
        <a href="/admin/cards/new?client_id=${client.id}"><button type="button">+ Přidat kartičku</button></a>
        <form method="POST" action="/admin/clients/${client.id}/delete" onsubmit="return confirm('Smazat klienta ${escapeHtml(client.name)} včetně všech kartiček a skenů? Tohle nejde vrátit zpět.');" style="margin:0;">
          <button type="submit" class="btn-danger-outline">Smazat klienta</button>
        </form>
      </div>
    </div>
  `, { logoutHref: '/admin/logout' }));
});

app.get('/admin/clients/:id/export.csv', requireAdmin, async (req, res) => {
  await sendScansCsv(res, req.params.id);
});

app.post('/admin/clients/:id/set-login', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const email = (req.body.email || '').trim().toLowerCase();
  if (!email) return res.redirect(`/admin/clients/${id}`);

  const password = generatePassword();
  const hash = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      'UPDATE clients SET email = $1, password_hash = $2 WHERE id = $3 RETURNING name, email',
      [email, hash, id]
    );
    if (!result.rows.length) return res.redirect('/admin');
    const client = result.rows[0];
    res.send(renderLayout('Přihlašovací údaje nastaveny', `
      <div class="card" style="max-width:480px;">
        <h1>Přihlašovací údaje nastaveny ✓</h1>
        <div class="success-box">
          <p style="margin:0;"><strong>Klient:</strong> ${escapeHtml(client.name)}</p>
          <p style="margin:0;"><strong>E-mail:</strong> ${escapeHtml(client.email)}</p>
          <p style="margin:0;"><strong>Heslo:</strong> <code>${escapeHtml(password)}</code></p>
        </div>
        <p><a href="/admin/clients/${id}">&larr; zpět na detail klienta</a></p>
      </div>
    `, { logoutHref: '/admin/logout' }));
  } catch (err) {
    console.error(err);
    res.send(renderLayout('Chyba', `<div class="card"><p class="error">Tenhle e-mail už je použitý u jiného klienta.</p><a href="/admin/clients/${id}">&larr; zpět</a></div>`, { logoutHref: '/admin/logout' }));
  }
});

app.post('/admin/clients/:id/reset-password', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const password = generatePassword();
  const hash = await bcrypt.hash(password, 10);
  const result = await pool.query('UPDATE clients SET password_hash = $1 WHERE id = $2 RETURNING name, email', [hash, id]);
  if (!result.rows.length) return res.redirect('/admin');
  const client = result.rows[0];
  res.send(renderLayout('Nové heslo', `
    <div class="card" style="max-width:480px;">
      <h1>Nové heslo vygenerováno ✓</h1>
      <div class="success-box">
        <p style="margin:0;"><strong>Klient:</strong> ${escapeHtml(client.name)}</p>
        <p style="margin:0;"><strong>E-mail:</strong> ${escapeHtml(client.email)}</p>
        <p style="margin:0;"><strong>Nové heslo:</strong> <code>${escapeHtml(password)}</code></p>
      </div>
      <p><a href="/admin/clients/${id}">&larr; zpět na detail klienta</a></p>
    </div>
  `, { logoutHref: '/admin/logout' }));
});

app.post('/admin/clients/:id/delete', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM clients WHERE id = $1', [req.params.id]);
  res.redirect('/admin');
});

// Uptime/SSL monitored sites (admin-managed)
app.post('/admin/clients/:id/sites', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const label = (req.body.label || '').trim() || null;
  const url = (req.body.url || '').trim();
  if (!url) return res.redirect(`/admin/clients/${id}`);
  try {
    await pool.query('INSERT INTO sites (client_id, url, label) VALUES ($1, $2, $3)', [id, url, label]);
  } catch (err) {
    console.error(err);
  }
  res.redirect(`/admin/clients/${id}`);
});

app.post('/admin/sites/:id/delete', requireAdmin, async (req, res) => {
  const result = await pool.query('SELECT client_id FROM sites WHERE id = $1', [req.params.id]);
  const clientId = result.rows[0]?.client_id;
  await pool.query('DELETE FROM sites WHERE id = $1', [req.params.id]);
  res.redirect(clientId ? `/admin/clients/${clientId}` : '/admin');
});

// AI review-reply drafting (admin, testing on behalf of a client)
app.post('/admin/clients/:id/reviews/draft', requireAdmin, async (req, res) => {
  try {
    const clientResult = await pool.query('SELECT name FROM clients WHERE id = $1', [req.params.id]);
    const businessName = clientResult.rows[0]?.name || 'firma';
    const drafts = await draftReviewReplies(req.body.review_text, req.body.rating, businessName);
    res.json({ drafts });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: err.message });
  }
});

// Add card (admin)
app.get('/admin/cards/new', requireAdmin, async (req, res) => {
  const clientsResult = await pool.query('SELECT id, name FROM clients ORDER BY name');
  const preselect = req.query.client_id || '';
  const options = clientsResult.rows.map((c) =>
    `<option value="${c.id}" ${String(c.id) === String(preselect) ? 'selected' : ''}>${escapeHtml(c.name)}</option>`
  ).join('');

  res.send(renderLayout('Nová kartička', `
    <div class="card" style="max-width:480px;">
      <h1>Přidat novou kartičku</h1>
      ${clientsResult.rows.length ? '' : '<p class="error">Nejdřív musíte vytvořit alespoň jednoho klienta.</p>'}
      <form method="POST" action="/admin/cards">
        <p><label>Klient<br>
          <select name="client_id" required style="width:100%">
            <option value="">— vyberte klienta —</option>
            ${options}
          </select>
        </label></p>
        <p><label>Označení kartičky <span style="font-weight:400;">(nepovinné, např. "Pult")</span><br><input type="text" name="label" style="width:100%"></label></p>
        <p><label>Cílová URL (Google recenze)<br><input type="url" name="target_url" required style="width:100%" placeholder="https://g.page/r/.../review"></label></p>
        <p><label>Vlastní kód <span style="font-weight:400;">(nepovinné)</span><br><input type="text" name="code" style="width:100%" placeholder="necháte-li prázdné, vygeneruje se samo"></label></p>
        <p><button type="submit">Uložit</button></p>
      </form>
      <p><a href="/admin">&larr; zpět</a></p>
    </div>
  `, { logoutHref: '/admin/logout' }));
});

app.post('/admin/cards', requireAdmin, async (req, res) => {
  const clientId = req.body.client_id;
  const label = (req.body.label || '').trim() || null;
  const targetUrl = (req.body.target_url || '').trim();
  const code = (req.body.code || '').trim() || nanoid(8);

  if (!clientId || !targetUrl) return res.redirect('/admin/cards/new');

  try {
    await pool.query(
      'INSERT INTO cards (code, client_id, label, target_url) VALUES ($1, $2, $3, $4)',
      [code, clientId, label, targetUrl]
    );
    res.redirect(`/admin/clients/${clientId}`);
  } catch (err) {
    console.error(err);
    res.send(renderLayout('Chyba', `<div class="card"><p class="error">Tenhle kód už existuje, zkuste jiný.</p><a href="/admin/cards/new">&larr; zpět</a></div>`, { logoutHref: '/admin/logout' }));
  }
});

app.post('/admin/cards/:code/delete', requireAdmin, async (req, res) => {
  const { code } = req.params;
  try {
    const cardResult = await pool.query('SELECT client_id FROM cards WHERE code = $1', [code]);
    const clientId = cardResult.rows[0]?.client_id;
    await pool.query('DELETE FROM cards WHERE code = $1', [code]);
    res.redirect(clientId ? `/admin/clients/${clientId}` : '/admin');
  } catch (err) {
    console.error(err);
    res.redirect('/admin');
  }
});

// =============================================================================
// CLIENT (per-company login)
// =============================================================================
app.get('/client/login', (req, res) => {
  res.send(renderLayout('Přihlášení — klienti', `
    <div class="card center-card">
      <h1>Přihlášení</h1>
      <p class="lead">Přihlaste se přihlašovacími údaji, které jste dostali od recenzePro.</p>
      <form method="POST" action="/client/login">
        <p><input type="email" name="email" placeholder="E-mail" required style="width:100%"></p>
        <p><input type="password" name="password" placeholder="Heslo" required style="width:100%"></p>
        <p><button type="submit">Přihlásit se</button></p>
      </form>
      ${req.query.error ? '<p class="error">Špatný e-mail nebo heslo.</p>' : ''}
    </div>
  `));
});

app.post('/client/login', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const password = req.body.password || '';
  try {
    const result = await pool.query('SELECT * FROM clients WHERE email = $1', [email]);
    if (!result.rows.length) return res.redirect('/client/login?error=1');
    const client = result.rows[0];
    const ok = client.password_hash && await bcrypt.compare(password, client.password_hash);
    if (!ok) return res.redirect('/client/login?error=1');
    req.session.clientId = client.id;
    req.session.clientName = client.name;
    res.redirect('/client');
  } catch (err) {
    console.error(err);
    res.redirect('/client/login?error=1');
  }
});

app.get('/client/logout', (req, res) => { req.session.destroy(() => res.redirect('/client/login')); });

app.get('/client', requireClient, async (req, res) => {
  const body = await renderClientDashboardBody(req.session.clientId, req.session.clientName, '/client/export.csv', {
    sitesEditable: false,
    reviewDraftEndpoint: '/client/reviews/draft'
  });
  res.send(renderLayout(`Přehled — ${req.session.clientName}`, body, {
    logoutHref: '/client/logout',
    brandLabel: req.session.clientName
  }));
});

app.get('/client/export.csv', requireClient, async (req, res) => {
  await sendScansCsv(res, req.session.clientId);
});

app.post('/client/reviews/draft', requireClient, async (req, res) => {
  try {
    const drafts = await draftReviewReplies(req.body.review_text, req.body.rating, req.session.clientName);
    res.json({ drafts });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
ensureSchema()
  .then(() => {
    app.listen(PORT, () => console.log(`recenzepro-tracker running on port ${PORT}`));
  })
  .catch((err) => {
    console.error('Failed to initialize database schema:', err);
    process.exit(1);
  });
