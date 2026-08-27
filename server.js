require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const { nanoid } = require('nanoid');

const app = express();
const PORT = process.env.PORT || 3000;

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
    CREATE TABLE IF NOT EXISTS cards (
      id SERIAL PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      client_name TEXT NOT NULL,
      target_url TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scans (
      id SERIAL PRIMARY KEY,
      card_code TEXT NOT NULL REFERENCES cards(code) ON DELETE CASCADE,
      scanned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      user_agent TEXT,
      referrer TEXT
    );
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

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function renderLayout(title, bodyHtml) {
  return `<!DOCTYPE html>
<html lang="cs">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: system-ui, sans-serif; background: #F0F4EC; color: #1C2E22; margin: 0; padding: 40px 20px; }
  .card { background: #fff; border: 1px solid rgba(28,46,34,0.12); border-radius: 14px; padding: 28px; max-width: 900px; margin: 0 auto 24px; }
  .top { display: flex; justify-content: space-between; align-items: center; max-width: 900px; margin: 0 auto 16px; }
  h1 { font-size: 1.5rem; margin: 0 0 4px; }
  h2 { font-size: 1.1rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid rgba(28,46,34,0.1); font-size: 0.9rem; }
  input, button { font: inherit; padding: 10px 12px; border-radius: 8px; border: 1px solid rgba(28,46,34,0.2); }
  button { background: #1F3A2E; color: #fff; border: none; cursor: pointer; }
  a { color: #1F3A2E; }
  code { background: rgba(28,46,34,0.06); padding: 2px 6px; border-radius: 4px; }
  .error { color: #B14B3D; }
</style>
</head>
<body>${bodyHtml}</body>
</html>`;
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

    // Log without blocking the redirect
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

app.get('/', (req, res) => res.redirect('/admin/login'));

// ---------------------------------------------------------------------------
// Admin: login
// ---------------------------------------------------------------------------
app.get('/admin/login', (req, res) => {
  res.send(renderLayout('Přihlášení', `
    <div class="card" style="max-width:380px;">
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

app.get('/admin/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/admin/login'));
});

// ---------------------------------------------------------------------------
// Admin: dashboard
// ---------------------------------------------------------------------------
app.get('/admin', requireAdmin, async (req, res) => {
  const cardsResult = await pool.query(`
    SELECT c.code, c.client_name, c.target_url, c.created_at,
      COUNT(s.id) AS total_scans,
      COUNT(s.id) FILTER (WHERE s.scanned_at > now() - interval '7 days') AS scans_7d
    FROM cards c
    LEFT JOIN scans s ON s.card_code = c.code
    GROUP BY c.code, c.client_name, c.target_url, c.created_at
    ORDER BY c.created_at DESC
  `);

  const dailyResult = await pool.query(`
    SELECT to_char(date_trunc('day', scanned_at), 'YYYY-MM-DD') AS day, COUNT(*) AS count
    FROM scans
    WHERE scanned_at > now() - interval '30 days'
    GROUP BY 1
    ORDER BY 1
  `);

  const rows = cardsResult.rows.map((r) => `
    <tr>
      <td>${escapeHtml(r.client_name)}</td>
      <td><code>/r/${escapeHtml(r.code)}</code></td>
      <td>${r.total_scans}</td>
      <td>${r.scans_7d}</td>
      <td><a href="${escapeHtml(r.target_url)}" target="_blank" rel="noopener">otevřít cíl</a></td>
      <td>
        <form method="POST" action="/admin/cards/${encodeURIComponent(r.code)}/delete" onsubmit="return confirm('Smazat kartičku ' + ${JSON.stringify(r.client_name)} + ' včetně všech jejích skenů? Tohle nejde vrátit zpět.');" style="margin:0;">
          <button type="submit" style="background:none;border:1px solid rgba(177,75,61,0.4);color:#B14B3D;padding:6px 12px;font-size:0.85rem;">Smazat</button>
        </form>
      </td>
    </tr>
  `).join('');

  const chartLabels = JSON.stringify(dailyResult.rows.map((r) => r.day));
  const chartData = JSON.stringify(dailyResult.rows.map((r) => Number(r.count)));

  res.send(renderLayout('Přehled skenů', `
    <div class="top"><h1>Přehled NFC/QR kartiček</h1><a href="/admin/logout">Odhlásit se</a></div>

    <div class="card">
      <h2 style="margin-top:0;">Skeny za posledních 30 dní</h2>
      <canvas id="chart" height="80"></canvas>
    </div>

    <div class="card">
      <div class="top" style="margin:0 0 12px;">
        <h2 style="margin:0;">Kartičky</h2>
        <a href="/admin/cards/new">+ Přidat kartičku</a>
      </div>
      <table>
        <thead><tr><th>Klient</th><th>Kód</th><th>Skeny celkem</th><th>Za 7 dní</th><th>Cíl</th><th></th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6">Zatím žádné kartičky.</td></tr>'}</tbody>
      </table>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
    <script>
      new Chart(document.getElementById('chart'), {
        type: 'line',
        data: {
          labels: ${chartLabels},
          datasets: [{
            label: 'Skeny',
            data: ${chartData},
            borderColor: '#1F3A2E',
            backgroundColor: 'rgba(31,58,46,0.1)',
            tension: 0.25,
            fill: true
          }]
        },
        options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
      });
    </script>
  `));
});

// ---------------------------------------------------------------------------
// Admin: add a new card
// ---------------------------------------------------------------------------
app.get('/admin/cards/new', requireAdmin, (req, res) => {
  res.send(renderLayout('Nová kartička', `
    <div class="card" style="max-width:480px;">
      <h1>Přidat novou kartičku</h1>
      <form method="POST" action="/admin/cards">
        <p><label>Jméno klienta<br><input type="text" name="client_name" required style="width:100%"></label></p>
        <p><label>Cílová URL (Google recenze)<br><input type="url" name="target_url" required style="width:100%" placeholder="https://g.page/r/.../review"></label></p>
        <p><label>Vlastní kód <span style="font-weight:400;">(nepovinné)</span><br><input type="text" name="code" style="width:100%" placeholder="necháte-li prázdné, vygeneruje se samo"></label></p>
        <p><button type="submit">Uložit</button></p>
      </form>
      <p><a href="/admin">&larr; zpět na přehled</a></p>
    </div>
  `));
});

app.post('/admin/cards', requireAdmin, async (req, res) => {
  const clientName = (req.body.client_name || '').trim();
  const targetUrl = (req.body.target_url || '').trim();
  const code = (req.body.code || '').trim() || nanoid(8);

  if (!clientName || !targetUrl) return res.redirect('/admin/cards/new');

  try {
    await pool.query(
      'INSERT INTO cards (code, client_name, target_url) VALUES ($1, $2, $3)',
      [code, clientName, targetUrl]
    );
    res.redirect('/admin');
  } catch (err) {
    console.error(err);
    res.send(renderLayout('Chyba', `
      <div class="card">
        <p class="error">Tenhle kód už existuje, zkuste jiný.</p>
        <a href="/admin/cards/new">&larr; zpět</a>
      </div>
    `));
  }
});

app.post('/admin/cards/:code/delete', requireAdmin, async (req, res) => {
  const { code } = req.params;
  try {
    // ON DELETE CASCADE on scans.card_code takes care of the scan rows too
    await pool.query('DELETE FROM cards WHERE code = $1', [code]);
    res.redirect('/admin');
  } catch (err) {
    console.error(err);
    res.redirect('/admin');
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
