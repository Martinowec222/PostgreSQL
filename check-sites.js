// Run periodically as a Render Cron Job: `node check-sites.js`
// Checks every monitored site's HTTP status and SSL certificate expiry,
// writes the result to the `sites` table, and (if SMTP is configured)
// emails an alert on a down transition or an expiring certificate.
require('dotenv').config();
const { Pool } = require('pg');
const tls = require('tls');
const nodemailer = require('nodemailer');

const useSsl = process.env.DATABASE_SSL !== 'false';
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: useSsl ? { rejectUnauthorized: false } : false
});

async function ensureSitesTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sites (
      id SERIAL PRIMARY KEY,
      client_id INTEGER NOT NULL,
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
}

function checkHttp(url) {
  return new Promise((resolve) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    fetch(url, { signal: controller.signal, redirect: 'follow' })
      .then((res) => { clearTimeout(timeout); resolve({ up: res.status < 500, status: res.status }); })
      .catch(() => { clearTimeout(timeout); resolve({ up: false, status: null }); });
  });
}

function checkSsl(hostname) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = tls.connect(443, hostname, { servername: hostname, timeout: 8000 }, () => {
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
    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: process.env.ALERT_EMAIL_TO,
      subject,
      text
    });
  } catch (err) {
    console.error('Failed to send alert email:', err.message);
  }
}

async function run() {
  await ensureSitesTable();

  const { rows: sites } = await pool.query(`
    SELECT s.*, c.name AS client_name
    FROM sites s
    JOIN clients c ON c.id = s.client_id
  `);

  console.log(`Checking ${sites.length} site(s)...`);

  for (const site of sites) {
    let hostname;
    try {
      hostname = new URL(site.url).hostname;
    } catch {
      console.error(`Skipping invalid URL for site ${site.id}: ${site.url}`);
      continue;
    }

    const httpResult = await checkHttp(site.url);
    const sslExpiry = site.url.startsWith('https') ? await checkSsl(hostname) : null;

    const wasUp = site.last_status === 'up';
    const nowUp = httpResult.up;

    let sslAlertedFor = site.ssl_alerted_for;
    const daysLeft = sslExpiry ? Math.floor((sslExpiry - new Date()) / (1000 * 60 * 60 * 24)) : null;
    const alreadyAlertedForThisCert = sslExpiry && sslAlertedFor && new Date(sslAlertedFor).getTime() === sslExpiry.getTime();

    await pool.query(
      `UPDATE sites
       SET last_checked_at = now(), last_status = $1, last_status_code = $2,
           ssl_expires_at = $3, consecutive_failures = $4
       WHERE id = $5`,
      [nowUp ? 'up' : 'down', httpResult.status, sslExpiry, nowUp ? 0 : (site.consecutive_failures || 0) + 1, site.id]
    );

    if (wasUp && !nowUp) {
      console.log(`ALERT: ${site.url} (${site.client_name}) is down.`);
      await sendAlertEmail(
        `⚠️ Web nedostupný: ${site.client_name}`,
        `Web ${site.url} (klient ${site.client_name}) neodpovídá (status: ${httpResult.status || 'timeout'}).`
      );
    }

    if (sslExpiry && daysLeft !== null && daysLeft <= 14 && !alreadyAlertedForThisCert) {
      console.log(`ALERT: SSL for ${site.url} (${site.client_name}) expires in ${daysLeft} days.`);
      await sendAlertEmail(
        `⏰ SSL certifikát brzy vyprší: ${site.client_name}`,
        `Certifikát pro ${site.url} (klient ${site.client_name}) vyprší za ${daysLeft} dní (${sslExpiry.toISOString()}).`
      );
      await pool.query('UPDATE sites SET ssl_alerted_for = $1 WHERE id = $2', [sslExpiry, site.id]);
    }
  }

  await pool.end();
  console.log('Done.');
}

run().catch((err) => {
  console.error('check-sites.js failed:', err);
  process.exit(1);
});
