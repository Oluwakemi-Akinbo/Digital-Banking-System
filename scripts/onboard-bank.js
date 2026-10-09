import 'dotenv/config';

const name = process.env.BANK_NAME; const email = process.env.BANK_EMAIL;
if (!name || !email) throw new Error('Set BANK_NAME and BANK_EMAIL before running this script.');
const base = (process.env.NIBSS_BASE_URL || 'https://nibssbyphoenix.onrender.com').replace(/\/$/, '');
const response = await fetch(`${base}/api/fintech/onboard`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ name, email }), signal: AbortSignal.timeout(20000),
});
const result = await response.json();
if (!response.ok) throw new Error(result.message || `NIBSS onboarding failed: ${response.status}`);
console.log(JSON.stringify(result, null, 2));
console.log('Store apiKey and apiSecret in a secret manager or local .env file. Do not commit them.');
