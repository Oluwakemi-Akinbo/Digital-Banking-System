import 'dotenv/config';
import express from 'express';
import { z } from 'zod';
import db from './db.js';
import nibss from './nibss.js';
import { decryptKyc, encryptKyc, hashPassword, kycDigest, signToken, verifyPassword, verifyToken } from './security.js';

const app = express();
app.use(express.json({ limit: '32kb' }));
const CustomerRegister = z.object({ email: z.string().email().max(254), full_name: z.string().trim().min(2).max(160), password: z.string().min(10).max(128) });
const Login = z.object({ email: z.string().email(), password: z.string() });
const Kyc = z.object({ kyc_id: z.string().regex(/^\d{11}$/), dob: z.string().regex(/^\d{4}-\d{2}-\d{2}$/) });
const Transfer = z.object({ to_account: z.string().regex(/^\d{10}$/), amount_naira: z.string().regex(/^(?:[1-9]\d{0,8})(?:\.\d{1,2})?$/), recipient_name_confirmed: z.literal(true), idempotency_key: z.string().min(8).max(100), narration: z.string().max(200).optional() });

const fail = (status, message) => Object.assign(new Error(message), { status });
function validate(schema, value) { const parsed = schema.safeParse(value); if (!parsed.success) throw fail(422, parsed.error.issues.map((x) => `${x.path.join('.')}: ${x.message}`).join('; ')); return parsed.data; }
function asyncRoute(fn) { return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); }
const customerById = db.prepare('SELECT * FROM customers WHERE id = ?');
const accountByCustomer = db.prepare('SELECT * FROM accounts WHERE customer_id = ?');
function auth(req, _res, next) {
  asyncRoute(async () => {
    const value = req.headers.authorization || '';
    if (!value.startsWith('Bearer ')) throw fail(401, 'Bearer token required');
    const id = await verifyToken(value.slice(7)); const customer = customerById.get(id);
    if (!customer) throw fail(401, 'Customer no longer exists');
    req.customer = customer; next();
  })(req, _res, next);
}
function accountView(a) { return { account_number: a.account_number, bank_code: a.bank_code, bank_name: a.bank_name, balance: (a.balance_kobo / 100).toFixed(2), currency: 'NGN' }; }
function txView(t) { return { transaction_id: t.transaction_id, direction: t.direction, from_account: t.sender_account_number, to_account: t.recipient_account_number, recipient_name: t.recipient_name, recipient_bank: t.recipient_bank_name, amount: (t.amount_kobo / 100).toFixed(2), currency: 'NGN', status: t.status, narration: t.narration, created_at: t.created_at }; }

app.get('/health', (_req, res) => res.json({ status: 'ok', nibss_mock_mode: process.env.NIBSS_MOCK_MODE === 'true' }));

app.post('/api/customers/register', asyncRoute(async (req, res) => {
  const data = validate(CustomerRegister, req.body); const email = data.email.toLowerCase();
  if (db.prepare('SELECT 1 FROM customers WHERE email = ?').get(email)) throw fail(409, 'Email is already registered');
  const result = db.prepare('INSERT INTO customers(email,full_name,password_hash) VALUES(?,?,?)').run(email, data.full_name, await hashPassword(data.password));
  const id = Number(result.lastInsertRowid);
  res.status(201).json({ customer_id: id, email, full_name: data.full_name, access_token: await signToken(id), token_type: 'bearer' });
}));

app.post('/api/customers/login', asyncRoute(async (req, res) => {
  const data = validate(Login, req.body); const c = db.prepare('SELECT * FROM customers WHERE email = ? COLLATE NOCASE').get(data.email);
  if (!c || !(await verifyPassword(data.password, c.password_hash))) throw fail(401, 'Invalid email or password');
  res.json({ access_token: await signToken(c.id), token_type: 'bearer' });
}));

async function onboard(type, req, res) {
  const data = validate(Kyc, req.body); const c = req.customer;
  if (c.kyc_verified) throw fail(409, 'Customer identity is already verified');
  const digest = kycDigest(type, data.kyc_id);
  if (db.prepare('SELECT 1 FROM customers WHERE kyc_hash = ?').get(digest)) throw fail(409, 'This identity is already associated with a customer');
  const identity = await nibss.validateKyc(type, data.kyc_id);
  if (identity.valid !== true) throw fail(422, 'Identity validation failed');
  const name = [identity.firstName, identity.lastName].filter(Boolean).join(' ').trim();
  if (identity.dob !== data.dob) throw fail(422, 'Date of birth did not match verified identity');
  if (name && name.toLowerCase() !== c.full_name.toLowerCase()) throw fail(422, 'Customer name did not match verified identity');
  db.prepare('UPDATE customers SET kyc_type=?,kyc_hash=?,kyc_ciphertext=?,kyc_dob=?,kyc_verified=1,kyc_verified_at=? WHERE id=?')
    .run(type, digest, encryptKyc(data.kyc_id), data.dob, new Date().toISOString(), c.id);
  res.json({ status: 'verified', kyc_type: type, verified_at: new Date().toISOString() });
}
app.post('/api/customers/onboarding/bvn', auth, asyncRoute((req, res) => onboard('BVN', req, res)));
app.post('/api/customers/onboarding/nin', auth, asyncRoute((req, res) => onboard('NIN', req, res)));

app.post('/api/accounts', auth, asyncRoute(async (req, res) => {
  const c = req.customer;
  if (!c.kyc_verified || !c.kyc_ciphertext || !c.kyc_dob) throw fail(403, 'Complete successful BVN or NIN verification before account creation');
  if (accountByCustomer.get(c.id)) throw fail(409, 'Customer already has an account');
  const provider = await nibss.createAccount({ type: c.kyc_type, id: decryptKyc(c.kyc_ciphertext), dob: c.kyc_dob, name: c.full_name });
  const number = String(provider.accountNumber || '');
  if (!/^\d{10}$/.test(number)) throw fail(502, 'NIBSS returned an invalid account number');
  const balance = Number(provider.balance ?? 15000);
  if (balance !== 15000) throw fail(502, 'NIBSS account opening balance was not ₦15,000');
  try {
    db.prepare('INSERT INTO accounts(customer_id,account_number,bank_code,bank_name,balance_kobo) VALUES(?,?,?,?,?)')
      .run(c.id, number, String(provider.bankCode || ''), String(provider.bankName || ''), 1500000);
  } catch (e) { if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') throw fail(409, 'An account already exists for this customer or account number'); throw e; }
  res.status(201).json(accountView(accountByCustomer.get(c.id)));
}));

app.get('/api/accounts/me', auth, asyncRoute(async (req, res) => {
  const a = accountByCustomer.get(req.customer.id); if (!a) throw fail(404, 'Account not found'); res.json(accountView(a));
}));

app.get('/api/accounts/me/balance', auth, asyncRoute(async (req, res) => {
  const a = accountByCustomer.get(req.customer.id); if (!a) throw fail(404, 'Account not found');
  const provider = await nibss.balance(a.account_number); const balance = Number(provider.balance);
  if (!Number.isFinite(balance)) throw fail(502, 'NIBSS returned an invalid balance');
  res.json({ account_number: a.account_number, balance: balance.toFixed(2), ledger_balance: (a.balance_kobo / 100).toFixed(2), currency: 'NGN', as_of: new Date().toISOString() });
}));

async function enquiry(number, customerId) {
  if (!/^\d{10}$/.test(number)) throw fail(422, 'Account number must contain 10 digits');
  const local = db.prepare('SELECT a.*,c.full_name FROM accounts a JOIN customers c ON c.id=a.customer_id WHERE a.account_number=?').get(number);
  if (local) return { account_number: number, account_name: local.full_name, bank_name: local.bank_name };
  const result = await nibss.nameEnquiry(number);
  if (!result.accountName) throw fail(404, 'Recipient account could not be verified');
  return { account_number: result.accountNumber || number, account_name: result.accountName, bank_name: result.bankName || 'Unknown Bank' };
}
app.get('/api/transfers/name-enquiry/:account_number', auth, asyncRoute(async (req, res) => res.json(await enquiry(req.params.account_number, req.customer.id))));

app.post('/api/transfers', auth, asyncRoute(async (req, res) => {
  const data = validate(Transfer, req.body); const sender = accountByCustomer.get(req.customer.id);
  if (!sender) throw fail(404, 'Sender account not found');
  if (sender.account_number === data.to_account) throw fail(422, 'Cannot transfer to the same account');
  const prior = db.prepare('SELECT * FROM transactions WHERE idempotency_key=?').get(data.idempotency_key);
  if (prior) { if (prior.owner_account_id !== sender.id) throw fail(409, 'Idempotency key was already used'); res.json(txView(prior)); return; }
  const recipient = await enquiry(data.to_account, req.customer.id);
  const amountKobo = Math.round(Number(data.amount_naira) * 100);
  if (!Number.isSafeInteger(amountKobo) || amountKobo <= 0) throw fail(422, 'Invalid transfer amount');
  const createPending = db.transaction(() => {
    const current = db.prepare('SELECT * FROM accounts WHERE id=?').get(sender.id);
    if (current.balance_kobo < amountKobo) throw fail(422, 'Insufficient funds');
    db.prepare('UPDATE accounts SET balance_kobo=balance_kobo-? WHERE id=?').run(amountKobo, sender.id);
    db.prepare(`INSERT INTO transactions(transaction_id,idempotency_key,owner_account_id,sender_account_number,recipient_account_number,recipient_name,recipient_bank_name,amount_kobo,status,narration)
      VALUES(?,?,?,?,?,?,?,?,'PENDING',?)`).run(`PENDING-${data.idempotency_key}`, data.idempotency_key, sender.id, sender.account_number, data.to_account, recipient.account_name, recipient.bank_name, amountKobo, data.narration || null);
  });
  try { createPending(); } catch (e) { if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') throw fail(409, 'Idempotency key was already used'); throw e; }
  const tx = db.prepare('SELECT * FROM transactions WHERE idempotency_key=?').get(data.idempotency_key);
  try {
    const provider = await nibss.transfer(sender.account_number, data.to_account, (amountKobo / 100).toFixed(2));
    const status = String(provider.status || 'PENDING').toUpperCase(); const localRecipient = db.prepare('SELECT * FROM accounts WHERE account_number=?').get(data.to_account);
    const settle = db.transaction(() => {
      db.prepare('UPDATE transactions SET transaction_id=?,status=?,provider_response=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(provider.transactionId || tx.transaction_id, status, JSON.stringify(provider), tx.id);
      if (status === 'SUCCESS' && localRecipient) {
        db.prepare('UPDATE accounts SET balance_kobo=balance_kobo+? WHERE id=?').run(amountKobo, localRecipient.id);
        db.prepare(`INSERT INTO transactions(transaction_id,owner_account_id,sender_account_number,recipient_account_id,recipient_account_number,recipient_name,recipient_bank_name,amount_kobo,status,direction,narration,provider_response)
          VALUES(?,?,?,?,?,?,?,?,'SUCCESS','CREDIT',?,?)`).run(`${provider.transactionId}-IN`, localRecipient.id, sender.account_number, localRecipient.id, data.to_account, recipient.account_name, recipient.bank_name, amountKobo, data.narration || null, JSON.stringify(provider));
      }
      if (['FAILED', 'REJECTED'].includes(status)) db.prepare('UPDATE accounts SET balance_kobo=balance_kobo+? WHERE id=?').run(amountKobo, sender.id);
    });
    settle();
  } catch (e) {
    if (e.status) {
      const rollback = db.transaction(() => {
        db.prepare('UPDATE accounts SET balance_kobo=balance_kobo+? WHERE id=?').run(amountKobo, sender.id);
        db.prepare("UPDATE transactions SET status='FAILED',provider_response=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(JSON.stringify({ error: e.message }), tx.id);
      }); rollback(); throw e;
    }
    db.prepare('UPDATE transactions SET provider_response=? WHERE id=?').run(JSON.stringify({ error: 'Provider outcome uncertain; query status before retrying' }), tx.id);
  }
  res.status(202).json(txView(db.prepare('SELECT * FROM transactions WHERE id=?').get(tx.id)));
}));

app.get('/api/transfers/:transaction_id', auth, asyncRoute(async (req, res) => {
  let tx = db.prepare(`SELECT t.* FROM transactions t JOIN accounts a ON a.id=t.owner_account_id WHERE t.transaction_id=? AND a.customer_id=?`).get(req.params.transaction_id, req.customer.id);
  if (!tx) throw fail(404, 'Transaction not found');
  if (tx.status === 'PENDING' && !tx.transaction_id.startsWith('PENDING-')) {
    const provider = await nibss.transactionStatus(tx.transaction_id); const status = String(provider.status || tx.status).toUpperCase();
    if (['SUCCESS', 'FAILED', 'REJECTED'].includes(status)) {
      const settle = db.transaction(() => {
        db.prepare('UPDATE transactions SET status=?,provider_response=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(status, JSON.stringify(provider), tx.id);
        if (['FAILED', 'REJECTED'].includes(status)) db.prepare('UPDATE accounts SET balance_kobo=balance_kobo+? WHERE id=?').run(tx.amount_kobo, tx.owner_account_id);
      }); settle();
    }
    tx = db.prepare('SELECT * FROM transactions WHERE id=?').get(tx.id);
  }
  res.json(txView(tx));
}));

app.get('/api/transactions', auth, asyncRoute(async (req, res) => {
  const limit = Number(req.query.limit || 50); const offset = Number(req.query.offset || 0);
  if (!Number.isInteger(limit) || limit < 1 || limit > 100 || !Number.isInteger(offset) || offset < 0) throw fail(422, 'limit must be 1-100 and offset cannot be negative');
  const account = accountByCustomer.get(req.customer.id); if (!account) throw fail(404, 'Account not found');
  const items = db.prepare('SELECT * FROM transactions WHERE owner_account_id=? ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?').all(account.id, limit, offset).map(txView);
  res.json({ items, limit, offset });
}));

app.post('/api/dev/mock-identities', (req, res, next) => {
  try {
    if (process.env.NIBSS_MOCK_MODE !== 'true' || !process.env.BOOTSTRAP_ADMIN_KEY || req.get('X-Admin-Key') !== process.env.BOOTSTRAP_ADMIN_KEY) throw fail(404, 'Not found');
    const data = validate(z.object({ kyc_type: z.enum(['BVN', 'NIN']), kyc_id: z.string().regex(/^\d{11}$/), first_name: z.string().min(1).max(80), last_name: z.string().min(1).max(80), dob: z.string().regex(/^\d{4}-\d{2}-\d{2}$/) }), req.body);
    nibss.seedIdentity({ type: data.kyc_type, id: data.kyc_id, first: data.first_name, last: data.last_name, dob: data.dob });
    res.status(201).json({ status: 'seeded', kyc_type: data.kyc_type, kyc_id: `********${data.kyc_id.slice(-3)}` });
  } catch (error) { next(error); }
});

app.use((err, _req, res, _next) => {
  if (res.headersSent) return;
  const status = Number(err.status) || (String(err.code || '').startsWith('SQLITE_CONSTRAINT') ? 409 : 500);
  res.status(status).json({ detail: status === 500 ? 'Internal server error' : err.message });
});

const port = Number(process.env.PORT || 8000);
app.listen(port, () => console.log(`${process.env.APP_NAME || 'Digital Banking Backend'} listening on :${port}`));
