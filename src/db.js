import Database from 'better-sqlite3';
import path from 'node:path';

const file = process.env.DATABASE_PATH || './bank.sqlite';
const db = new Database(path.resolve(file));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  full_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  kyc_type TEXT,
  kyc_hash TEXT UNIQUE,
  kyc_ciphertext TEXT,
  kyc_dob TEXT,
  kyc_verified INTEGER NOT NULL DEFAULT 0,
  kyc_verified_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL UNIQUE REFERENCES customers(id),
  account_number TEXT NOT NULL UNIQUE,
  bank_code TEXT NOT NULL,
  bank_name TEXT NOT NULL,
  balance_kobo INTEGER NOT NULL DEFAULT 1500000,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  transaction_id TEXT NOT NULL UNIQUE,
  idempotency_key TEXT UNIQUE,
  owner_account_id INTEGER NOT NULL REFERENCES accounts(id),
  sender_account_number TEXT NOT NULL,
  recipient_account_id INTEGER REFERENCES accounts(id),
  recipient_account_number TEXT NOT NULL,
  recipient_name TEXT NOT NULL,
  recipient_bank_name TEXT NOT NULL,
  amount_kobo INTEGER NOT NULL,
  status TEXT NOT NULL,
  direction TEXT NOT NULL DEFAULT 'DEBIT',
  narration TEXT,
  provider_response TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

export default db;
