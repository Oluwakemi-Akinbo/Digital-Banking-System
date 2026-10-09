import crypto from 'node:crypto';

class NibssClient {
  token = null;
  tokenExpiry = 0;
  identities = new Map();
  accounts = new Map();
  transactions = new Map();

  async request(method, route, body, auth = true) {
    const headers = { 'content-type': 'application/json' };
    if (auth) headers.authorization = `Bearer ${await this.getToken()}`;
    let response;
    try {
      response = await fetch(`${(process.env.NIBSS_BASE_URL || 'https://nibssbyphoenix.onrender.com').replace(/\/$/, '')}${route}`, {
        method, headers, body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(Number(process.env.NIBSS_TIMEOUT_MS || 15000)),
      });
    } catch {
      const error = new Error('NIBSS service is unavailable'); error.status = 502; throw error;
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(data.message || 'NIBSS request failed');
      error.status = response.status === 409 ? 409 : 502; throw error;
    }
    return data;
  }

  async getToken() {
    if (this.token && this.tokenExpiry > Date.now() + 30000) return this.token;
    const apiKey = process.env.NIBSS_API_KEY; const apiSecret = process.env.NIBSS_API_SECRET;
    if (!apiKey || !apiSecret) { const e = new Error('Configure NIBSS_API_KEY and NIBSS_API_SECRET'); e.status = 503; throw e; }
    const result = await this.request('POST', '/api/auth/token', { apiKey, apiSecret }, false);
    if (!result.token) { const e = new Error('NIBSS login response did not include a token'); e.status = 502; throw e; }
    this.token = result.token; this.tokenExpiry = Date.now() + 3500000;
    return this.token;
  }

  async validateKyc(type, id) {
    if (process.env.NIBSS_MOCK_MODE === 'true') {
      const record = this.identities.get(`${type}:${id}`);
      if (!record) { const e = new Error(`${type} was not found or could not be verified`); e.status = 422; throw e; }
      return { valid: true, ...record };
    }
    return this.request('POST', `/api/validate${type[0]}${type.slice(1).toLowerCase()}`, { [type.toLowerCase()]: id });
  }

  async createAccount({ type, id, dob, name }) {
    if (process.env.NIBSS_MOCK_MODE === 'true') {
      if (!this.identities.has(`${type}:${id}`)) { const e = new Error('KYC identity is not seeded in mock NIBSS'); e.status = 422; throw e; }
      let number; do { number = String(1000000000 + crypto.randomInt(0, 9000000000)); } while (this.accounts.has(number));
      const result = { accountNumber: number, bankCode: '999', bankName: 'Phoenix Mock Bank', accountName: name, balance: 15000 };
      this.accounts.set(number, result); return result;
    }
    return this.request('POST', '/api/account/create', { kycType: type.toLowerCase(), kycID: id, dob });
  }

  async nameEnquiry(number) {
    if (process.env.NIBSS_MOCK_MODE === 'true') {
      const account = this.accounts.get(number);
      return account ? { accountNumber: number, accountName: account.accountName, bankName: account.bankName } : { accountNumber: number, accountName: `Test Recipient ${number.slice(-4)}`, bankName: 'External Test Bank' };
    }
    return this.request('GET', `/api/account/name-enquiry/${number}`);
  }

  async balance(number) {
    if (process.env.NIBSS_MOCK_MODE === 'true') {
      const account = this.accounts.get(number);
      if (!account) { const e = new Error('Account not found by mock NIBSS'); e.status = 404; throw e; }
      return { accountNumber: number, balance: account.balance };
    }
    return this.request('GET', `/api/account/balance/${number}`);
  }

  async transfer(from, to, amount) {
    if (process.env.NIBSS_MOCK_MODE === 'true') {
      const source = this.accounts.get(from); const destination = this.accounts.get(to); const value = Number(amount);
      if (source && source.balance < value) { const e = new Error('Insufficient funds at mock NIBSS'); e.status = 400; throw e; }
      if (source) source.balance -= value; if (destination) destination.balance += value;
      const transactionId = `MOCK-${crypto.randomUUID()}`;
      const result = { transactionId, status: 'SUCCESS', from, to, amount: value };
      this.transactions.set(transactionId, result); return result;
    }
    return this.request('POST', '/api/transfer', { from, to, amount });
  }

  async transactionStatus(id) {
    if (process.env.NIBSS_MOCK_MODE === 'true') return this.transactions.get(id) || { transactionId: id, status: 'NOT_FOUND' };
    return this.request('GET', `/api/transaction/${id}`);
  }

  seedIdentity({ type, id, first, last, dob }) { this.identities.set(`${type}:${id}`, { firstName: first, lastName: last, dob }); }
}

export default new NibssClient();
