# Digital Banking Backend (JavaScript)

Node.js/Express implementation of the backend assignment. Includes customer registration/login, BVN/NIN verification, account creation with ₦15,000 opening balance, name enquiry, balance lookup, transfers, transaction status, and customer-scoped transaction history. Data is stored in SQLite; integration with NIBSS by Phoenix is configurable. The SQLite driver uses the current N-API-based release line, which removed the deprecated prebuild-install dependency present in the older version from the first ZIP.

## Run locally

Requires Node.js 20 or newer.

```sh
npm install
cp .env.example .env
```

Set `JWT_SECRET`, `KYC_ENCRYPTION_KEY`, and `BOOTSTRAP_ADMIN_KEY` to independent random values of at least 32 characters. Start the API:

```sh
npm run dev
```

The API listens on `http://localhost:8000`. SQLite creates `bank.sqlite` in the project directory. Use `npm start` for normal startup.

## NIBSS configuration

The assignment requires onboarding your bank with the assigned company name and team email, then using the issued API credentials. A helper script is included; provide the real contact details when known:

```sh
BANK_NAME="Assigned bank name" BANK_EMAIL="team contact email" node scripts/onboard-bank.js
```

On Windows PowerShell, set `$env:BANK_NAME` and `$env:BANK_EMAIL` before running the script. Put the returned values in `.env` as `NIBSS_API_KEY` and `NIBSS_API_SECRET`, then set `NIBSS_MOCK_MODE=false`. The backend obtains and caches NIBSS's one-hour JWT. Do not use or commit the sample token and credentials embedded in the Postman collection.

## Mock mode

Mock mode is on by default. Seed a synthetic identity while the server is running:

```sh
curl -X POST http://localhost:8000/api/dev/mock-identities \
  -H 'content-type: application/json' \
  -H 'X-Admin-Key: your-bootstrap-admin-key' \
  -d '{"kyc_type":"BVN","kyc_id":"12345678901","first_name":"Ada","last_name":"Okafor","dob":"1995-03-14"}'
```

Use synthetic BVN/NIN values only. The mock identity and NIBSS account directory is held in process memory, so seed it again after restarting the server. Mock name enquiry returns a synthetic recipient for other 10-digit account numbers to allow transfer demonstrations.

## Customer API workflow

Register and login return a customer JWT. Send it as `Authorization: Bearer <access_token>` to all customer routes.

1. `POST /api/customers/register`: `{ "email", "full_name", "password" }`
2. `POST /api/customers/onboarding/bvn` or `/api/customers/onboarding/nin`: `{ "kyc_id": "11 digits", "dob": "YYYY-MM-DD" }`
3. `POST /api/accounts`: `{}`
4. `GET /api/transfers/name-enquiry/{10-digit-account-number}`
5. `POST /api/transfers`: `{ "to_account", "amount_naira", "recipient_name_confirmed": true, "idempotency_key", "narration?" }`
6. `GET /api/accounts/me/balance`, `GET /api/transfers/{transaction_id}`, `GET /api/transactions?limit=50&offset=0`

Example transfer body:

```json
{
  "to_account": "1234567890",
  "amount_naira": "250.00",
  "recipient_name_confirmed": true,
  "idempotency_key": "ada-demo-000001",
  "narration": "Test transfer"
}
```

The recipient name must be checked by the client using name enquiry before sending the transfer. Amounts are strings with up to two decimal places and are stored as integer kobo.

## Security and assignment notes

- Passwords use bcrypt. Customer sessions are signed short-lived JWTs.
- BVN/NIN values are encrypted using AES-256-GCM for account creation and indexed by a keyed HMAC digest for duplicate prevention. Keep the encryption key stable and backed up securely.
- SQLite uniqueness constraints enforce one account per customer, unique account numbers, and idempotency keys. History queries are limited to the authenticated customer's own account.
- Transfers reserve local funds before calling NIBSS, then settle or restore them based on the provider response. A network timeout can have an ambiguous provider outcome; it remains pending and must be reconciled before retrying.
- The PDF says account creation uses `kycType`, `kycID`, and `dob`; the Postman collection's account body instead shows `name` and `email`. This implementation follows the PDF. NIBSS offers status by transaction ID but no customer-history endpoint, so history is persisted locally.
- This assignment prototype is not a production double-entry ledger. Before real-money use, add migrations, proper accounting postings, reconciliation, rate limits, monitoring, and operational controls.
