import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import { SignJWT, jwtVerify } from 'jose';

const jwtKey = () => {
  const secret = process.env.JWT_SECRET || '';
  if (secret.length < 32) throw new Error('JWT_SECRET must contain at least 32 characters');
  return new TextEncoder().encode(secret);
};

export const hashPassword = (password) => bcrypt.hash(password, 12);
export const verifyPassword = (password, hash) => bcrypt.compare(password, hash);
export const signToken = (customerId) => new SignJWT({})
  .setProtectedHeader({ alg: 'HS256' }).setSubject(String(customerId))
  .setIssuedAt().setExpirationTime(`${Number(process.env.JWT_EXPIRE_MINUTES || 60)}m`)
  .sign(jwtKey());

export async function verifyToken(token) {
  const { payload } = await jwtVerify(token, jwtKey());
  const id = Number(payload.sub);
  if (!Number.isSafeInteger(id)) throw new Error('Invalid subject');
  return id;
}

function encryptionKey() {
  const secret = process.env.KYC_ENCRYPTION_KEY || '';
  if (secret.length < 32) throw new Error('KYC_ENCRYPTION_KEY must contain at least 32 characters');
  return crypto.createHash('sha256').update(secret).digest();
}

export function encryptKyc(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), ciphertext].map((part) => part.toString('base64url')).join('.');
}

export function decryptKyc(value) {
  const [iv, tag, ciphertext] = value.split('.').map((part) => Buffer.from(part, 'base64url'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

export function kycDigest(type, value) {
  const key = process.env.JWT_SECRET || '';
  return crypto.createHmac('sha256', key).update(`${type}:${value}`).digest('hex');
}
