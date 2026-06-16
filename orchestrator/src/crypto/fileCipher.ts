// ============================================================
// Incorrupt / DEMS — Cifra de ficheiros (AES-256-GCM)
//
// Centraliza a cifra/decifra usada pelo storage e pelo backup
// no Drive (antes a chave era derivada em dois sítios).
//
// GCM é cifra AUTENTICADA: dá confidencialidade E integridade
// num só passo. Ao contrário do CBC (maleável), qualquer
// adulteração do ciphertext é detetada na decifra (a auth tag
// não bate → erro). Substitui o AES-256-CBC anterior.
//
// Formato do blob: iv(12) || authTag(16) || ciphertext
// ============================================================

import crypto from 'crypto';

const IV_LEN  = 12;   // nonce recomendado para GCM
const TAG_LEN = 16;   // tag de autenticação GCM (128 bits)

export function getEncryptionKey(): Buffer {
    const envKey = process.env.ENCRYPTION_KEY;
    if (envKey && /^[0-9a-fA-F]{64}$/.test(envKey)) {
        return Buffer.from(envKey, 'hex');               // 32 bytes
    }
    if (envKey) {
        console.warn('[AVISO] [AES] ENCRYPTION_KEY não é hex de 64 chars — a derivar via scrypt (DEV).');
    } else {
        console.warn('[AVISO] [AES] ENCRYPTION_KEY ausente — a usar chave derivada (DEV ONLY).');
    }
    return crypto.scryptSync(envKey || 'dems_default_dev_key', 'dems_salt_v1', 32);
}

export function encryptBuffer(plain: Buffer): Buffer {
    const iv     = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv('aes-256-gcm', getEncryptionKey(), iv);
    const ct     = Buffer.concat([cipher.update(plain), cipher.final()]);
    const tag    = cipher.getAuthTag();
    return Buffer.concat([iv, tag, ct]);
}

export function decryptBuffer(encrypted: Buffer): Buffer {
    if (encrypted.length < IV_LEN + TAG_LEN) {
        throw new Error('Blob cifrado demasiado curto (corrompido).');
    }
    const iv         = encrypted.subarray(0, IV_LEN);
    const tag        = encrypted.subarray(IV_LEN, IV_LEN + TAG_LEN);
    const ciphertext = encrypted.subarray(IV_LEN + TAG_LEN);
    const decipher   = crypto.createDecipheriv('aes-256-gcm', getEncryptionKey(), iv);
    decipher.setAuthTag(tag);   // adulteração → final() lança
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
