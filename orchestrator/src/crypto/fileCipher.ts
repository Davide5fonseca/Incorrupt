// ============================================================
// Incorrupt / DEMS — Cifra de ficheiros (AES-256-CBC)
//
// Centraliza a cifra/decifra usada pelo storage e pelo backup
// no Drive (antes a chave era derivada em dois sítios). O IV
// (16 bytes) é guardado como prefixo do ciphertext.
// ============================================================

import crypto from 'crypto';

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
    const iv     = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', getEncryptionKey(), iv);
    return Buffer.concat([iv, cipher.update(plain), cipher.final()]);
}

export function decryptBuffer(encrypted: Buffer): Buffer {
    const iv         = encrypted.subarray(0, 16);
    const ciphertext = encrypted.subarray(16);
    const decipher   = crypto.createDecipheriv('aes-256-cbc', getEncryptionKey(), iv);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
