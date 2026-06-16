// ============================================================
// Incorrupt / DEMS — Armazenamento local cifrado (obrigatório)
//
// Guarda cada prova como .storage/<fileHash>.enc (AES-256-CBC).
// O fileHash é validado antes de gravar; na leitura, o conteúdo
// decifrado é re-hasheado e comparado com o pedido — se não bater,
// o ficheiro em disco foi corrompido e a leitura falha.
// ============================================================

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { StorageProvider } from './StorageProvider';
import { encryptBuffer, decryptBuffer } from '../crypto/fileCipher';

const HEX64 = /^[0-9a-f]{64}$/;

export class LocalStorageProvider implements StorageProvider {
    readonly name = 'local';
    private readonly dir: string;

    constructor(baseDir?: string) {
        this.dir = baseDir ?? path.join(process.cwd(), '.storage');
        if (!fs.existsSync(this.dir)) fs.mkdirSync(this.dir, { recursive: true });
    }

    private pathFor(fileHash: string): string {
        if (!HEX64.test(fileHash)) throw new Error('fileHash inválido (esperado SHA-256 hex).');
        return path.join(this.dir, `${fileHash}.enc`);
    }

    async put(fileHash: string, data: Buffer): Promise<string> {
        // Garante que o hash declarado corresponde mesmo aos bytes.
        const actual = crypto.createHash('sha256').update(data).digest('hex');
        if (actual !== fileHash) {
            throw new Error(`fileHash não corresponde aos bytes (esperado ${fileHash}, obtido ${actual}).`);
        }
        const target = this.pathFor(fileHash);
        // Idempotente: o mesmo conteúdo tem sempre o mesmo hash.
        if (!fs.existsSync(target)) {
            await fs.promises.writeFile(target, encryptBuffer(data));
        }
        return `${this.name}:${fileHash}`;
    }

    async get(fileHash: string): Promise<Buffer> {
        const target = this.pathFor(fileHash);
        if (!fs.existsSync(target)) throw new Error('Ficheiro não encontrado no armazenamento.');
        const plain = decryptBuffer(await fs.promises.readFile(target));
        const actual = crypto.createHash('sha256').update(plain).digest('hex');
        if (actual !== fileHash) throw new Error('Integridade do armazenamento comprometida (hash não bate).');
        return plain;
    }

    async has(fileHash: string): Promise<boolean> {
        try { return fs.existsSync(this.pathFor(fileHash)); }
        catch { return false; }
    }
}

// Instância partilhada (obrigatória no fluxo de upload).
export const localStorage = new LocalStorageProvider();
