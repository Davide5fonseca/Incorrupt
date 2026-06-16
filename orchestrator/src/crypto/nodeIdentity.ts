// ============================================================
// Incorrupt / DEMS — Identidade criptográfica dos nós de auditoria
//
// Cada nó de auditoria é uma ENTIDADE INDEPENDENTE com o seu
// próprio par de chaves Ed25519. Quando um nó concorda em aceitar
// um bloco, assina o hash desse bloco com a sua chave privada.
// O conjunto de assinaturas (>= QUORUM) forma o "quorum
// certificate" que fica gravado dentro do bloco.
//
// É isto que torna o consenso REAL (e não teatro): a verificação
// posterior consegue provar, criptograficamente, que pelo menos
// QUORUM nós distintos validaram cada bloco — e não confia na
// palavra do orquestrador.
//
// As chaves privadas são persistidas em .keys/ (fora do git).
// ============================================================

import crypto, { KeyObject } from 'crypto';
import fs from 'fs';
import path from 'path';

export interface NodeSignature {
    nodeId:    string;  // ex.: 'audit_node_1'
    publicKey: string;  // PEM (SPKI) — a chave pública do nó
    signature: string;  // base64 — Ed25519(blockHash)
}

const KEYS_DIR = path.join(process.cwd(), '.keys');

export class NodeIdentity {
    readonly nodeId:       string;
    readonly publicKeyPem: string;
    private readonly privateKey: KeyObject;

    private constructor(nodeId: string, publicKeyPem: string, privateKey: KeyObject) {
        this.nodeId       = nodeId;
        this.publicKeyPem = publicKeyPem;
        this.privateKey   = privateKey;
    }

    // ── Carrega a identidade do disco, ou gera uma nova ───────
    static loadOrCreate(nodeId: string): NodeIdentity {
        if (!fs.existsSync(KEYS_DIR)) fs.mkdirSync(KEYS_DIR, { recursive: true });
        const keyPath = path.join(KEYS_DIR, `${nodeId}.json`);

        if (fs.existsSync(keyPath)) {
            const { privateKeyPem, publicKeyPem } = JSON.parse(fs.readFileSync(keyPath, 'utf-8'));
            const privateKey = crypto.createPrivateKey(privateKeyPem);
            return new NodeIdentity(nodeId, publicKeyPem, privateKey);
        }

        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        const publicKeyPem  = publicKey.export({ type: 'spki',  format: 'pem' }).toString();
        const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
        fs.writeFileSync(keyPath, JSON.stringify({ nodeId, publicKeyPem, privateKeyPem }, null, 2), 'utf-8');
        return new NodeIdentity(nodeId, publicKeyPem, privateKey);
    }

    // ── Identidade efémera (para testes — não toca no disco) ──
    static ephemeral(nodeId: string): NodeIdentity {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
        return new NodeIdentity(nodeId, publicKeyPem, privateKey);
    }

    // ── O nó assina o hash de um bloco (o seu "voto") ─────────
    sign(blockHash: string): NodeSignature {
        const signature = crypto
            .sign(null, Buffer.from(blockHash, 'utf8'), this.privateKey)
            .toString('base64');
        return { nodeId: this.nodeId, publicKey: this.publicKeyPem, signature };
    }

    // ── Verifica uma assinatura de nó sobre um hash ───────────
    static verify(blockHash: string, sig: NodeSignature): boolean {
        try {
            return crypto.verify(
                null,
                Buffer.from(blockHash, 'utf8'),
                crypto.createPublicKey(sig.publicKey),
                Buffer.from(sig.signature, 'base64'),
            );
        } catch {
            return false;
        }
    }
}

// ── Validação de um quorum certificate completo ───────────────
// Devolve quantas assinaturas VÁLIDAS e de nós DISTINTOS (cujas
// chaves públicas constam de `trustedKeys`) existem sobre o hash.
export function countValidSignatures(
    blockHash:    string,
    signatures:   NodeSignature[],
    trustedKeys:  Set<string>,
): number {
    const seenNodes = new Set<string>();
    let valid = 0;
    for (const sig of signatures || []) {
        if (seenNodes.has(sig.nodeId)) continue;        // não conta o mesmo nó 2x
        if (!trustedKeys.has(sig.publicKey)) continue;  // chave desconhecida → ignora
        if (NodeIdentity.verify(blockHash, sig)) {
            seenNodes.add(sig.nodeId);
            valid++;
        }
    }
    return valid;
}
