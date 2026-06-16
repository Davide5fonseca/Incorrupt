// ============================================================
// Incorrupt / DEMS — Fórmulas de hash da cadeia (módulo puro)
//
// Centraliza o cálculo do hash de cada bloco. Antes estava
// duplicado entre o ConsensusManager e o model AuditEntry — o
// que é perigoso: se as duas cópias divergirem, a verificação
// de integridade falha silenciosamente. Aqui há uma só fonte.
//
// Versões (schemaVersion):
//   1 LEGACY : previousHash|timestamp|action|actorID|fileCID|envelopeID
//   2 v2     : previousHash|blockIndex|timestamp|action|actorID|fileHash|fileName
//   3 v3     : v2 + signature|publicKey|timeSource  (metadata NÃO protegido — bug)
//   4 v4     : v3 + metadata  (metadata passa a ser à prova de adulteração)
// ============================================================

import crypto from 'crypto';

function sha256(payload: string): string {
    return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
}

// ── v4 (atual) — inclui metadata no hash ──────────────────────
export function computeHashV4(
    previousHash: string,
    blockIndex:   number,
    timestamp:    Date,
    action:       string,
    actorID:      number,
    fileHash:     string,
    fileName:     string,
    signature:    string,
    publicKey:    string,
    timeSource:   string,
    metadata:     string,
): string {
    return sha256([
        previousHash, String(blockIndex), timestamp.toISOString(),
        action, String(actorID), fileHash, fileName,
        signature, publicKey, timeSource, metadata,
    ].join('|'));
}

// ── v3 (legacy de leitura) ────────────────────────────────────
export function computeHashV3(
    previousHash: string,
    blockIndex:   number,
    timestamp:    Date,
    action:       string,
    actorID:      number,
    fileHash:     string,
    fileName:     string,
    signature:    string,
    publicKey:    string,
    timeSource:   string,
): string {
    return sha256([
        previousHash, String(blockIndex), timestamp.toISOString(),
        action, String(actorID), fileHash, fileName,
        signature, publicKey, timeSource,
    ].join('|'));
}

// ── v2 ────────────────────────────────────────────────────────
export function computeHashV2(
    previousHash: string,
    blockIndex:   number,
    timestamp:    Date,
    action:       string,
    actorID:      number,
    fileHash:     string,
    fileName:     string,
): string {
    return sha256([
        previousHash, String(blockIndex), timestamp.toISOString(),
        action, String(actorID), fileHash, fileName,
    ].join('|'));
}

// ── v1 (legacy) ───────────────────────────────────────────────
export function computeHashV1(
    previousHash: string,
    timestamp:    Date,
    action:       string,
    actorID:      number,
    fileCID:      string,
    envelopeID:   string,
): string {
    return sha256([
        previousHash, timestamp.toISOString(), action,
        String(actorID), fileCID, envelopeID,
    ].join('|'));
}

// ── Recalcular o hash esperado de um bloco já gravado ─────────
// Usado pela verificação de integridade: pega no documento tal
// como está na BD e devolve o hash que ELE devia ter, segundo a
// sua própria schemaVersion. Se != currentHash → adulterado.
export function expectedHashFor(prevHash: string, block: any): string {
    const ver = block.schemaVersion ?? 1;
    const ts  = new Date(block.timestamp);
    if (ver >= 4) {
        return computeHashV4(
            prevHash, block.blockIndex, ts, block.action, block.actorID,
            block.fileHash, block.fileName,
            block.signature ?? 'NONE', block.publicKey ?? 'NONE',
            block.timeSource ?? 'LOCAL', block.metadata ?? 'NONE',
        );
    }
    if (ver === 3) {
        return computeHashV3(
            prevHash, block.blockIndex, ts, block.action, block.actorID,
            block.fileHash, block.fileName,
            block.signature ?? 'NONE', block.publicKey ?? 'NONE',
            block.timeSource ?? 'LOCAL',
        );
    }
    if (ver === 2) {
        return computeHashV2(
            prevHash, block.blockIndex, ts, block.action, block.actorID,
            block.fileHash, block.fileName,
        );
    }
    return computeHashV1(
        prevHash, ts, block.action, block.actorID,
        block.fileCID ?? '', block.envelopeID ?? '',
    );
}
