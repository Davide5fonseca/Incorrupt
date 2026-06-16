// ============================================================
// Incorrupt / DEMS — Mongoose Schema: AuditEntry (bloco da cadeia)
//
// As fórmulas de hash vivem agora em src/crypto/blockHash.ts
// (fonte única, partilhada entre escrita e verificação).
//
// schemaVersion:
//   1 LEGACY : SHA-256(previousHash | timestamp | action | actorID | fileCID | envelopeID)
//   2 v2     : + blockIndex | fileHash | fileName
//   3 v3     : + signature | publicKey | timeSource
//   4 v4     : + metadata protegido + nodeSignatures (quorum certificate)
// ============================================================

import { Schema, Document } from 'mongoose';
import { NodeSignature } from '../crypto/nodeIdentity';

export interface IAuditEntry extends Document {
    schemaVersion: number;

    // ── Estrutura da cadeia ───────────────────────────────────
    previousHash: string;
    currentHash:  string;
    blockIndex:   number;

    // ── Evento ────────────────────────────────────────────────
    timestamp:  Date;
    timeSource: string;            // 'NTP_SECURE' | 'LOCAL'
    action:     string;
    actorID:    number;
    actorEmail: string;
    actorRole:  string;

    // ── Prova (ficheiro) ──────────────────────────────────────
    fileHash:    string;           // SHA-256 dos bytes ('LEGACY' em v1)
    fileSize:    number;
    fileCID:     string;           // CID IPFS (pode ser vazio)
    envelopeID:  string;           // DocuSign (vazio se N/A)
    fileName:    string;
    driveFileId: string;

    // ── Não-repúdio (assinatura do utilizador) ────────────────
    publicKey:  string;
    signature:  string;

    // ── Consenso (quorum certificate dos nós) ─────────────────
    nodeSignatures: NodeSignature[];  // >= QUORUM assinaturas de nós distintos
    consensusCount: number;           // = nodeSignatures.length

    // ── Forense ───────────────────────────────────────────────
    metadata: string;              // JSON de metadados (ex.: EXIF)
}

const NodeSignatureSchema = new Schema<NodeSignature>(
    {
        nodeId:    { type: String, required: true },
        publicKey: { type: String, required: true },
        signature: { type: String, required: true },
    },
    { _id: false },
);

const AuditEntrySchema = new Schema<IAuditEntry>(
    {
        schemaVersion: { type: Number, required: true, default: 4 },

        previousHash:  { type: String, required: true },
        currentHash:   { type: String, required: true, unique: true },
        blockIndex:    { type: Number, required: true, default: 0 },

        timestamp:     { type: Date,   required: true, default: () => new Date() },
        timeSource:    { type: String, default: 'LOCAL' },
        action:        { type: String, required: true },
        actorID:       { type: Number, required: true },
        actorEmail:    { type: String, required: true },
        actorRole:     { type: String, required: true },

        fileHash:      { type: String, required: true, default: 'LEGACY' },
        fileSize:      { type: Number, required: true, default: 0 },
        fileCID:       { type: String, default: '' },
        envelopeID:    { type: String, default: '' },
        fileName:      { type: String, required: true },
        driveFileId:   { type: String, default: 'OFFLINE' },

        publicKey:     { type: String, default: 'NONE' },
        signature:     { type: String, default: 'NONE' },

        nodeSignatures: { type: [NodeSignatureSchema], default: [] },
        consensusCount: { type: Number, required: true, min: 0, default: 0 },

        metadata:      { type: String, default: 'NONE' },
    },
    { versionKey: false, timestamps: false },
);

AuditEntrySchema.index({ timestamp: -1 });
AuditEntrySchema.index({ blockIndex: 1 });
AuditEntrySchema.index({ actorID: 1 });
AuditEntrySchema.index({ fileHash: 1 });

export { AuditEntrySchema };
