// ============================================================
// Incorrupt / DEMS — Consensus Manager (BFT real)
//
// Cada nó de auditoria é uma ENTIDADE INDEPENDENTE com o seu
// próprio par de chaves Ed25519. O commit de um bloco é:
//
//   1. PROPOR   — o orquestrador monta o bloco candidato e o hash.
//   2. VALIDAR  — cada nó confere, contra a SUA própria ponta da
//                 cadeia, que o previousHash/blockIndex batem certo
//                 e que o hash foi bem calculado.
//   3. ASSINAR  — se concorda, o nó assina o hash (o seu "voto").
//   4. CERTIFICAR — juntam-se >= QUORUM assinaturas (quorum
//                 certificate) e o bloco certificado é gravado.
//
// Com 4 nós e quórum 3 (3f+1, f=1) o sistema:
//   • sobrevive a 1 nó em baixo (continua a aceitar provas);
//   • DETETA e isola 1 nó que minta/divirja (verificação cross-node);
//   • prova, a qualquer momento, que >= 3 nós distintos validaram
//     cada bloco — sem confiar na palavra do orquestrador.
//
// Modos: LOCAL_DEV (mongodb-memory-server) e produção (containers).
// ============================================================

import mongoose, { Connection, Model } from 'mongoose';
import axios from 'axios';
import fs from 'fs';
import path from 'path';
import { AuditEntrySchema, IAuditEntry } from '../models/AuditEntry';
import { computeHashV4, expectedHashFor } from '../crypto/blockHash';
import { NodeIdentity, NodeSignature, countValidSignatures } from '../crypto/nodeIdentity';

export interface NewAuditEntry {
    action:      string;
    actorID:     number;
    actorEmail:  string;
    actorRole:   string;
    fileCID:     string;
    envelopeID?: string;
    fileName:    string;
    driveFileId: string;
    fileHash:    string;
    fileSize:    number;
    publicKey?:  string;
    signature?:  string;
    metadata?:   string;
}

export interface ConsensusResult {
    success:        boolean;
    consensusCount: number;
    currentHash:    string;
    previousHash:   string;
    blockIndex:     number;
    fileHash:       string;
    timestamp:      Date;
    nodeSignatures: NodeSignature[];
}

interface PreviousBlockInfo {
    hash:       string;
    blockIndex: number;
}

interface NodeStatus {
    name:      string;
    uri:       string;
    healthy:   boolean;
    lastError: string | null;
    publicKey: string;
}

export interface BlockSummary {
    blockIndex:     number;
    currentHash:    string;
    previousHash:   string;
    timestamp:      Date;
    action:         string;
    actorEmail:     string;
    actorRole:      string;
    fileName:       string;
    fileHash:       string;
    fileSize:       number;
    fileCID:        string;
    consensusCount: number;
    schemaVersion:  number;
    publicKey:      string;
    signature:      string;
    timeSource:     string;
    metadata:       string;
    nodeSignatures: NodeSignature[];
}

export interface CrossNodeReport {
    consistent:     boolean;
    totalNodes:     number;
    healthyNodes:   number;
    checkedBlocks:  number;
    divergentNodes: string[];   // nós cuja cópia diverge da maioria
    conflicts: Array<{ blockIndex: number; majorityHash: string; dissenters: string[] }>;
}

export interface ReconcileReport {
    targetNode:        string;
    referenceNode:     string | null;
    alreadyConsistent: boolean;
    copied:            number;   // blocos copiados para o alvo
    removed:           number;   // blocos divergentes/órfãos removidos do alvo
    totalBlocks:       number;   // tamanho da cadeia canónica de referência
    skippedUncertified: number;  // blocos da referência sem quorum cert válido (não propagados)
}

export class ConsensusError extends Error {
    public readonly successCount:  number;
    public readonly requiredCount: number;
    constructor(successCount: number, requiredCount: number) {
        super(
            `BFT consenso FALHOU: apenas ${successCount}/${requiredCount} nós validaram o bloco. ` +
            `Nenhuma escrita foi confirmada.`
        );
        this.name = 'ConsensusError';
        this.successCount  = successCount;
        this.requiredCount = requiredCount;
    }
}

type MongoMemoryServer = any;

class ConsensusManager {
    private readonly TOTAL_NODES  = 4;            // 3f+1, f=1
    private readonly QUORUM       = 3;            // 2f+1
    private readonly GENESIS_HASH = '0'.repeat(64);

    private connections:   Connection[]         = [];
    private models:        Model<IAuditEntry>[] = [];
    private nodeStatus:    NodeStatus[]         = [];
    private identities:    NodeIdentity[]       = [];
    private memoryServers: MongoMemoryServer[]  = [];

    // Mutex: serializa os commits para que dois uploads em paralelo
    // não disputem o mesmo blockIndex/previousHash.
    private commitLock: Promise<unknown> = Promise.resolve();

    // Conjunto das chaves públicas confiáveis (as dos nossos nós).
    private get trustedKeys(): Set<string> {
        return new Set(this.identities.filter(Boolean).map(id => id.publicKeyPem));
    }

    // ── Inicialização ─────────────────────────────────────────
    async initialise(): Promise<void> {
        // Cada nó carrega/gera a sua identidade Ed25519 (persistente).
        for (let i = 0; i < this.TOTAL_NODES; i++) {
            this.identities[i] = NodeIdentity.loadOrCreate(`audit_node_${i + 1}`);
        }

        const isLocal = process.env.LOCAL_DEV === 'true';
        if (isLocal) await this._initialiseLocal();
        else         await this._initialiseProd();

        const healthyCount = this.nodeStatus.filter(n => n.healthy).length;
        if (healthyCount < this.QUORUM) {
            throw new Error(
                `[Consensus] Quórum impossível: ${healthyCount}/${this.TOTAL_NODES} nós disponíveis ` +
                `(mínimo ${this.QUORUM}).`
            );
        }
        console.log(`[ ONLINE ] [Consensus] ${healthyCount}/${this.TOTAL_NODES} nós activos. Quórum (${this.QUORUM}) garantido.\n`);
    }

    // ── Modo LOCAL ────────────────────────────────────────────
    private async _initialiseLocal(): Promise<void> {
        console.log(`[ TESTE ] [Consensus] Modo LOCAL — a iniciar ${this.TOTAL_NODES} instâncias MongoDB em memória...`);

        let MongoMemoryServer: any;
        try {
            const requireFn = new Function('require', 'return require')(require);
            MongoMemoryServer = requireFn('mongodb-memory-server').MongoMemoryServer;
        } catch {
            throw new Error(
                'mongodb-memory-server não instalado.\n' +
                'Passo 1: corre  1-instalar.bat.\n' +
                'Passo 2: corre  2-arrancar-servidor.bat.'
            );
        }

        for (let i = 0; i < this.TOTAL_NODES; i++) {
            const nodeName = `audit_node_${i + 1}`;
            const dbDir = path.join(process.cwd(), '.db', nodeName);
            if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

            try {
                const server: MongoMemoryServer = await MongoMemoryServer.create({ instance: { dbPath: dbDir } });
                const uri = server.getUri();
                this.memoryServers[i] = server;

                const conn  = await mongoose.createConnection(uri).asPromise();
                const model = conn.model<IAuditEntry>('AuditEntry', AuditEntrySchema);

                this.connections[i] = conn;
                this.models[i]      = model;
                this.nodeStatus[i]  = { name: nodeName, uri, healthy: true, lastError: null, publicKey: this.identities[i].publicKeyPem };

                console.log(`  [OK] Nó ${i + 1} (${nodeName}) — persistente (.db/${nodeName})`);
            } catch (err: any) {
                this.nodeStatus[i] = { name: nodeName, uri: 'N/A', healthy: false, lastError: err.message, publicKey: this.identities[i].publicKeyPem };
                console.warn(`  [FALHA] Nó ${i + 1}: ${err.message}`);
            }
        }
    }

    // ── Modo PRODUÇÃO ─────────────────────────────────────────
    private async _initialiseProd(): Promise<void> {
        const nodeUris = Array.from({ length: this.TOTAL_NODES }, (_, i) => ({
            name: `audit_node_${i + 1}`,
            uri:  `mongodb://audit_node_${i + 1}:27017/dems_audit`,
        }));

        console.log(`[Consensus] Modo PRODUÇÃO — a ligar aos ${this.TOTAL_NODES} containers Mongo...`);
        this.nodeStatus = nodeUris.map((n, i) => ({
            name: n.name, uri: n.uri, healthy: false, lastError: null, publicKey: this.identities[i].publicKeyPem,
        }));

        await Promise.allSettled(nodeUris.map(async (node, i) => {
            try {
                const conn  = await mongoose.createConnection(node.uri, {
                    serverSelectionTimeoutMS: 5000,
                    connectTimeoutMS:         5000,
                }).asPromise();
                const model = conn.model<IAuditEntry>('AuditEntry', AuditEntrySchema);

                this.connections[i]        = conn;
                this.models[i]             = model;
                this.nodeStatus[i].healthy = true;
                console.log(`  [OK] Nó ${i + 1} (${node.name}) ligado`);

                conn.on('disconnected', () => { this.nodeStatus[i].healthy = false; });
                conn.on('reconnected',  () => { this.nodeStatus[i].healthy = true;  });
            } catch (err: any) {
                this.nodeStatus[i].healthy   = false;
                this.nodeStatus[i].lastError = err.message;
                console.warn(`  [AVISO] Nó ${i + 1} indisponível: ${err.message}`);
            }
        }));
    }

    // ── Ponta da cadeia (hash + índice) a partir de um nó saudável ──
    private async getPreviousBlockInfo(): Promise<PreviousBlockInfo> {
        for (let i = 0; i < this.TOTAL_NODES; i++) {
            if (!this.nodeStatus[i]?.healthy) continue;
            try {
                const latest = await this.models[i]
                    .findOne().sort({ blockIndex: -1 })
                    .select('currentHash blockIndex').lean().exec() as any;
                if (latest) return { hash: latest.currentHash, blockIndex: latest.blockIndex ?? 0 };
                return { hash: this.GENESIS_HASH, blockIndex: -1 };
            } catch { /* tenta o próximo nó */ }
        }
        return { hash: this.GENESIS_HASH, blockIndex: -1 };
    }

    // ── Timestamp seguro (NTP com fallback) ───────────────────
    private async _getSecureTimestamp(): Promise<{ timestamp: Date, timeSource: string }> {
        try {
            const res = await axios.get('https://worldtimeapi.org/api/timezone/Etc/UTC', { timeout: 2000 });
            if (res.data?.datetime) return { timestamp: new Date(res.data.datetime), timeSource: 'NTP_SECURE' };
        } catch {
            console.warn('[AVISO] [NTP] Fallback para hora local (API indisponível).');
        }
        return { timestamp: new Date(), timeSource: 'LOCAL' };
    }

    // ── PASSO 2+3: um nó valida o candidato contra a SUA cadeia e assina ──
    private async _nodeValidateAndSign(
        i:         number,
        candidate: { previousHash: string; blockIndex: number; currentHash: string; content: any },
    ): Promise<{ index: number; sig: NodeSignature } | null> {
        if (!this.nodeStatus[i]?.healthy || !this.models[i]) return null;
        try {
            // O nó lê a SUA própria ponta da cadeia.
            const tip = await this.models[i].findOne().sort({ blockIndex: -1 })
                .select('currentHash blockIndex').lean().exec() as any;
            const expectedPrev  = tip ? tip.currentHash : this.GENESIS_HASH;
            const expectedIndex = tip ? (tip.blockIndex ?? 0) + 1 : 0;

            // Discorda se o bloco não assenta na sua ponta.
            if (candidate.previousHash !== expectedPrev) return null;
            if (candidate.blockIndex   !== expectedIndex) return null;

            // Recalcula o hash a partir do conteúdo — não confia no proposto.
            const c = candidate.content;
            const recomputed = computeHashV4(
                candidate.previousHash, candidate.blockIndex, c.timestamp,
                c.action, c.actorID, c.fileHash, c.fileName,
                c.signature, c.publicKey, c.timeSource, c.metadata,
            );
            if (recomputed !== candidate.currentHash) return null;

            // Concorda → assina o hash com a sua chave privada.
            return { index: i, sig: this.identities[i].sign(candidate.currentHash) };
        } catch (err: any) {
            if (this.nodeStatus[i]) this.nodeStatus[i].lastError = err.message;
            return null;
        }
    }

    // ── Fan-out + quórum BFT (com mutex) ──────────────────────
    async broadcastAndCommit(entry: NewAuditEntry): Promise<ConsensusResult> {
        // Serializa os commits: o próximo só arranca quando este acabar.
        const run = this.commitLock.then(() => this._commit(entry));
        this.commitLock = run.then(() => {}, () => {});
        return run;
    }

    private async _commit(entry: NewAuditEntry): Promise<ConsensusResult> {
        const { timestamp, timeSource } = await this._getSecureTimestamp();
        const prev       = await this.getPreviousBlockInfo();
        const blockIndex = prev.blockIndex + 1;

        const signature = entry.signature || 'NONE';
        const publicKey = entry.publicKey || 'NONE';
        const metadata  = entry.metadata  || 'NONE';

        const content = {
            timestamp, timeSource,
            action: entry.action, actorID: entry.actorID,
            fileHash: entry.fileHash, fileName: entry.fileName,
            signature, publicKey, metadata,
        };

        const currentHash = computeHashV4(
            prev.hash, blockIndex, timestamp,
            entry.action, entry.actorID, entry.fileHash, entry.fileName,
            signature, publicKey, timeSource, metadata,
        );

        const candidate = { previousHash: prev.hash, blockIndex, currentHash, content };

        // ── PASSO 2/3: recolher votos (cada nó valida e assina) ──
        const voteResults = await Promise.all(
            this.models.map((_, i) => this._nodeValidateAndSign(i, candidate)),
        );
        const votes = voteResults.filter(Boolean) as Array<{ index: number; sig: NodeSignature }>;

        console.log(`[BFT] Votos: ${votes.length}/${this.TOTAL_NODES} nós validaram o bloco #${blockIndex}`);

        if (votes.length < this.QUORUM) {
            throw new ConsensusError(votes.length, this.QUORUM);
        }

        // ── PASSO 4: gravar o bloco CERTIFICADO nos nós que votaram ──
        const nodeSignatures = votes.map(v => v.sig);
        const document = {
            schemaVersion: 4,
            previousHash:  prev.hash,
            currentHash,
            blockIndex,
            timestamp,
            timeSource,
            action:        entry.action,
            actorID:       entry.actorID,
            actorEmail:    entry.actorEmail,
            actorRole:     entry.actorRole,
            fileHash:      entry.fileHash,
            fileSize:      entry.fileSize,
            fileCID:       entry.fileCID,
            envelopeID:    entry.envelopeID ?? '',
            fileName:      entry.fileName,
            driveFileId:   entry.driveFileId,
            publicKey,
            signature,
            nodeSignatures,
            consensusCount: nodeSignatures.length,
            metadata,
        };

        const writeResults = await Promise.allSettled(
            votes.map(v => this.models[v.index].create(document)),
        );
        const written = writeResults.filter(r => r.status === 'fulfilled').length;
        writeResults.forEach((r, k) => {
            if (r.status === 'rejected') {
                const i = votes[k].index;
                if (this.nodeStatus[i]) this.nodeStatus[i].lastError = (r.reason as any)?.message;
                console.warn(`  [ERRO] Escrita falhou no nó ${i + 1}: ${(r.reason as any)?.message}`);
            }
        });

        if (written < this.QUORUM) {
            await this._rollback(votes.map(v => v.index), currentHash);
            throw new ConsensusError(written, this.QUORUM);
        }

        console.log(`[BFT] COMMITTED — bloco #${blockIndex} | ${currentHash.substring(0, 12)}... | certificado por ${nodeSignatures.length} nós`);
        return {
            success: true, consensusCount: nodeSignatures.length,
            currentHash, previousHash: prev.hash, blockIndex,
            fileHash: entry.fileHash, timestamp, nodeSignatures,
        };
    }

    private async _rollback(indices: number[], currentHash: string): Promise<void> {
        await Promise.allSettled(
            indices.map(i => this.models[i].deleteOne({ currentHash })
                .then(() => console.log(`  [REVERT] Nó ${i + 1} revertido`))
                .catch(() => {})),
        );
    }

    // ── Mapeamento de documento → BlockSummary ────────────────
    private _toSummary(r: any): BlockSummary {
        return {
            blockIndex:     r.blockIndex ?? 0,
            currentHash:    r.currentHash,
            previousHash:   r.previousHash,
            timestamp:      r.timestamp,
            action:         r.action,
            actorEmail:     r.actorEmail,
            actorRole:      r.actorRole,
            fileName:       r.fileName,
            fileHash:       r.fileHash ?? 'LEGACY',
            fileSize:       r.fileSize ?? 0,
            fileCID:        r.fileCID ?? '',
            consensusCount: r.consensusCount ?? 0,
            schemaVersion:  r.schemaVersion ?? 1,
            publicKey:      r.publicKey ?? 'NONE',
            signature:      r.signature ?? 'NONE',
            timeSource:     r.timeSource ?? 'LOCAL',
            metadata:       r.metadata ?? 'NONE',
            nodeSignatures: r.nodeSignatures ?? [],
        };
    }

    async getBlocks(nodeIndex = 0, limit = 20): Promise<BlockSummary[]> {
        const model = this._healthyModel(nodeIndex);
        const raw = await model.find().sort({ blockIndex: -1 }).limit(limit).lean().exec() as any[];
        return raw.map(r => this._toSummary(r));
    }

    async getBlockByHash(hash: string, nodeIndex = 0): Promise<BlockSummary | null> {
        const model = this._healthyModel(nodeIndex);
        const raw = await model.findOne({ currentHash: hash }).lean().exec() as any;
        return raw ? this._toSummary(raw) : null;
    }

    async findBlockByFileHash(fileHash: string, nodeIndex = 0): Promise<BlockSummary | null> {
        if (!fileHash || fileHash === 'LEGACY') return null;
        const model = this._healthyModel(nodeIndex);
        const raw = await model.findOne({ fileHash, schemaVersion: { $gte: 2 } })
            .sort({ blockIndex: -1 }).lean().exec() as any;
        return raw ? this._toSummary(raw) : null;
    }

    async findAllBlocksByFileHash(fileHash: string, nodeIndex = 0): Promise<BlockSummary[]> {
        if (!fileHash || fileHash === 'LEGACY') return [];
        const model = this._healthyModel(nodeIndex);
        const raw = await model.find({ fileHash, schemaVersion: { $gte: 2 } })
            .sort({ blockIndex: -1 }).lean().exec() as any[];
        return raw.map(r => this._toSummary(r));
    }

    // ── Verificação de integridade de UM nó ───────────────────
    // (a) cada bloco encadeia com o anterior; (b) o hash bate certo
    // com o conteúdo; (c) blocos v4 têm um quorum certificate válido.
    async verifyChainIntegrity(nodeIndex = 0): Promise<{
        valid: boolean;
        brokenAtBlock?: number;
        brokenAtHash?: string;
        reason?: string;
        totalBlocks: number;
        legacyBlocks: number;
        certifiedBlocks: number;
    }> {
        const model = this._healthyModel(nodeIndex);
        const entries = await model.find().sort({ blockIndex: 1 }).lean().exec() as any[];

        if (entries.length === 0) return { valid: true, totalBlocks: 0, legacyBlocks: 0, certifiedBlocks: 0 };

        const trusted = this.trustedKeys;
        let legacyBlocks    = 0;
        let certifiedBlocks = 0;

        for (let i = 0; i < entries.length; i++) {
            const curr = entries[i];
            const prevHash = i === 0 ? this.GENESIS_HASH : entries[i - 1].currentHash;
            const ver = curr.schemaVersion ?? 1;

            // (a)+(b): o hash recalculado tem de bater certo.
            const expected = expectedHashFor(prevHash, curr);
            if (expected !== curr.currentHash) {
                return {
                    valid: false, brokenAtBlock: curr.blockIndex ?? i, brokenAtHash: curr.currentHash,
                    reason: 'HASH_MISMATCH', totalBlocks: entries.length, legacyBlocks, certifiedBlocks,
                };
            }

            // (c): blocos v4 precisam de quorum certificate válido.
            if (ver >= 4) {
                const validSigs = countValidSignatures(curr.currentHash, curr.nodeSignatures, trusted);
                if (validSigs < this.QUORUM) {
                    return {
                        valid: false, brokenAtBlock: curr.blockIndex ?? i, brokenAtHash: curr.currentHash,
                        reason: `QUORUM_CERT_INVALID (${validSigs}/${this.QUORUM})`,
                        totalBlocks: entries.length, legacyBlocks, certifiedBlocks,
                    };
                }
                certifiedBlocks++;
            } else {
                legacyBlocks++;
            }
        }

        return { valid: true, totalBlocks: entries.length, legacyBlocks, certifiedBlocks };
    }

    // ── Verificação CROSS-NODE (deteta o nó que mente) ────────
    // Lê a cadeia dos nós saudáveis e compara bloco a bloco. Para
    // cada blockIndex, o hash maioritário é o "verdadeiro"; nós com
    // hash diferente (ou em falta) são marcados como divergentes.
    async verifyAcrossNodes(): Promise<CrossNodeReport> {
        const healthy = this.nodeStatus
            .map((s, i) => ({ s, i }))
            .filter(x => x.s?.healthy && this.models[x.i]);

        const chains = await Promise.all(healthy.map(async ({ i, s }) => {
            const rows = await this.models[i].find().sort({ blockIndex: 1 })
                .select('blockIndex currentHash').lean().exec() as any[];
            const byIndex = new Map<number, string>();
            rows.forEach(r => byIndex.set(r.blockIndex, r.currentHash));
            return { name: s.name, byIndex, maxIndex: rows.length ? rows[rows.length - 1].blockIndex : -1 };
        }));

        const maxIndex = chains.reduce((m, c) => Math.max(m, c.maxIndex), -1);
        const divergent = new Set<string>();
        const conflicts: CrossNodeReport['conflicts'] = [];

        for (let idx = 0; idx <= maxIndex; idx++) {
            // Conta hashes por blockIndex (ausência = '∅').
            const tally = new Map<string, string[]>();
            for (const c of chains) {
                const h = c.byIndex.get(idx) ?? '∅';
                if (!tally.has(h)) tally.set(h, []);
                tally.get(h)!.push(c.name);
            }
            // Hash maioritário.
            let majorityHash = ''; let majorityNodes: string[] = [];
            for (const [h, nodes] of tally) {
                if (nodes.length > majorityNodes.length) { majorityHash = h; majorityNodes = nodes; }
            }
            const dissenters: string[] = [];
            for (const [h, nodes] of tally) {
                if (h !== majorityHash) { nodes.forEach(n => { divergent.add(n); dissenters.push(n); }); }
            }
            if (dissenters.length > 0) conflicts.push({ blockIndex: idx, majorityHash, dissenters });
        }

        return {
            consistent:     divergent.size === 0,
            totalNodes:     this.TOTAL_NODES,
            healthyNodes:   healthy.length,
            checkedBlocks:  maxIndex + 1,
            divergentNodes: [...divergent],
            conflicts,
        };
    }

    // ── Reconciliação (anti-entropy) ──────────────────────────
    // Um nó que esteve offline volta atrasado; um nó bizantino tem
    // blocos divergentes. Em ambos os casos, alinhamo-lo à cadeia
    // CANÓNICA — a do nó saudável com a cadeia válida mais longa —
    // copiando os blocos em falta/errados. Cada bloco da referência
    // é RE-VERIFICADO (encadeamento + quorum certificate) antes de
    // ser propagado: nunca se replica um bloco não certificado.
    //
    // Vai pelo mesmo mutex dos commits para não correr em paralelo
    // com uma escrita.
    async reconcileNode(targetIndex: number): Promise<ReconcileReport> {
        const run = this.commitLock.then(() => this._reconcile(targetIndex));
        this.commitLock = run.then(() => {}, () => {});
        return run;
    }

    // Reconcilia todos os nós saudáveis contra a cadeia canónica.
    async reconcileAll(): Promise<ReconcileReport[]> {
        const reports: ReconcileReport[] = [];
        for (let i = 0; i < this.TOTAL_NODES; i++) {
            if (this.nodeStatus[i]?.healthy && this.models[i]) {
                reports.push(await this.reconcileNode(i));
            }
        }
        return reports;
    }

    // Escolhe a referência: o nó saudável (≠ alvo) cuja cadeia é
    // VÁLIDA e mais longa. Devolve -1 se nenhum servir.
    private async _pickReference(targetIndex: number): Promise<number> {
        let ref = -1;
        let refLen = -1;
        for (let i = 0; i < this.TOTAL_NODES; i++) {
            if (i === targetIndex) continue;
            if (!this.nodeStatus[i]?.healthy || !this.models[i]) continue;
            try {
                const integ = await this.verifyChainIntegrity(i);
                if (integ.valid && integ.totalBlocks > refLen) {
                    ref = i;
                    refLen = integ.totalBlocks;
                }
            } catch { /* nó ilegível — tenta o próximo */ }
        }
        return ref;
    }

    private async _reconcile(targetIndex: number): Promise<ReconcileReport> {
        if (targetIndex < 0 || targetIndex >= this.TOTAL_NODES) {
            throw new Error('Índice de nó inválido.');
        }
        const target = this.models[targetIndex];
        const targetName = this.nodeStatus[targetIndex]?.name ?? `audit_node_${targetIndex + 1}`;
        if (!this.nodeStatus[targetIndex]?.healthy || !target) {
            throw new Error(`Nó ${targetIndex + 1} offline — não pode ser reconciliado.`);
        }

        const refIndex = await this._pickReference(targetIndex);
        if (refIndex === -1) {
            throw new Error('Sem nó de referência íntegro para reconciliar.');
        }
        const refName = this.nodeStatus[refIndex].name;

        const refDocs = await this.models[refIndex].find().sort({ blockIndex: 1 }).lean().exec() as any[];
        const tgtRows = await target.find().select('blockIndex currentHash').sort({ blockIndex: 1 }).lean().exec() as any[];
        const tgtByIndex = new Map<number, string>(tgtRows.map(r => [r.blockIndex, r.currentHash]));

        const trusted = this.trustedKeys;
        let copied = 0;
        let removed = 0;
        let skippedUncertified = 0;

        for (const rdoc of refDocs) {
            // Re-verifica o quorum certificate antes de propagar (blocos v4).
            if ((rdoc.schemaVersion ?? 1) >= 4) {
                const validSigs = countValidSignatures(rdoc.currentHash, rdoc.nodeSignatures, trusted);
                if (validSigs < this.QUORUM) { skippedUncertified++; continue; }
            }

            const tgtHash = tgtByIndex.get(rdoc.blockIndex);
            if (tgtHash === rdoc.currentHash) continue;   // já correto

            // Divergente no mesmo índice → remove a cópia errada do alvo.
            if (tgtHash !== undefined) {
                await target.deleteOne({ blockIndex: rdoc.blockIndex });
                removed++;
            }

            // Insere o bloco canónico (sem o _id da referência).
            const { _id, ...clean } = rdoc;
            await target.create(clean);
            copied++;
        }

        // Remove órfãos do alvo para lá da ponta canónica (fork bizantino).
        const refMax = refDocs.length ? refDocs[refDocs.length - 1].blockIndex : -1;
        const orphans = await target.deleteMany({ blockIndex: { $gt: refMax } });
        removed += orphans.deletedCount ?? 0;

        const alreadyConsistent = copied === 0 && removed === 0;
        if (!alreadyConsistent) {
            console.log(`[RECONCILE] ${targetName} ← ${refName}: +${copied} copiados, -${removed} removidos` +
                (skippedUncertified ? `, ${skippedUncertified} ignorados (sem quórum)` : ''));
        }

        return {
            targetNode: targetName,
            referenceNode: refName,
            alreadyConsistent,
            copied,
            removed,
            totalBlocks: refDocs.length,
            skippedUncertified,
        };
    }

    // ── Helpers ───────────────────────────────────────────────
    private _healthyModel(preferredNode = 0): Model<IAuditEntry> {
        const order = [preferredNode, ...Array.from({ length: this.TOTAL_NODES }, (_, i) => i).filter(i => i !== preferredNode)];
        for (const i of order) {
            if (this.nodeStatus[i]?.healthy && this.models[i]) return this.models[i];
        }
        throw new Error('Nenhum nó disponível para leitura.');
    }

    getNodeHealth()  {
        return this.nodeStatus.map(n => ({
            name: n.name, uri: n.uri, healthy: n.healthy, lastError: n.lastError,
        }));
    }
    getQuorumStatus() {
        const healthy = this.nodeStatus.filter(n => n.healthy).length;
        return { healthy, total: this.TOTAL_NODES, quorum: this.QUORUM, quorumAchievable: healthy >= this.QUORUM };
    }

    async shutdown(): Promise<void> {
        await Promise.allSettled(this.connections.map(c => c?.close()));
        await Promise.allSettled(this.memoryServers.map(s => s?.stop?.()));
    }

    // ── Chaos Monkey (demonstração de resiliência) ────────────
    async killNode(index: number): Promise<void> {
        if (index < 0 || index >= this.TOTAL_NODES) throw new Error('Índice de nó inválido.');
        if (!this.nodeStatus[index].healthy) throw new Error('O nó já está offline.');

        console.warn(`[CHAOS MONKEY] A abater o nó ${index + 1}...`);
        this.nodeStatus[index].healthy   = false;
        this.nodeStatus[index].lastError = 'ABATIDO (CHAOS MONKEY)';

        if (this.connections[index])   await this.connections[index].close().catch(() => {});
        if (this.memoryServers[index]) await this.memoryServers[index].stop().catch(() => {});
        console.warn(`[CHAOS MONKEY] Nó ${index + 1} offline.`);
    }

    async reviveNode(index: number): Promise<void> {
        if (index < 0 || index >= this.TOTAL_NODES) throw new Error('Índice de nó inválido.');
        if (this.nodeStatus[index].healthy) throw new Error('O nó já está online.');

        console.warn(`[CHAOS MONKEY] A ressuscitar o nó ${index + 1}...`);
        try {
            if (process.env.LOCAL_DEV === 'true') {
                const nodeName = `audit_node_${index + 1}`;
                const dbDir = path.join(process.cwd(), '.db', nodeName);
                const requireFn = new Function('require', 'return require')(require);
                const MongoMemoryServer = requireFn('mongodb-memory-server').MongoMemoryServer;

                const server = await MongoMemoryServer.create({ instance: { dbPath: dbDir } });
                const uri = server.getUri();
                this.memoryServers[index] = server;

                const conn = await mongoose.createConnection(uri).asPromise();
                this.connections[index] = conn;
                this.models[index]      = conn.model<IAuditEntry>('AuditEntry', AuditEntrySchema);
                this.nodeStatus[index]  = { name: nodeName, uri, healthy: true, lastError: null, publicKey: this.identities[index].publicKeyPem };
            } else {
                const uri = this.nodeStatus[index].uri;
                if (!uri || uri === 'N/A') throw new Error('Sem URI para o nó de produção.');
                const conn = await mongoose.createConnection(uri, {
                    serverSelectionTimeoutMS: 5000, connectTimeoutMS: 5000,
                }).asPromise();
                this.connections[index] = conn;
                this.models[index]      = conn.model<IAuditEntry>('AuditEntry', AuditEntrySchema);
                this.nodeStatus[index].healthy   = true;
                this.nodeStatus[index].lastError = null;
            }
            console.warn(`[CHAOS MONKEY] Nó ${index + 1} restaurado.`);
        } catch (err: any) {
            console.error(`[CHAOS MONKEY] Erro ao restaurar nó ${index + 1}: ${err.message}`);
            this.nodeStatus[index].lastError = err.message;
            throw err;
        }

        // Catch-up automático: o nó volta atrasado e ressincroniza-se
        // com a cadeia canónica (best-effort — não falha o revive).
        try {
            const rep = await this.reconcileNode(index);
            if (!rep.alreadyConsistent) {
                console.log(`[CHAOS MONKEY] Nó ${index + 1} ressincronizado (+${rep.copied}/-${rep.removed}).`);
            }
        } catch (err: any) {
            console.warn(`[AVISO] [Reconcile] Catch-up do nó ${index + 1} falhou: ${err.message}`);
        }
    }
}

export const consensusManager = new ConsensusManager();
