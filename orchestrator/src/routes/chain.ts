// ============================================================
// DEMS – Blockchain Chain Router
//
// GET  /api/v1/chain/blocks          — lista os últimos N blocos
// GET  /api/v1/chain/block/:hash     — detalhe de um bloco
// POST /api/v1/chain/verify-file     — prova imutabilidade de ficheiro
// GET  /api/v1/chain/integrity       — verificação completa da cadeia
// ============================================================

import { Router, Request, Response } from 'express';
import multer from 'multer';
import crypto from 'crypto';
import { z } from 'zod';
import { authenticateToken, requireRole, AuthenticatedUser } from '../middleware/auth';
import { validateBody, sha256Hex } from '../middleware/validate';
import { consensusManager, BlockSummary } from '../services/consensusManager';
import { extractPdfMetadata, extractImageMetadata } from './analyse';

const auditLogSchema = z.object({
    fileHash:     sha256Hex,
    fileName:     z.string().min(1, 'fileName obrigatório'),
    actionDetail: z.string().optional(),
    publicKey:    z.string().optional(),
    signature:    z.string().optional(),
});

// Roles with read access to the chain explorer
const CHAIN_READERS = ['Investigador', 'Perito', 'Juiz', 'Admin', 'Utilizador'] as const;

// ── Controlo de acesso à cadeia ───────────────────────────────
// Admin e Juiz são papéis de supervisão: veem todos os blocos. Os
// restantes só veem blocos em que estão ENVOLVIDOS — como autor da
// ação, ou como parte da cadeia de custódia desse ficheiro (autor de
// upload/transferência, remetente ou destinatário).
const PRIVILEGED_ROLES = ['Admin', 'Juiz'];

function isPrivileged(user: AuthenticatedUser): boolean {
    return PRIVILEGED_ROLES.includes(user.role);
}

// fileHash → conjunto de emails envolvidos nessa prova.
function buildInvolvement(blocks: BlockSummary[]): Map<string, Set<string>> {
    const involved = new Map<string, Set<string>>();
    for (const b of blocks) {
        if (!b.fileHash || b.fileHash === 'LEGACY') continue;
        let set = involved.get(b.fileHash);
        if (!set) { set = new Set<string>(); involved.set(b.fileHash, set); }
        if (b.actorEmail) set.add(b.actorEmail);
        if (b.action === 'CUSTODY_TRANSFER') {
            try {
                const m = JSON.parse(b.metadata);
                if (m.to) set.add(m.to);
                if (m.from) set.add(m.from);
            } catch { /* metadata não-JSON */ }
        }
    }
    return involved;
}

function canSee(b: BlockSummary, user: AuthenticatedUser, involved: Map<string, Set<string>>): boolean {
    if (isPrivileged(user)) return true;
    if (b.actorEmail === user.email) return true;
    const set = involved.get(b.fileHash);
    return !!(set && set.has(user.email));
}

// Filtra uma lista de blocos para o que o utilizador pode ver.
export function visibleBlocksFor(blocks: BlockSummary[], user: AuthenticatedUser): BlockSummary[] {
    if (isPrivileged(user)) return blocks;
    const involved = buildInvolvement(blocks);
    return blocks.filter(b => canSee(b, user, involved));
}

const upload = multer({ storage: multer.memoryStorage() });

export function createChainRouter(): Router {
    const router = Router();

    // ── GET /api/v1/chain/blocks ──────────────────────────────
    // Lista os últimos N blocos. Requer autenticação (qualquer role com
    // acesso de leitura ao explorador). A verificação pública de ficheiros
    // faz-se em POST /verify-file, que não requer login.
    router.get('/blocks', authenticateToken, requireRole(...CHAIN_READERS), async (req: Request, res: Response) => {
        try {
            const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
            const user  = req.user!;

            // Busca alargada e filtra por visibilidade ANTES de aplicar o
            // limite, para que o utilizador receba os seus blocos mesmo que
            // não estejam entre os mais recentes globais.
            const all = await consensusManager.getBlocks(0, 1000);
            const visible = visibleBlocksFor(all, user);
            const blocks = visible.slice(0, limit);

            return res.status(200).json({
                status:       'OK',
                totalFetched: blocks.length,
                totalVisible: visible.length,
                blocks,
            });
        } catch (err: any) {
            return res.status(503).json({ error: 'NodeUnavailable', message: err.message });
        }
    });

    // ── GET /api/v1/chain/block/:hash ─────────────────────────
    // Detalhe de um bloco específico pelo currentHash (requer login)
    router.get('/block/:hash', authenticateToken, requireRole(...CHAIN_READERS), async (req: Request, res: Response) => {
        try {
            const block = await consensusManager.getBlockByHash(req.params.hash);
            if (!block) {
                return res.status(404).json({ error: 'BlockNotFound', message: 'Nenhum bloco com esse hash.' });
            }
            // Controlo de acesso: calcula o envolvimento a partir de todos
            // os blocos do mesmo ficheiro antes de decidir.
            const user = req.user!;
            if (!isPrivileged(user)) {
                const related = await consensusManager.findAllBlocksByFileHash(block.fileHash);
                const involved = buildInvolvement(related.length ? related : [block]);
                if (!canSee(block, user, involved)) {
                    return res.status(403).json({ error: 'Forbidden', message: 'Sem acesso a este bloco.' });
                }
            }
            return res.status(200).json({ status: 'OK', block });
        } catch (err: any) {
            return res.status(503).json({ error: 'NodeUnavailable', message: err.message });
        }
    });

    // ── POST /api/v1/chain/verify-file ────────────────────────
    // Calcula SHA-256 do ficheiro enviado e verifica se está na chain.
    // NÃO requer autenticação — qualquer pessoa pode verificar.
    router.post('/verify-file', upload.single('file'), async (req: Request, res: Response) => {
        if (!req.file) {
            return res.status(400).json({ error: 'MissingFile', message: 'Envia o ficheiro no campo "file".' });
        }

        try {
            // 1. Calcular SHA-256 do ficheiro recebido
            const computedFileHash = crypto
                .createHash('sha256')
                .update(req.file.buffer)
                .digest('hex');

            // 2. Procurar bloco com esse fileHash
            const block = await consensusManager.findBlockByFileHash(computedFileHash);

            if (!block) {
                // Fazer análise forense on-the-fly para descobrir *porquê* que está alterado
                const originalName = req.file.originalname;
                const mimeType     = req.file.mimetype || 'application/octet-stream';
                let forensicHints = '';
                let signals: string[] = [];

                if (mimeType === 'application/pdf' || originalName.toLowerCase().endsWith('.pdf')) {
                    const pdfMeta = extractPdfMetadata(req.file.buffer);
                    if (pdfMeta.suspicionSignals) signals.push(...pdfMeta.suspicionSignals);
                } else if (mimeType.startsWith('image/') || originalName.toLowerCase().match(/\.(jpg|jpeg|png|gif)$/)) {
                    const imgMeta = extractImageMetadata(req.file.buffer);
                    if (imgMeta.suspicionSignals) signals.push(...imgMeta.suspicionSignals);
                }

                if (signals.length > 0) {
                    forensicHints = '<br><br><b>[!] ANÁLISE FORENSE (CSI):</b><br>' + signals.map(s => `- ${s}`).join('<br>');
                }

                return res.status(200).json({
                    verified:    false,
                    reason:      'FILE_NOT_IN_CHAIN',
                    computedFileHash,
                    message:     'Este ficheiro não foi registado nesta blockchain, ou foi adulterado.' + forensicHints,
                });
            }

            // 3. Verificar integridade da cadeia a partir desse bloco até ao topo
            const integrity = await consensusManager.verifyChainIntegrity(0);

            return res.status(200).json({
                verified:    true,
                computedFileHash,
                proof: {
                    blockIndex:         block.blockIndex,
                    blockHash:          block.currentHash,
                    previousBlockHash:  block.previousHash,
                    registeredFileHash: block.fileHash,
                    fileName:           block.fileName,
                    fileSize:           block.fileSize,
                    registeredAt:       block.timestamp,
                    registeredBy:       block.actorEmail,
                    actorRole:          block.actorRole,
                    consensusCount:     block.consensusCount,
                    schemaVersion:      block.schemaVersion,
                },
                chainIntegrity: {
                    valid:           integrity.valid,
                    totalBlocks:     integrity.totalBlocks,
                    certifiedBlocks: integrity.certifiedBlocks,
                },
                message: integrity.valid
                    ? '[OK] Ficheiro autêntico e cadeia íntegra. Conteúdo inalterado desde o registo.'
                    : '[AVISO] Ficheiro encontrado mas a integridade da cadeia está comprometida.',
            });

        } catch (err: any) {
            return res.status(500).json({ error: 'InternalServerError', message: err.message });
        }
    });

    // ── GET /api/v1/chain/integrity ───────────────────────────
    // Verificação completa da integridade da cadeia
    router.get('/integrity', async (_req: Request, res: Response) => {
        try {
            const result = await consensusManager.verifyChainIntegrity(0);
            return res.status(result.valid ? 200 : 409).json({
                status: result.valid ? 'CHAIN_INTACT' : 'CHAIN_COMPROMISED',
                ...result,
            });
        } catch (err: any) {
            return res.status(503).json({ error: 'NodeUnavailable', message: err.message });
        }
    });

    // ── POST /api/v1/chain/audit-log ──────────────────────────
    // Regista o acesso (leitura/verificação) de um ficheiro na blockchain
    router.post('/audit-log', authenticateToken, validateBody(auditLogSchema), async (req: Request, res: Response) => {
        try {
            const { fileHash, fileName, actionDetail } = req.body;

            const actor = req.user;
            if (!actor) return res.status(401).json({ error: 'Unauthorized' });

            const result = await consensusManager.broadcastAndCommit({
                action:      `ACCESS_LOG:${actionDetail || 'VERIFY'}`,
                actorID:     actor.id,
                actorEmail:  actor.email,
                actorRole:   actor.role,
                fileCID:     'N/A',
                fileName:    fileName,
                driveFileId: 'N/A',
                fileHash:    fileHash,
                fileSize:    0,
                publicKey:   req.body.publicKey || 'NONE',
                signature:   req.body.signature || 'NONE'
            });

            return res.status(201).json({
                status: 'OK',
                message: 'Acesso registado na blockchain.',
                blockIndex: result.blockIndex
            });
        } catch (err: any) {
            return res.status(500).json({ error: 'ConsensusFailed', message: err.message });
        }
    });

    return router;
}
