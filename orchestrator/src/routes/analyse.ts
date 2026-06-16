// ============================================================
// DEMS – Document Integrity Analyser
// POST /api/v1/analyse
//
// Analisa um ficheiro ANTES de ser submetido na plataforma:
//   1. Calcula SHA-256 do ficheiro recebido
//   2. Verifica se o hash já existe na blockchain
//   3. Extrai metadados do ficheiro (PDF, Office, genérico)
//   4. Retorna diagnóstico de integridade com 3 estados:
//      - NEVER_SEEN          → nunca registado, seguro para submeter
//      - ALREADY_REGISTERED  → hash idêntico na chain (autêntico/duplicado)
//      - MODIFIED_SUSPECTED  → metadados indicam possível adulteração
// ============================================================

import { Router, Request, Response } from 'express';
import multer from 'multer';
import crypto from 'crypto';
import { consensusManager } from '../services/consensusManager';

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 200 * 1024 * 1024 }, // 200 MB
});

// ── Tipos ─────────────────────────────────────────────────────
type AnalysisStatus =
    | 'NEVER_SEEN'
    | 'ALREADY_REGISTERED'
    | 'MODIFIED_SUSPECTED';

// Severidade de cada indício. NUNCA afirmamos adulteração a partir
// de um só sinal: 'info' é neutro (comum em ficheiros legítimos),
// 'suspeito' merece revisão, 'forte' é um indício sério. A análise
// é heurística — indício, não prova.
type Severity = 'info' | 'suspeito' | 'forte';

interface ForensicSignal {
    severity: Severity;
    message:  string;
}

const RISK_BY_SEVERITY: Record<Severity, number> = { info: 0, suspeito: 1, forte: 2 };

interface FileMetadata {
    name:             string;
    size:             number;
    mimeType:         string;
    lastModified?:    string | null;
    // PDF-specific
    pdfTitle?:        string | null;
    pdfAuthor?:       string | null;
    pdfCreator?:      string | null;
    pdfProducer?:     string | null;
    pdfCreationDate?: string | null;
    pdfModDate?:      string | null;
    pdfPageCount?:    number | null;
    // Sinais (estruturados + lista de mensagens para retrocompat)
    signalDetails:    ForensicSignal[];
    suspicionSignals: string[];
}

// ── Extrator de metadados PDF (sem dependência pesada) ────────
// Faz parsing simples do header binário do PDF para extrair info do dicionário Info.
export function extractPdfMetadata(buffer: Buffer): Partial<FileMetadata> {
    const meta: Partial<FileMetadata> = { suspicionSignals: [] };

    try {
        // Verificar assinatura PDF
        const header = buffer.slice(0, 8).toString('ascii');
        if (!header.startsWith('%PDF-')) {
            return meta;
        }

        const text = buffer.toString('latin1'); // usar latin1 para evitar erros de encoding

        // Helper: extrai valor de uma chave do dicionário Info PDF
        const extractKey = (key: string): string | null => {
            // Padrão: /Key (value) ou /Key <hex>
            const patterns = [
                new RegExp(`/${key}\\s*\\(([^)]{0,500})\\)`, 'i'),
                new RegExp(`/${key}\\s*<([0-9A-Fa-f]{0,500})>`, 'i'),
            ];
            for (const pat of patterns) {
                const m = text.match(pat);
                if (m && m[1]) {
                    const val = m[1].trim();
                    if (val.startsWith('feff') || val.match(/^[0-9a-f]+$/i)) {
                        // hex decode (UTF-16BE ou hex)
                        try {
                            const bytes = Buffer.from(val, 'hex');
                            return bytes.toString('utf16le').replace(/\0/g, '').trim() || null;
                        } catch { return val; }
                    }
                    return val || null;
                }
            }
            return null;
        };

        meta.pdfTitle    = extractKey('Title');
        meta.pdfAuthor   = extractKey('Author');
        meta.pdfCreator  = extractKey('Creator');   // app que criou o documento original
        meta.pdfProducer = extractKey('Producer');  // app que gerou o PDF final
        meta.pdfCreationDate = extractKey('CreationDate');
        meta.pdfModDate      = extractKey('ModDate');

        // Contar páginas
        const pageCountMatch = text.match(/\/N\s+(\d+)/);
        if (pageCountMatch) meta.pdfPageCount = parseInt(pageCountMatch[1]);

        // ── Indícios (heurística — indício, não prova) ────────
        const signals: ForensicSignal[] = [];
        const add = (severity: Severity, message: string) => signals.push({ severity, message });

        // 1. Criação != Modificação. Comum (qualquer reedição legítima
        //    altera a ModDate), por isso é apenas suspeito.
        if (meta.pdfCreationDate && meta.pdfModDate) {
            const norm = (d: string) => d.replace(/[^0-9]/g, '').substring(0, 14);
            if (norm(meta.pdfCreationDate) !== norm(meta.pdfModDate)) {
                add('suspeito', 'Datas de criação e modificação diferem: o documento foi alterado após ter sido criado (frequente em documentos legítimos revistos).');
            }
        }

        // 2. Produtor != Criador → reprocessado/convertido. Neutro.
        if (meta.pdfCreator && meta.pdfProducer) {
            const creatorLower  = meta.pdfCreator.toLowerCase();
            const producerLower = meta.pdfProducer.toLowerCase();
            const knownEditors = ['acrobat', 'word', 'libreoffice', 'openoffice', 'ghostscript', 'pdfedit', 'pdfill'];
            if (knownEditors.some(e => producerLower.includes(e) && !creatorLower.includes(e))) {
                add('info', `Reprocessado/convertido por "${meta.pdfProducer}" (comum; por si só não indica adulteração).`);
            }
        }

        // 3. Sem metadados → pode ser limpeza deliberada ou exportador
        //    que não os escreve. Neutro.
        if (!meta.pdfCreationDate && !meta.pdfAuthor && !meta.pdfCreator) {
            add('info', 'Sem metadados de criação: podem ter sido removidos, ou o exportador não os escreve.');
        }

        // 4. Editores online no produtor. Merecem revisão.
        if (meta.pdfProducer) {
            const onlineTools = ['pdfescape', 'sejda', 'smallpdf', 'ilovepdf', 'pdfcandy', 'pdffiller'];
            const found = onlineTools.find(t => meta.pdfProducer!.toLowerCase().includes(t));
            if (found) {
                add('suspeito', `Produzido por um editor online ("${meta.pdfProducer}").`);
            }
        }

        // 5. Múltiplos %%EOF (incremental updates). NORMAL em PDFs
        //    assinados ou revistos — é informativo, não "adulteração".
        const eofCount = (text.match(/%%EOF/g) || []).length;
        const hasSig   = text.includes('/Sig');
        if (eofCount > 1) {
            add('info', `${eofCount} versões internas (incremental updates): o ficheiro foi atualizado após a versão inicial. Normal em documentos assinados ou revistos.`);
        }

        // 6. Assinatura digital presente. É garantia, não suspeita —
        //    e assinar adiciona legitimamente um incremental update.
        if (hasSig) {
            add('info', 'Contém um campo de assinatura digital (/Sig).');
        }

        // 7. Anotações sobre o documento. Podem ser revisão legítima
        //    ou ocultação — merecem revisão (suspeito), não veredicto.
        const annotations: Array<[string[], string]> = [
            [['/Underline'], 'sublinhados'],
            [['/Highlight'], 'destaques (highlight)'],
            [['/FreeText'],  'caixas de texto'],
            [['/Ink'],       'desenhos à mão livre'],
            [['/Stamp'],     'carimbos ou imagens sobrepostas'],
            [['/Square', '/Circle', '/Polygon'], 'formas geométricas'],
            [['/Widget'],    'campos de formulário'],
        ];
        const foundAnnot = annotations
            .filter(([keys]) => keys.some(k => text.includes(k)))
            .map(([, label]) => label);
        if (foundAnnot.length > 0) {
            add('suspeito', `Anotações adicionadas sobre o documento (${foundAnnot.join(', ')}): conteúdo acrescentado após a criação — pode ser revisão legítima ou ocultar texto.`);
        }

        meta.signalDetails    = signals;
        (meta as any).suspicionSignals = signals.map(s => s.message);

    } catch {
        // Parsing falhou — continua sem metadados
    }

    return meta;
}

// ── Extrator Forense de Imagens ───────────────────────────────
export function extractImageMetadata(buffer: Buffer): Partial<FileMetadata> {
    const signals: ForensicSignal[] = [];

    // Ler buffer como latin1 para pesquisar assinaturas no binário.
    const binaryStr = buffer.toString('latin1');

    // Presença de software de edição: ter sido aberto/exportado num
    // editor NÃO é adulteração (exportar uma foto do Lightroom é
    // legítimo). É informativo — indica origem, não manipulação.
    const editors = ['Photoshop', 'GIMP', 'Canva', 'Lightroom', 'Paint.NET', 'Pixelmator'];
    const found = editors.filter(e => binaryStr.includes(e));
    if (found.length > 0) {
        signals.push({
            severity: 'info',
            message: `Editado/exportado com ${found.join(', ')}: indica a origem do ficheiro, não prova adulteração.`,
        });
    }

    return { signalDetails: signals, suspicionSignals: signals.map(s => s.message) };
}

// ── Router ────────────────────────────────────────────────────
export function createAnalyseRouter(): Router {
    const router = Router();

    // ── POST /api/v1/analyse ──────────────────────────────────
    // Público — não requer autenticação.
    // Corpo: multipart/form-data com campo "file"
    router.post('/', upload.single('file'), async (req: Request, res: Response) => {
        if (!req.file) {
            return res.status(400).json({
                error:   'MissingFile',
                message: 'Envia o ficheiro no campo "file" (multipart/form-data).',
            });
        }

        try {
            const buffer       = req.file.buffer;
            const originalName = req.file.originalname;
            const mimeType     = req.file.mimetype || 'application/octet-stream';
            const fileSize     = buffer.length;

            // 1. SHA-256 do ficheiro
            const fileHash = crypto.createHash('sha256').update(buffer).digest('hex');

            // 2. Consultar blockchain
            const existingBlocks = await consensusManager.findAllBlocksByFileHash(fileHash);

            // 3. Extrair metadados
            const fileMeta: FileMetadata = {
                name:             originalName,
                size:             fileSize,
                mimeType,
                signalDetails:    [],
                suspicionSignals: [],
            };

            let extracted: Partial<FileMetadata> | null = null;
            if (mimeType === 'application/pdf' || originalName.toLowerCase().endsWith('.pdf')) {
                extracted = extractPdfMetadata(buffer);
            } else if (mimeType.startsWith('image/') || originalName.toLowerCase().match(/\.(jpg|jpeg|png|gif)$/)) {
                extracted = extractImageMetadata(buffer);
            }
            if (extracted) Object.assign(fileMeta, extracted);

            // 4. Determinar status. Só sinais 'suspeito'/'forte' contam
            //    para "possível adulteração". Sinais 'info' (incremental
            //    updates, editor, etc.) são comuns em ficheiros legítimos.
            const concerning = fileMeta.signalDetails.filter(s => s.severity !== 'info');
            const maxRisk    = fileMeta.signalDetails.reduce((m, s) => Math.max(m, RISK_BY_SEVERITY[s.severity]), 0);
            const riskLevel  = (['NONE', 'LOW', 'HIGH'] as const)[maxRisk];

            let status: AnalysisStatus;
            let verdict: string;
            let verdictDetail: string;

            if (existingBlocks.length > 0) {
                // Hash idêntico na chain → ficheiro autêntico ou duplicado
                status       = 'ALREADY_REGISTERED';
                verdict      = '[OK] FICHEIRO JÁ REGISTADO NA BLOCKCHAIN';
                verdictDetail = `Este ficheiro (ou uma cópia byte-a-byte idêntica) foi registado ${existingBlocks.length}x na blockchain. O seu conteúdo é autêntico e não foi alterado desde o registo.`;
            } else if (concerning.length > 0) {
                // Hash não está na chain E há indícios que merecem revisão.
                status       = 'MODIFIED_SUSPECTED';
                verdict      = '[AVISO] INDÍCIOS A REVER ANTES DE SUBMETER';
                verdictDetail = `Este ficheiro não consta da blockchain e os metadados apresentam ${concerning.length} indício(s) que merecem revisão. Heurística — indício, não prova. Confirma o documento antes de o submeter.`;
            } else {
                // Hash não está na chain, sem indícios relevantes (pode
                // ter sinais 'info', que são neutros).
                status       = 'NEVER_SEEN';
                verdict      = '[OK] FICHEIRO NOVO — PRONTO PARA SUBMETER';
                verdictDetail = fileMeta.signalDetails.length > 0
                    ? 'Este ficheiro nunca foi registado nesta blockchain. Há apenas sinais informativos (comuns em ficheiros legítimos), sem indício de adulteração.'
                    : 'Este ficheiro nunca foi registado nesta blockchain. Não foram detetados sinais relevantes nos metadados.';
            }

            // 5. Informação de integridade da chain
            let chainIntegrity = null;
            try {
                chainIntegrity = await consensusManager.verifyChainIntegrity(0);
            } catch { /* não fatal */ }

            console.log(`[ANALYSE] ${originalName} | hash: ${fileHash.substring(0, 16)}... | status: ${status}`);

            return res.status(200).json({
                status,
                verdict,
                verdictDetail,
                analysis: {
                    fileHash,
                    fileSize,
                    fileName:  originalName,
                    mimeType,
                    // Historial na blockchain
                    foundInChain:    existingBlocks.length > 0,
                    chainOccurrences: existingBlocks.length,
                    chainHistory: existingBlocks.map(b => ({
                        blockIndex:    b.blockIndex,
                        blockHash:     b.currentHash,
                        registeredAt:  b.timestamp,
                        registeredBy:  b.actorEmail,
                        actorRole:     b.actorRole,
                        action:        b.action,
                        consensusCount: b.consensusCount,
                    })),
                    // Metadados do ficheiro
                    metadata: {
                        pdfTitle:        fileMeta.pdfTitle    ?? null,
                        pdfAuthor:       fileMeta.pdfAuthor   ?? null,
                        pdfCreator:      fileMeta.pdfCreator  ?? null,
                        pdfProducer:     fileMeta.pdfProducer ?? null,
                        pdfCreationDate: fileMeta.pdfCreationDate ?? null,
                        pdfModDate:      fileMeta.pdfModDate  ?? null,
                        pdfPageCount:    fileMeta.pdfPageCount ?? null,
                    },
                    // Sinais encontrados (lista de mensagens + estruturados)
                    suspicionSignals: fileMeta.suspicionSignals,
                    suspicionCount:   concerning.length,
                    signalDetails:    fileMeta.signalDetails,
                    riskLevel,
                },
                chainIntegrity,
                analyzedAt: new Date().toISOString(),
            });

        } catch (err: any) {
            console.error(`[ERRO ANALYSE] Erro: ${err.message}`);
            return res.status(500).json({ error: 'InternalServerError', message: err.message });
        }
    });

    return router;
}
