# Incorrupt — Cadeia de Custódia Digital (DEMS)

Plataforma de gestão de prova forense digital. Cada ficheiro de prova é
registado numa cadeia de blocos encadeada por hash, replicada e **certificada
por um conjunto de nós de auditoria independentes**. O objetivo é provar, a
qualquer momento e sem confiar num único servidor, que um ficheiro não foi
alterado desde o registo e que pelo menos um quórum de nós validou esse registo.

> **Nota de honestidade.** Versões anteriores deste README descreviam o sistema
> com termos que o código não cumpria ("military grade", "BFT" sem assinaturas).
> Esta versão descreve apenas o que está realmente implementado e testado.

---

## Como funciona o consenso (BFT real)

Cada nó de auditoria é uma entidade independente com o seu próprio par de chaves
**Ed25519**. Registar um bloco passa por 4 passos:

1. **Propor** — o orquestrador monta o bloco candidato e calcula o seu SHA-256.
2. **Validar** — cada nó confere, contra a *sua própria* ponta da cadeia, que o
   `previousHash`/`blockIndex` encaixam e que o hash foi bem calculado.
3. **Assinar** — se concorda, o nó assina o hash com a sua chave privada (o "voto").
4. **Certificar** — juntam-se ≥ **quórum** assinaturas (o *quorum certificate*) e o
   bloco certificado é gravado. Sem quórum, **nada** é escrito.

Configuração: **4 nós, quórum 3** (3f+1 com f=1). Resultado prático:

- Sobrevive a **1 nó em baixo** (continua a aceitar prova).
- **Deteta e isola 1 nó que minta** — a verificação *cross-node* compara as cópias
  dos nós e identifica, por maioria, qual diverge.
- Prova, a qualquer momento, que **≥ 3 nós distintos** validaram cada bloco —
  verificando as assinaturas Ed25519, sem confiar na palavra do orquestrador.

A integridade é verificável a três níveis:

| Nível | O que prova | Endpoint |
|-------|-------------|----------|
| Encadeamento + conteúdo | nenhum bloco foi reescrito num nó | `GET /api/v1/health/chain` |
| Quorum certificate | ≥ 3 nós assinaram cada bloco | (incluído no anterior) |
| Cross-node | os nós concordam entre si; deteta o mentiroso | `GET /api/v1/health/cross-node` |

---

## Outras funcionalidades

- **SHA-256 do ficheiro** calculado localmente e gravado no bloco — é a prova de
  imutabilidade do conteúdo.
- **Análise forense pré-submissão** de PDFs/imagens (heurística — ver limitações).
- **Verificação pública** de um ficheiro contra a cadeia (`POST /api/v1/chain/verify-file`),
  sem necessidade de login.
- **Transferência de custódia** e **webhook DocuSign** registados como blocos.
- **Chaos Monkey** — abater/ressuscitar nós para demonstrar a resiliência do quórum.
- Backups opcionais para **IPFS (Pinata)** e **Google Drive (AES-256)**.

---

## Arquitetura

- **Backend:** Node.js (TypeScript), Express, Mongoose
- **Frontend:** HTML/CSS/JS vanilla (multipágina)
- **Auth:** JWT + bcrypt (PostgreSQL em produção; store em ficheiro em modo local)
- **Nós de auditoria:** 4× MongoDB (containers em produção; `mongodb-memory-server` em local)

---

## Arranque rápido (modo local, sem Docker)

```bash
# 1. Copia o template de ambiente e preenche os segredos
cp .env.example .env

# 2. Instala dependências (ou corre 1-instalar.bat no Windows)
cd orchestrator && npm install

# 3. Arranca (ou corre 2-arrancar-servidor.bat no Windows)
npm run dev:local
```

Interface em `http://localhost:8888`. Credenciais de teste:

```
investigador.silva@policia.pt / senha_super_segura
perito.costa@policia.pt       / senha_super_segura
juiz.ferreira@tribunal.pt     / senha_super_segura
```

## Produção (Docker)

```bash
docker compose up --build
```

Sobe o orquestrador, PostgreSQL e os 4 nós de auditoria numa rede isolada.

---

## Testes

```bash
cd orchestrator
npm test               # testes puros (hash + assinaturas) — rápidos
npm run test:integration   # arranca os 4 nós e testa o consenso a sério
```

A suite cobre: encadeamento de hash, deteção de adulteração de conteúdo,
quorum certificate, falha de consenso sem quórum, deteção cross-node do nó
divergente e ausência de colisão de `blockIndex` em commits concorrentes.

---

## Segurança

- Os segredos vivem em `.env` (ignorado pelo git). Ver `.env.example`.
- **A chave Pinata anterior foi exposta e tem de ser revogada** antes de qualquer
  deploy. Gera segredos novos:
  ```bash
  node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"  # JWT_SECRET
  node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"  # ENCRYPTION_KEY
  ```
- As chaves privadas dos nós ficam em `orchestrator/.keys/` (ignorado pelo git).

---

## Limitações conhecidas / trabalho futuro

- **Reconciliação (anti-entropy).** Um nó que esteve offline durante commits
  volta atrasado e **ressincroniza-se automaticamente** ao reentrar: copia os
  blocos em falta da cadeia canónica (o nó saudável com a cadeia válida mais
  longa), re-verificando o quorum certificate de cada bloco antes de o aceitar.
  Há também `POST /api/v1/health/reconcile` para forçar a reconciliação. Um nó
  bizantino (blocos divergentes) é igualmente realinhado. *Limitação:* a
  reconciliação corre no reentrar/sob pedido, não há ainda um gossip periódico
  contínuo entre nós.
- **Análise forense é heurística.** A deteção de sinais em PDF/imagem é graduada
  por severidade (`info` neutro · `suspeito` a rever · `forte`): sinais comuns em
  ficheiros legítimos — incremental updates, presença de `/Sig`, edição num editor —
  são `info` e **não** disparam alerta de adulteração; só `suspeito`/`forte` o fazem.
  Ainda assim é indício, não prova.
- **Timestamp NTP** depende de um serviço externo, com fallback para hora local.
  Para datação forte, considerar um TSA RFC 3161.
- **Assinatura do utilizador** (ECDSA no browser) é registada mas a verificação
  server-side ainda é parcial.
