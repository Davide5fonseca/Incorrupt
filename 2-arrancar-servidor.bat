@echo off
title DEMS - http://localhost:8888
cd /d "%~dp0orchestrator"

echo.
echo  =====================================================
echo    DEMS - Orquestrador (Modo Local - Sem Docker)
echo  =====================================================
echo.
echo   Endpoints disponiveis:
echo     GET  http://localhost:8888/api/v1/health
echo     POST http://localhost:8888/api/v1/auth/login
echo     POST http://localhost:8888/api/v1/evidence/upload
echo.
echo   Credenciais de teste:
echo     investigador.silva@policia.pt / senha_super_segura
echo     perito.costa@policia.pt       / senha_super_segura
echo.
echo   NOTA: Na primeira vez, o MongoDB em memoria pode demorar
echo         30-60s a descarregar (~70MB). E normal.
echo.
echo   Aguarda a mensagem: "Orquestrador DEMS a correr"
echo   Carrega Ctrl+C para parar.
echo  =====================================================
echo.

REM Os segredos (JWT_SECRET, ENCRYPTION_KEY, ...) sao lidos do .env na
REM raiz do projeto via dotenv. Nao colocar segredos neste ficheiro.
set LOCAL_DEV=true
set PORT=8888

call npm run dev:local
pause
