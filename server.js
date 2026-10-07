const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
require('dotenv').config();
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { Pool } = require('pg');
const http = require('http'); // F: usado pelo aquecedor de cache interno

const app = express();

// ==========================================
// 🛡️ VALIDAÇÃO DE SEGURANÇA (Fail Secure)
// ==========================================
if (!process.env.SESSION_SECRET || !process.env.SNOOZE_HOOK_TOKEN) {
    console.error("🚨 ERRO FATAL DE SEGURANÇA: Variáveis SESSION_SECRET ou SNOOZE_HOOK_TOKEN ausentes no ambiente.");
    console.error("O servidor não será iniciado usando chaves de fallback públicas. Configure o arquivo .env!");
    process.exit(1); // Derruba a aplicação instantaneamente
}

// ==========================================
// 1. BLINDAGEM DE SEGURANÇA BASE E BANCO DE DADOS
// ==========================================
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: { success: false, error: "Muitas requisições. Aguarde alguns minutos." }
});
app.use('/api/', limiter);

// Conexão de Leitura com PostgreSQL (Chatwoot)
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    ssl: false, // SSL desligado conforme configurado
    application_name: 'dash-gex', // identifica as conexoes do Dash no Postgres (pg_stat_activity)
    max: 4,                       // teto de conexoes do Dash (reduzido de 10 p/ 4 em 01/10/2026 p/ nao pesar no banco do Chatwoot)
    statement_timeout: 45000,     // mata query travada (com folga p/ as consultas pesadas legitimas)
    idleTimeoutMillis: 10000,     // fecha conexao ociosa em 10s (evita reusar conexao ja derrubada pelo servidor)
    connectionTimeoutMillis: 30000, // tolerancia p/ pegar conexao sob carga (evita "connection timeout")
    keepAlive: true               // mantem o TCP vivo (evita "connection terminated unexpectedly")
});

// 🛡️ BLINDAGEM (01/10/2026) — o Dash só LÊ o banco do Chatwoot e não pode prejudicar o atendimento
// 1) Conexão perdida (banco reiniciou/caiu): só registra no log. Sem isto o processo do Dash cai junto.
pool.on('error', (err) => { console.error('⚠️ Pool do Postgres: conexão perdida (o Dash continua no ar):', err && err.message); });
// 2) Freio: 3 falhas seguidas de banco (timeout/queda) => o Dash para de consultar por 3 min e as telas recebem o último dado guardado.
const FREIO = { falhas: 0, ate: 0, acionamentos: 0, ultimo_erro: '', ultimo_acionamento: 0 };
const FREIO_LIMITE = 3, FREIO_PAUSA_MS = 3 * 60 * 1000;
function erroDeSaudeDoBanco(e) {
    const cod = String((e && e.code) || ''), msg = String((e && e.message) || '').toLowerCase();
    return ['57014', '57P01', '57P02', '57P03', '53300', '53400'].includes(cod) || cod.startsWith('08')
        || ['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'EPIPE', 'EHOSTUNREACH', 'ENETUNREACH'].includes(cod)
        || msg.includes('timeout') || msg.includes('connection terminated') || msg.includes('too many clients');
}
const _poolQueryOriginal = pool.query.bind(pool);
pool.query = function (...args) {
    if (typeof args[args.length - 1] === 'function') return _poolQueryOriginal(...args);   // estilo callback: segue igual
    if (Date.now() < FREIO.ate) {
        const e = new Error('Banco do Chatwoot instável: o Dash pausou as consultas por alguns minutos para não sobrecarregar.');
        e.code = 'FREIO_DASH';
        return Promise.reject(e);
    }
    return _poolQueryOriginal(...args).then((r) => { FREIO.falhas = 0; return r; }, (e) => {
        if (erroDeSaudeDoBanco(e)) {
            FREIO.falhas += 1; FREIO.ultimo_erro = String((e && e.message) || e).slice(0, 160);
            if (FREIO.falhas >= FREIO_LIMITE) {
                FREIO.ate = Date.now() + FREIO_PAUSA_MS; FREIO.acionamentos += 1; FREIO.ultimo_acionamento = Date.now();
                FREIO.falhas = FREIO_LIMITE - 1;   // depois da pausa, 1 falha nova já pausa de novo
                console.warn(`🛑 Freio do banco ACIONADO por ${FREIO_PAUSA_MS / 60000} min — último erro: ${FREIO.ultimo_erro}`);
            }
        }
        throw e;
    });
};

// 🔥 OTIMIZAÇÃO EXTREMA: Query direta usando os índices do banco de dados (ignorando excluídos/privados)
const queryTickets = `
    SELECT
        u.id AS agente_id,
        u.name AS agente,
        DATE(m.created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo') AS dia,
        COUNT(*) AS tickets
    FROM messages m
    INNER JOIN users u ON u.id = m.sender_id
    WHERE m.sender_type = 'User'
        AND m.account_id = 1
        AND m.message_type = 1
        AND m.private = FALSE
        AND m.content IS NOT NULL
        AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE
        AND m.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
        AND m.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
    GROUP BY u.id, u.name, DATE(m.created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo')
`;

// Funções utilitárias de Data para o Banco
function unixParaYYYYMMDD(unixSecs) {
    return new Date(unixSecs * 1000).toLocaleDateString('en-CA', { timeZone: 'America/Sao_Paulo' });
}

function formatarDataSQL(dataObj) {
    const ano = dataObj.getFullYear();
    const mes = String(dataObj.getMonth() + 1).padStart(2, '0');
    const dia = String(dataObj.getDate()).padStart(2, '0');
    return `${ano}-${mes}-${dia}`;
}

// ==========================================
// 2. SISTEMA DE LOGIN GOOGLE E SESSÕES
// ==========================================
app.get('/ping', (req, res) => res.status(200).send('Servidor GEX Ativo!'));

app.set('trust proxy', 1);

app.use(session({
    secret: process.env.SESSION_SECRET || 'chave_reserva_gex',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // Sessão guardada por 30 dias
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback',
    proxy: true 
},
function(accessToken, refreshToken, profile, cb) {
    const email = profile.emails && profile.emails[0] ? profile.emails[0].value : '';
    if (email.endsWith('@institutoexperience.com.br')) return cb(null, profile);
    else return cb(null, false, { message: 'Acesso negado.' });
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Servir logo público para a tela de login ANTES do bloqueio
app.get('/logo.jpg', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logo.jpg')));

// 🎨 TELA DE LOGIN ESTILIZADA GEX
app.get('/login', (req, res) => {
    if (req.isAuthenticated()) return res.redirect('/');
    res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR" class="dark">
    <head>
        <meta charset="UTF-8">
        <title>Login - Dash GEX</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;800&family=Roboto:wght@400;700;900&display=swap" rel="stylesheet">
    </head>
    <body class="bg-[#020617] text-white flex items-center justify-center min-h-screen font-['Roboto'] relative overflow-hidden">
        <div class="absolute inset-0 z-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCI+PGNpcmNsZSBjeD0iMSIgY3k9IjEiIHI9IjEiIGZpbGw9InJnYmEoMjU1LDI1NSwyNTUsMC4wNSkiLz48L3N2Zz4=')] bg-[length:24px_24px]"></div>
        <div class="absolute -top-[120px] -right-[150px] rotate-[40deg] flex flex-col gap-3 opacity-20">
            <div class="w-[800px] h-[85px] bg-[#1b52af] rounded-full mb-2"></div>
            <div class="w-[800px] h-[15px] bg-[#1b52af] rounded-full"></div>
            <div class="w-[800px] h-[15px] bg-[#1b52af] rounded-full"></div>
        </div>
        <div class="z-10 bg-[#0a0f1c] p-10 rounded-[2rem] shadow-2xl border border-gray-800 max-w-md w-full text-center backdrop-blur-xl">
            <img src="/logo.jpg" alt="Logo GEX" class="w-24 h-24 mx-auto rounded-2xl mb-6 shadow-[0_0_20px_rgba(34,167,240,0.3)] object-cover">
            <h1 class="text-3xl font-black mb-2 tracking-tight">Dash GEX</h1>
            <p class="text-gray-400 font-medium mb-10 text-sm">Acesso restrito à operação.</p>
            
            <a href="/auth/google" class="flex items-center justify-center gap-3 bg-white text-gray-900 font-bold py-3.5 px-6 rounded-xl hover:bg-gray-100 transition-all hover:scale-105 shadow-[0_10px_25px_rgba(255,255,255,0.1)]">
                <svg class="w-5 h-5" viewBox="0 0 24 24">
                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 15.02 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                </svg>
                Continuar com o Google
            </a>
        </div>
    </body>
    </html>
    `);
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => { res.redirect('/'); });

app.get('/logout', (req, res) => {
    req.logout(() => { res.redirect('/login'); });
});

// Trava Global
const verificarLogin = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    if (req.originalUrl.startsWith('/api/')) return res.status(401).json({ success: false, error: 'Não autorizado' });
    res.redirect('/login');
};

// Identidade e Permissões do Usuário (RBAC)
app.get('/api/me', verificarLogin, (req, res) => {
    const email = (req.user.emails && req.user.emails[0] ? req.user.emails[0].value : '').toLowerCase();
    const nome = req.user.displayName;
    
    // Lista de ADMs cadastrada no seu painel da Render.com
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    
    res.json({ 
        success: true, 
        user: { 
            nome: nome, 
            email: email, 
            role: adms.includes(email) ? 'admin' : 'agente' 
        } 
    });
});

// ==========================================
// 4.5. SISTEMA DE CACHE INTELIGENTE BLINDADO (Anti-DoS)
// ==========================================
let cacheMemoria = {};
let tempoRotas = {}; // ultimo tempo (ms) de cada rota — alimenta o Raio-X de Desempenho
const MAX_CACHE_KEYS = 200; // Trava de segurança para impedir estouro de RAM

const emAndamento = {};          // 🛡️ consultas rodando agora (por URL) — quem pedir a mesma coisa espera e aproveita o resultado
let consultasAproveitadas = 0, dadosGuardadosServidos = 0;
const cacheMiddleware = (req, res, next) => {
    const agora = Date.now();
    // 🔄 Refresh manual (líder clicou Atualizar/Sincronizar/Recarregar): fura o cache e busca dados frescos.
    // O tempo de 15–30m continua como fallback passivo (agentes / navegação normal).
    let bypass = false, chaveUrl = req.originalUrl;
    try {
        const u = new URL(req.originalUrl, 'http://x');
        bypass = u.searchParams.get('fresh') === '1';
        u.searchParams.delete('fresh');
        const qs = u.searchParams.toString();
        chaveUrl = u.pathname + (qs ? '?' + qs : '');
    } catch (e) { chaveUrl = req.originalUrl; }

    if (chaveUrl.includes('/api/raio-x-perf')) return next(); // Raio-X de Desempenho: sempre ao vivo, nunca cacheado

    // 🛡️ PROTEÇÃO DoS: Se o cache inchar de forma anormal, limpa a memória
    if (Object.keys(cacheMemoria).length > MAX_CACHE_KEYS) {
        console.warn("🚨 ALERTA: Limite de cache atingido. Esvaziando memória para prevenir Memory Exhaustion (DoS).");
        cacheMemoria = {}; 
    }

    // Lógica inteligente: Planilhas = 15 min / Banco de Dados (Tickets puros) = 30 min
    let tempoCacheMinutos = 30; 
    if (chaveUrl.includes('/api/qualidade') || chaveUrl.includes('/api/retencao') || chaveUrl.includes('/api/sinalizacoes')) {
        tempoCacheMinutos = 15;
    }

    if (!bypass && cacheMemoria[chaveUrl] && (agora - cacheMemoria[chaveUrl].tempo < tempoCacheMinutos * 60 * 1000)) {
        console.log(`⚡ Retornando do Cache (${tempoCacheMinutos}m): ${chaveUrl}`);
        return res.json(cacheMemoria[chaveUrl].data);
    }

    // 🛡️ A mesma consulta já está rodando (outra pessoa abriu a mesma tela agora): espera ela terminar e usa o mesmo resultado, sem rodar de novo no banco
    if (req.method === 'GET' && emAndamento[chaveUrl]) {
        consultasAproveitadas += 1;
        return emAndamento[chaveUrl].then((d) => (d && d.success) ? res.json(d) : next()).catch(() => next());
    }
    let liberarEmAndamento = null;
    if (req.method === 'GET') {
        emAndamento[chaveUrl] = new Promise((resolve) => { liberarEmAndamento = resolve; });
        const encerrar = () => { if (liberarEmAndamento) { const liberar = liberarEmAndamento; liberarEmAndamento = null; delete emAndamento[chaveUrl]; liberar(null); } };
        res.on('finish', encerrar);
        res.on('close', encerrar);
    }

    const sendJsonOriginal = res.json;
    res.json = function(dados) {
        if (dados && dados.success) {
            cacheMemoria[chaveUrl] = { tempo: agora, data: dados };
            tempoRotas[chaveUrl] = Date.now() - agora;
            console.log(`🔄 Dados Atualizados e Cache Salvo (${tempoCacheMinutos}m): ${chaveUrl}`);
        }
        // 🛡️ GET que falhou por erro do servidor/banco e já tinha dado guardado: entrega o último dado bom (marcado) em vez do erro
        if (!(dados && dados.success) && req.method === 'GET' && this.statusCode >= 500 && cacheMemoria[chaveUrl]) {
            const idadeMin = Math.round((Date.now() - cacheMemoria[chaveUrl].tempo) / 60000);
            dadosGuardadosServidos += 1;
            console.warn(`🛟 Banco falhou — entregando o último dado bom (de ${idadeMin} min atrás): ${chaveUrl}`);
            this.status(200);
            dados = Object.assign({}, cacheMemoria[chaveUrl].data, { dados_guardados: true, dados_guardados_min: idadeMin });
        }
        if (liberarEmAndamento) { const liberar = liberarEmAndamento; liberarEmAndamento = null; delete emAndamento[chaveUrl]; liberar(dados); }
        sendJsonOriginal.call(this, dados);
    };
    next();
};

// ==========================================
// 🅱️ PLANO B — CAPTURA DE SNOOZE (grava no GOOGLE SHEETS; NÃO toca no banco do Chatwoot)
// O webhook do Chatwoot manda pra cá no momento do adiamento.
// ==========================================
const SNOOZE_SHEET_ID = (process.env.GOOGLE_SHEET_ID_SNOOZE_LOG || process.env.GOOGLE_SHEET_ID_SNOOZE || '1GD58KTkrCIJUdU0TLQQfg9SbI5jXi3C803RLXWL698M').trim();
const SNOOZE_ABA = 'snooze_log';
const SNOOZE_TOKEN = process.env.SNOOZE_HOOK_TOKEN || 'gex-snooze-2026';
const snoozeRawRecentes = []; // últimos payloads crus (em memória) pra conferir o formato
let snoozeHeaderOk = false;

function getSheetsRW() {
    const privateKey = (process.env.GOOGLE_PRIVATE_KEY || '').replace(/\\n/g, '\n').replace(/"/g, '').trim();
    const auth = new google.auth.GoogleAuth({
        credentials: { client_email: (process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || '').trim(), private_key: privateKey },
        scopes: ['https://www.googleapis.com/auth/spreadsheets'] // escrita só nesta planilha (a service account só tem Editor aqui)
    });
    return google.sheets({ version: 'v4', auth });
}

async function garantirCabecalhoSnooze(sheets) {
    if (snoozeHeaderOk) return;
    try {
        const r = await sheets.spreadsheets.values.get({ spreadsheetId: SNOOZE_SHEET_ID, range: `${SNOOZE_ABA}!A1:F1` });
        if (!r.data.values || r.data.values.length === 0) {
            await sheets.spreadsheets.values.update({
                spreadsheetId: SNOOZE_SHEET_ID, range: `${SNOOZE_ABA}!A1`, valueInputOption: 'RAW',
                requestBody: { values: [['capturado_em', 'conversation_id', 'display_id', 'snoozed_until', 'agente', 'status']] }
            });
        }
        snoozeHeaderOk = true;
    } catch (e) { /* segue mesmo sem cabeçalho */ }
}

app.post('/hook/snooze/:token', express.json({ limit: '3mb' }), async (req, res) => {
    if (req.params.token !== SNOOZE_TOKEN) return res.status(401).json({ ok: false, motivo: 'token invalido' });
    const body = req.body || {};
    snoozeRawRecentes.unshift({ recebido_em: new Date().toISOString(), body });
    if (snoozeRawRecentes.length > 10) snoozeRawRecentes.pop();
    res.json({ ok: true }); // responde já; o Chatwoot não espera o Google Sheets

    try {
        const conv = body.conversation || body || {};
        const status = conv.status || body.status;
        const snoozedUntil = conv.snoozed_until != null ? conv.snoozed_until
            : (body.snoozed_until != null ? body.snoozed_until
            : (conv.additional_attributes && conv.additional_attributes.snoozed_until) || null);
        if (String(status) !== 'snoozed') return; // grava TODO adiamento (com tempo OU 'até a próxima resposta')

        const convId = conv.id || body.id || '';
        const displayId = conv.display_id || body.display_id || '';
        const agente = (conv.meta && conv.meta.assignee && conv.meta.assignee.name)
            || (body.meta && body.meta.assignee && body.meta.assignee.name) || '';

        const sheets = getSheetsRW();
        await garantirCabecalhoSnooze(sheets);
        await sheets.spreadsheets.values.append({
            spreadsheetId: SNOOZE_SHEET_ID, range: `${SNOOZE_ABA}!A:F`,
            valueInputOption: 'RAW', insertDataOption: 'INSERT_ROWS',
            requestBody: { values: [[new Date().toISOString(), String(convId), String(displayId), (snoozedUntil ? String(snoozedUntil) : ''), String(agente), String(status)]] }
        });
    } catch (e) {
        console.error('[snooze-hook] falha ao gravar no Sheets:', e.message);
    }
});

// F: aquecedor de cache (warmer) — revalida em background as rotas pesadas do Postgres, sem o admin esperar.
// Requisicao interna (localhost + token) finge um admin so-leitura; o ultimoAcessoApi so conta acesso REAL.
const WARM_TOKEN = process.env.WARM_TOKEN || 'gex-warm-2026-interno';
const EMAIL_ADM_WARM = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',')[0].trim();
let ultimoAcessoApi = 0;
app.use('/api', (req, res, next) => {
    if (req.headers['x-warm-token'] === WARM_TOKEN) {
        req.user = { emails: [{ value: EMAIL_ADM_WARM }], role: 'admin' };
        req.isAuthenticated = () => true;
    } else {
        ultimoAcessoApi = Date.now();
    }
    next();
});
app.use('/api', verificarLogin, cacheMiddleware);
app.use(verificarLogin, express.static(path.join(__dirname, 'public')));

// ==========================================
// 5. FUNÇÕES COMPARTILHADAS (RETENÇÃO E TICKETS)
// ==========================================
const parseMoeda = (val) => {
    if (!val) return 0;
    const limpo = String(val).replace(/[^0-9,-]/g, '').replace(',', '.');
    return parseFloat(limpo) || 0;
};
const parsePct = (val) => {
    if (!val) return 0;
    const limpo = String(val).replace('%', '').replace(',', '.').trim();
    return parseFloat(limpo) || 0;
};
const normalizeNome = (nome) => {
    if (!nome) return '';
    return String(nome).toUpperCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/\s*[-(\[|].*/, '').replace(/\s+/g, ' ').trim();
};
const vincularTickets = (nomePlanilha, ticketsMap, totalSemanas) => {
    const nomeLimpo = normalizeNome(nomePlanilha);
    let agenteEncontrado = ticketsMap[nomeLimpo];

    if (!agenteEncontrado) {
        const partes = nomeLimpo.split(' ');
        const primeiroNome = partes[0];
        const candidatos = Object.keys(ticketsMap).filter(k => k.split(' ')[0] === primeiroNome);
        if (candidatos.length === 1) agenteEncontrado = ticketsMap[candidatos[0]];
        else if (candidatos.length > 1 && partes.length > 1) {
            for (let c of candidatos) {
                const ultimoPlanilha = partes[partes.length - 1];
                if (c.includes(ultimoPlanilha) || c.includes(partes[1])) {
                    agenteEncontrado = ticketsMap[c];
                    break;
                }
            }
        }
    }
    if (agenteEncontrado) {
        if (!agenteEncontrado.hist_tickets) agenteEncontrado.hist_tickets = new Array(totalSemanas).fill(0);
        return agenteEncontrado;
    }
    return { totalMes: 0, hist_tickets: new Array(totalSemanas).fill(0) };
};

// ==========================================
// 6. ROTA DE RETENÇÃO (PLANILHA A)
// ==========================================
app.get('/api/retencao', async (req, res) => {
    try {
        const agoraBR = new Date(new Date().toLocaleString("en-US", {timeZone: "America/Sao_Paulo"}));
        const anoPlanilha = 2026;

        let privateKey = (process.env.GOOGLE_PRIVATE_KEY || '').replace(/\\n/g, '\n').replace(/"/g, '').trim();
        const auth = new google.auth.GoogleAuth({
            credentials: { client_email: (process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || '').trim(), private_key: privateKey },
            scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
        });
        const sheets = google.sheets({ version: 'v4', auth });
        const sheetId = (process.env.GOOGLE_SHEET_ID || '').trim();

        // --- Abas de "Metas" disponíveis (seletor de mês) ---
        const MESES_PT = ['Janeiro','Fevereiro','Março','Abril','Maio','Junho','Julho','Agosto','Setembro','Outubro','Novembro','Dezembro'];
        let abasDisponiveis = [];
        try {
            const metaInfo = await sheets.spreadsheets.get({ spreadsheetId: sheetId, fields: 'sheets.properties.title' });
            abasDisponiveis = (metaInfo.data.sheets || []).map(sh => sh.properties.title).filter(t => /Metas/i.test(t) && MESES_PT.some(mm => t.toLowerCase().includes(mm.toLowerCase())));
        } catch (e) {}

        // --- Meses selecionados: ?aba= (1 ou vários), validados; padrão Setembro ---
        const PADRAO_ABA = "📊 Análise | Metas | Outubro";
        let selecionadas = req.query.aba;
        if (typeof selecionadas === 'string') selecionadas = [selecionadas];
        if (!Array.isArray(selecionadas)) selecionadas = [];
        selecionadas = selecionadas.map(a => (a || '').trim()).filter(a => abasDisponiveis.includes(a));
        if (selecionadas.length === 0) selecionadas = abasDisponiveis.includes(PADRAO_ABA) ? [PADRAO_ABA] : (abasDisponiveis.length ? [abasDisponiveis[abasDisponiveis.length - 1]] : [PADRAO_ABA]);

        // 🔒 Multi-mês/comparativo é só pra ADMIN. Não-admin vê sempre o mês atual (como sempre).
        const emailUserRet = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
        const admsRet = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
        const isAdminRet = admsRet.includes(emailUserRet);
        if (!isAdminRet) selecionadas = abasDisponiveis.includes(PADRAO_ABA) ? [PADRAO_ABA] : (abasDisponiveis.length ? [abasDisponiveis[abasDisponiveis.length - 1]] : [PADRAO_ABA]);

        const mesDaAba = (aba) => { const i = MESES_PT.findIndex(mm => aba.toLowerCase().includes(mm.toLowerCase())); return i >= 0 ? i : 8; };
        const labelDaAba = (aba) => aba.split('|').pop().trim();

        const processarMes = async (aba) => {
            const mesP = mesDaAba(aba);
            const diasNoMes = new Date(anoPlanilha, mesP + 1, 0).getDate();
            const dIni = new Date(anoPlanilha, mesP, 1);
            const dFim = new Date(anoPlanilha, mesP + 1, 0);
            const domBase = new Date(dIni.getTime());
            domBase.setUTCDate(dIni.getUTCDate() - dIni.getUTCDay());
            const nSem = Math.max(1, Math.floor(((dFim.getTime() - domBase.getTime()) / 86400000) / 7) + 1);

            const [tkRes, shRes] = await Promise.all([
                pool.query(queryTickets, [formatarDataSQL(dIni), formatarDataSQL(dFim)]),
                sheets.spreadsheets.values.get({ spreadsheetId: sheetId, range: `'${aba}'!A1:T300` })
            ]);

            const tkMap = {};
            tkRes.rows.forEach(row => {
                const nb = normalizeNome(row.agente);
                if (!tkMap[nb]) tkMap[nb] = { totalMes: 0, hist_tickets: new Array(nSem).fill(0) };
                tkMap[nb].totalMes += parseInt(row.tickets) || 0;
                const dd = new Date(String(row.dia).split('T')[0] + 'T12:00:00Z');
                const idx = Math.floor(((dd.getTime() - domBase.getTime()) / 86400000) / 7);
                if (idx >= 0 && idx < nSem) tkMap[nb].hist_tickets[idx] += parseInt(row.tickets) || 0;
            });

            const rows = shRes.data.values || [];
            let g = { meta_trv: 70, trv_medio: 0, meta_mes: 0, recuperado_total: 0, faltam: 0, meta_minima_casos: 0 };
            if (rows[5]) {
                g.meta_trv = parsePct(rows[5][3] || rows[5][2]);
                g.trv_medio = parsePct(rows[5][5] || rows[5][4]);
                g.meta_mes = parseMoeda(rows[5][9] || rows[5][8]);
                g.recuperado_total = parseMoeda(rows[5][11] || rows[5][10]);
                g.faltam = parseMoeda(rows[5][15] || rows[5][14]);
                g.meta_minima_casos = parseMoeda(rows[5][17] || rows[5][16]);
            }
            const ags = {};
            rows.slice(10).filter(r => String(r[3] || r[2] || '').trim() !== '' && parseMoeda(r[6] || r[7]) > 0).forEach(row => {
                const nome = String(row[3] || row[2] || '').trim();
                const nb = normalizeNome(nome);
                const tk = vincularTickets(nome, tkMap, nSem);
                ags[nb] = {
                    nome, meta_casos: parseMoeda(row[4] || row[3]),
                    casos_atual: parseMoeda(row[6] || row[7]), refund: parseMoeda(row[8] || row[9]),
                    recuperado: parseMoeda(row[10] || row[11]), meta_trv_agente: parsePct(row[13] || row[12]),
                    trv: parsePct(row[15] || row[14]), status_vol: String(row[17] || row[16] || '').trim(),
                    status_trv: String(row[19] || row[18] || '').trim(),
                    tickets: tk.totalMes, hist_tickets: tk.hist_tickets
                };
            });
            return { aba, label: labelDaAba(aba), mesP, diasNoMes, nSem, globais: g, ags };
        };

        selecionadas.sort((a, b) => mesDaAba(a) - mesDaAba(b));
        const meses = await Promise.all(selecionadas.map(processarMes));
        const mesRecenteObj = meses[meses.length - 1];
        const multiMes = meses.length > 1;

        // detalhe por mês (card / comparativo)
        const detalhePorMes = {};
        meses.forEach(mo => {
            Object.entries(mo.ags).forEach(([nb, a]) => {
                if (!detalhePorMes[nb]) detalhePorMes[nb] = { nome: a.nome, meses: {} };
                detalhePorMes[nb].meses[mo.label] = {
                    casos_atual: a.casos_atual, refund: a.refund, recuperado: a.recuperado,
                    tickets: a.tickets, trv: a.trv, meta_casos: a.meta_casos, meta_trv_agente: a.meta_trv_agente
                };
            });
        });

        // ranking combinado (soma; TRV ponderada por casos)
        let idCounter = 1;
        const basesSet = new Set();
        meses.forEach(mo => Object.keys(mo.ags).forEach(nb => basesSet.add(nb)));
        const agentes = Array.from(basesSet).map(nb => {
            let casos = 0, refund = 0, recuperado = 0, tickets = 0, meta_casos = 0, trvNum = 0, trvDen = 0, hist = [];
            let nome = nb, status_vol = '', status_trv = '', meta_trv_agente = 0;
            meses.forEach(mo => {
                const a = mo.ags[nb];
                if (a) {
                    nome = a.nome;
                    casos += a.casos_atual; refund += a.refund; recuperado += a.recuperado;
                    tickets += a.tickets; meta_casos += a.meta_casos;
                    trvNum += a.trv * (a.casos_atual || 0); trvDen += (a.casos_atual || 0);
                    hist = hist.concat(a.hist_tickets || []);
                    if (mo === mesRecenteObj) { status_vol = a.status_vol; status_trv = a.status_trv; meta_trv_agente = a.meta_trv_agente; }
                } else {
                    hist = hist.concat(new Array(mo.nSem).fill(0));
                }
            });
            if (!meta_trv_agente) { for (let k = meses.length - 1; k >= 0; k--) { if (meses[k].ags[nb]) { meta_trv_agente = meses[k].ags[nb].meta_trv_agente; status_vol = status_vol || meses[k].ags[nb].status_vol; status_trv = status_trv || meses[k].ags[nb].status_trv; break; } } }
            const trv = trvDen > 0 ? (trvNum / trvDen) : 0;
            return { id: idCounter++, base: nb, nome, time: 'RET', tickets, hist_tickets: hist,
                meta_casos, casos_atual: casos, refund, recuperado, meta_trv_agente,
                trv, status_vol, status_trv, qual: 0, score: 0, hist_trv: [] };
        });

        const maxTrv = Math.max(...agentes.map(a => a.trv), 1);
        const maxCasos = Math.max(...agentes.map(a => a.casos_atual), 1);
        agentes.forEach(a => { a.score = (((maxTrv > 0 ? a.trv / maxTrv : 0) * 0.60) + ((maxCasos > 0 ? a.casos_atual / maxCasos : 0) * 0.40)) * 100; });
        agentes.sort((a, b) => b.score - a.score);

        // globais: mês único = valores da planilha (mantém cards originais); multi = combinado
        let globais;
        if (!multiMes) {
            const g0 = mesRecenteObj.globais;
            globais = { meta_trv: g0.meta_trv, trv_medio: g0.trv_medio, meta_mes: g0.meta_mes, recuperado_total: g0.recuperado_total, faltam: g0.faltam, meta_minima_casos: g0.meta_minima_casos, dias_mes_atual: mesRecenteObj.diasNoMes };
        } else {
            let gMetaMes = 0, gRecup = 0, gFaltam = 0, gMetaMin = 0, gTrvNum = 0, gTrvDen = 0, gDias = 0;
            meses.forEach(mo => {
                gMetaMes += mo.globais.meta_mes; gRecup += mo.globais.recuperado_total;
                gFaltam += mo.globais.faltam; gMetaMin += mo.globais.meta_minima_casos; gDias += mo.diasNoMes;
                Object.values(mo.ags).forEach(a => { gTrvNum += a.trv * (a.casos_atual || 0); gTrvDen += (a.casos_atual || 0); });
            });
            globais = { meta_trv: mesRecenteObj.globais.meta_trv, trv_medio: gTrvDen > 0 ? (gTrvNum / gTrvDen) : mesRecenteObj.globais.trv_medio, meta_mes: gMetaMes, recuperado_total: gRecup, faltam: gFaltam, meta_minima_casos: gMetaMin, dias_mes_atual: gDias };
        }

        res.json({ success: true, globais, agentes, meses: abasDisponiveis, selecionados: meses.map(mo => mo.label), mesAtual: mesRecenteObj.aba, multiMes, mesRecente: mesRecenteObj.label, detalhePorMes });

    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// ==========================================
// 7. ROTA DE QUALIDADE (PLANILHA B - BASE_MONITORIA)
// ==========================================
// Qualidade e Sinalizações (07/10/2026): meses em ordem de CALENDÁRIO, o mais novo primeiro (antes era ordem alfabética e "setembro" sempre ganhava).
// Entende o mês por extenso ("Outubro", "OUTUBRO/2026"), abreviado ("out/2026") ou em número ("10/2026", "2026-10", "01/10/2026").
const QUAL_MESES = ['janeiro', 'fevereiro', 'marco', 'abril', 'maio', 'junho', 'julho', 'agosto', 'setembro', 'outubro', 'novembro', 'dezembro'];
function qualOrdemDoMes(txt) {
    const t = String(txt || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    let mes = QUAL_MESES.findIndex(m => t.includes(m));
    if (mes < 0) mes = QUAL_MESES.findIndex(m => new RegExp('(^|[^a-z])' + m.slice(0, 3) + '([^a-z]|$)').test(t));
    let ano = (t.match(/(^|\D)(20\d{2})(\D|$)/) || [])[2];
    if (mes < 0) {
        const d = t.match(/(\d{1,2})\s*[\/.-]\s*(\d{1,2})\s*[\/.-]\s*(\d{2,4})/);   // data completa: dd/mm/aaaa
        const n = d ? null : (t.match(/(\d{4})\s*[\/.-]\s*(\d{1,2})/) || t.match(/(\d{1,2})\s*[\/.-]\s*(\d{2,4})/));
        if (d) { mes = parseInt(d[2], 10) - 1; ano = d[3].length === 2 ? '20' + d[3] : d[3]; }
        else if (n) { const quatro = n[1].length === 4; mes = parseInt(quatro ? n[2] : n[1], 10) - 1; const a = quatro ? n[1] : n[2]; ano = a.length === 2 ? '20' + a : a; }
    }
    if (!(mes >= 0 && mes <= 11)) return -1;   // sem mês reconhecido: vai para o fim da lista
    const hoje = new Date(new Date().toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' }));
    let a = ano ? parseInt(ano, 10) : hoje.getFullYear();
    if (!ano && mes > hoje.getMonth()) a -= 1;   // mês sem ano depois do mês atual é do ano passado (ex.: "dezembro" lido em janeiro)
    return a * 12 + mes;
}
const qualMesesDoMaisNovo = (x, y) => (qualOrdemDoMes(y) - qualOrdemDoMes(x)) || String(y).localeCompare(String(x));

app.get('/api/qualidade', async (req, res) => {
    try {
        let privateKey = (process.env.GOOGLE_PRIVATE_KEY || '').replace(/\\n/g, '\n').replace(/"/g, '').trim();
        const auth = new google.auth.GoogleAuth({
            credentials: { client_email: (process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || '').trim(), private_key: privateKey },
            scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
        });
        const sheets = google.sheets({ version: 'v4', auth });
        
        const sheetIdQualidade = process.env.GOOGLE_SHEET_ID_QUALIDADE ? process.env.GOOGLE_SHEET_ID_QUALIDADE.trim() : '1YVu29a_MiqU73_Za_Daj7nmfMJz-phTec2gxX6VKqwk';
        
        // 1. LER ABA DE MONITORIAS
        const response = await sheets.spreadsheets.values.get({ spreadsheetId: sheetIdQualidade, range: `'BASE_MONITORIA'!A1:Z5000` });
        const rows = response.data.values || [];

        if (rows.length < 4) return res.json({ success: true, meses: [], mesAtual: '', agentes: [] });

        // 2. LER NOVA ABA DE LINKS DO DRIVE
        let linksDriveAgentes = {};
        try {
            const responseLinks = await sheets.spreadsheets.values.get({ spreadsheetId: sheetIdQualidade, range: `'LINKS_AGENTES'!A1:B200` });
            const rowsLinks = responseLinks.data.values || [];
            
            rowsLinks.forEach(row => {
                const nomeAgent = normalizeNome(String(row[0] || '').trim());
                const linkDrive = String(row[1] || '').trim();
                if (nomeAgent && linkDrive.startsWith('http')) {
                    linksDriveAgentes[nomeAgent] = linkDrive;
                }
            });
        } catch (e) { console.log("Aba LINKS_AGENTES vazia ou não encontrada."); }

        // Mapeamento das colunas
        const idxSetor = 1; // Coluna B
        const idxNome  = 2; // Coluna C
        const idxCiclo = 3; // Coluna D
        const idxNota  = 5; // Coluna F
        const idxMes   = 8; // Coluna I

        let mesesSet = new Set();
        let monitoriasGerais = [];

        for (let i = 4; i < rows.length; i++) {
            const row = rows[i];
            const nomeRaw = String(row[idxNome] || '').trim();
            const mesRaw = String(row[idxMes] || '').trim();
            
            // Ignora as linhas vazias E ignora o cabeçalho "MES_REF"
            if (!nomeRaw || !mesRaw || mesRaw.toUpperCase() === 'MES_REF') continue;
            
            const nomeFormatado = normalizeNome(nomeRaw);
            mesesSet.add(mesRaw);

            let notaStr = String(row[idxNota] || '0').replace('%', '').replace(',', '.');
            let nota = parseFloat(notaStr) || 0;
            let cicloNum = parseInt(row[idxCiclo]) || 1;

            let setorRaw = String(row[idxSetor] || '').toUpperCase();
            let siglaSetor = 'RET'; 
            
            // 🔥 ARRAY COM OS NOMES DO TIME 48H
            const nomes48H = [
                'THAUANE GARCIA', 
                'BRUNO SILVA', 
                'ALEXANDRE FILHO', 
                'DARYSON MATHEUS', 
                'DARYSON NASCIMENTO', 
                'GABRIELA ANDRADE', 
                'GABRIELA PENHA'
            ];

            // 🔥 ARRAY COM OS NOMES DO TIME SMS
            const nomesSMS = [
                'ANA GODINHO',
                'REBECA SILVA',
                'BRUNO LIMA',
                'KEULIANE MOURA'
            ];
            
            // A ordem importa! 48H e SMS são lidos primeiro para evitar conflito com "SAC - SMS"
            // Adaptacao (novatos): setor da planilha "Adaptacao - Retencao - Email" tem prioridade sobre o resto
            if (setorRaw.includes('ADAPTA')) {
                siglaSetor = 'ADAPTACAO';
            } else if (setorRaw.includes('48H') || nomes48H.some(n => nomeFormatado.includes(n))) {
                siglaSetor = '48H';
            } else if (setorRaw.includes('SMS') || nomesSMS.some(n => nomeFormatado.includes(n))) {
                siglaSetor = 'SMS';
            } else if (setorRaw.includes('SAC')) {
                siglaSetor = 'SAC';
            } else if (setorRaw.includes('BKO') || setorRaw.includes('BACKOFFICE')) {
                siglaSetor = 'BKO';
            }

            monitoriasGerais.push({ mes: mesRaw, nome: nomeFormatado, time: siglaSetor, qual: nota, ciclo: cicloNum, nomeOriginal: nomeRaw });
        }

        const meses = Array.from(mesesSet).sort(qualMesesDoMaisNovo);   // mês mais novo primeiro (calendário, não alfabeto) 
        const mesSelecionado = req.query.mes || (meses.length > 0 ? meses[0] : '');
        const monitoriasDoMes = monitoriasGerais.filter(m => m.mes === mesSelecionado);

        const agentesAgrupados = {};
        monitoriasDoMes.forEach(m => {
            if (!agentesAgrupados[m.nome]) agentesAgrupados[m.nome] = { nome: m.nome, time: m.time, soma: 0, count: 0, ciclos: {}, nomeOriginal: m.nomeOriginal };
            agentesAgrupados[m.nome].soma += m.qual;
            agentesAgrupados[m.nome].count++;
            agentesAgrupados[m.nome].ciclos[`c${m.ciclo}`] = m.qual; 
        });

        const resultados = Object.values(agentesAgrupados).map(a => {
            let linkPastaDrive = '#';
            const nomeBuscadoOriginal = String(a.nomeOriginal || '').trim();
            const nomeBuscadoNormalizado = normalizeNome(nomeBuscadoOriginal);
            
            if (linksDriveAgentes[nomeBuscadoNormalizado]) {
                linkPastaDrive = linksDriveAgentes[nomeBuscadoNormalizado];
            } else {
                const palavrasBuscadas = nomeBuscadoNormalizado.split(' ').filter(p => p.length > 0);
                let melhorChave = null;
                let maiorPontuacao = 0;

                for (const chaveLink of Object.keys(linksDriveAgentes)) {
                    const palavrasChave = chaveLink.split(' ').filter(p => p.length > 0);
                    let pontuacaoAtual = 0;

                    if (palavrasBuscadas.length > 0 && palavrasChave.length > 0 && palavrasBuscadas[0] === palavrasChave[0]) {
                        pontuacaoAtual += 10; 
                        for (let i = 1; i < palavrasBuscadas.length; i++) {
                            if (palavrasChave.includes(palavrasBuscadas[i])) {
                                pontuacaoAtual += 1;
                            }
                        }
                    }

                    if (pontuacaoAtual > maiorPontuacao) {
                        maiorPontuacao = pontuacaoAtual;
                        melhorChave = chaveLink;
                    }
                }
                if (melhorChave && maiorPontuacao > 0) {
                    linkPastaDrive = linksDriveAgentes[melhorChave];
                }
            }

            return { 
                nome: a.nomeOriginal.toUpperCase(), time: a.time, qual: a.soma / a.count,
                c1: a.ciclos['c1'] !== undefined ? a.ciclos['c1'] : null,
                c2: a.ciclos['c2'] !== undefined ? a.ciclos['c2'] : null,
                c3: a.ciclos['c3'] !== undefined ? a.ciclos['c3'] : null,
                c4: a.ciclos['c4'] !== undefined ? a.ciclos['c4'] : null,
                link: linkPastaDrive
            };
        });
        
        res.json({ success: true, meses: meses, mesAtual: mesSelecionado, agentes: resultados });

    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// ==========================================
// 7.5 ROTA DE SINALIZAÇÕES (PLANILHA C - BASE_SINALIZACOES)
// ==========================================
app.get('/api/sinalizacoes', async (req, res) => {
    try {
        let privateKey = (process.env.GOOGLE_PRIVATE_KEY || '').replace(/\\n/g, '\n').replace(/"/g, '').trim();
        const auth = new google.auth.GoogleAuth({
            credentials: { client_email: (process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || '').trim(), private_key: privateKey },
            scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
        });
        const sheets = google.sheets({ version: 'v4', auth });
        
        const sheetIdQualidade = process.env.GOOGLE_SHEET_ID_QUALIDADE ? process.env.GOOGLE_SHEET_ID_QUALIDADE.trim() : '1YVu29a_MiqU73_Za_Daj7nmfMJz-phTec2gxX6VKqwk';
        
        const response = await sheets.spreadsheets.values.get({ spreadsheetId: sheetIdQualidade, range: `'BASE_SINALIZACOES'!A1:Z5000` });
        const rows = response.data.values || [];

        if (rows.length < 3) return res.json({ success: true, meses: [], mesAtual: '', agentes: [] });

        const idxSetor = 1; // Coluna B
        const idxNome  = 2; // Coluna C
        const idxCiclo = 3; // Coluna D
        const idxItem  = 5; // Coluna F
        const idxTipo  = 7; // Coluna H
        const idxData  = 8; // Coluna I
        const idxQtd   = 9; // Coluna J
        const idxObs   = 10; // Coluna K
        const idxFeed  = 11; // Coluna L
        const idxMes   = 12; // Coluna M

        let mesesSet = new Set();
        let sinalizacoesGerais = [];

        for (let i = 2; i < rows.length; i++) {
            const row = rows[i];
            const nomeRaw = String(row[idxNome] || '').trim();
            
            // 🔥 Transforma em minúsculo para agrupar
            let mesRaw = String(row[idxMes] || '').trim().toLowerCase(); 
            
            // 🔥 Bloqueia erros de fórmula (#ERROR!, #REF!) e cabeçalhos
            if (!nomeRaw || !mesRaw || mesRaw === 'mes' || mesRaw.startsWith('#') || nomeRaw.toUpperCase() === 'ANALISTA') continue;
            
            const nomeFormatado = normalizeNome(nomeRaw);
            mesesSet.add(mesRaw);

            let cicloNum = parseInt(row[idxCiclo]) || 1;
            let item = String(row[idxItem] || '').trim();
            if (!item) item = "Sem sinalizações";

            let setorRaw = String(row[idxSetor] || '').toUpperCase();
            let siglaSetor = 'RET'; 
            
            const nomes48H = ['THAUANE GARCIA', 'BRUNO SILVA', 'BRUNO LIMA', 'ALEXANDRE FILHO', 'DARYSON MATHEUS', 'DARYSON NASCIMENTO', 'GABRIELA ANDRADE', 'GABRIELA PENHA'];
            
            if (setorRaw.includes('48H') || nomes48H.some(n => nomeFormatado.includes(n))) {
                siglaSetor = '48H';
            } else if (setorRaw.includes('SAC')) {
                siglaSetor = 'SAC';
            } else if (setorRaw.includes('BKO') || setorRaw.includes('BACKOFFICE')) {
                siglaSetor = 'BKO';
            } else if (setorRaw.includes('SMS')) {
                siglaSetor = 'SMS';
            }

            sinalizacoesGerais.push({
                mes: mesRaw, nome: nomeFormatado, nomeOriginal: nomeRaw, time: siglaSetor,
                ciclo: cicloNum, item: item, tipo: String(row[idxTipo] || '').trim(),
                qtd: parseInt(row[idxQtd]) || 1, obs: String(row[idxObs] || '').trim(),
                feedback: String(row[idxFeed] || '').trim().length > 0 // Se tiver qualquer texto, true.
            });
        }

        const meses = Array.from(mesesSet).sort(qualMesesDoMaisNovo);   // mês mais novo primeiro (calendário, não alfabeto) 
        const mesSelecionado = req.query.mes || (meses.length > 0 ? meses[0] : '');
        const dadosDoMes = sinalizacoesGerais.filter(m => m.mes === mesSelecionado);

        const agentesAgrupados = {};
        dadosDoMes.forEach(s => {
            if (!agentesAgrupados[s.nome]) {
                agentesAgrupados[s.nome] = { nome: s.nomeOriginal.toUpperCase(), time: s.time, ciclos: { 1: [], 2: [], 3: [], 4: [] } };
            }
            if (s.ciclo >= 1 && s.ciclo <= 4) {
                agentesAgrupados[s.nome].ciclos[s.ciclo].push({ item: s.item, tipo: s.tipo, qtd: s.qtd, obs: s.obs, feedback: s.feedback });
            }
        });

        const resultados = Object.values(agentesAgrupados).sort((a, b) => a.nome.localeCompare(b.nome));

        res.json({ success: true, meses: meses, mesAtual: mesSelecionado, agentes: resultados });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// ==========================================
// 8. ROTA TICKETS ATUAL
// ==========================================
app.get('/api/tickets', async (req, res) => {
    try {
        let dataInicioSQL, dataFimSQL;
        if (req.query.since && req.query.until) {
            dataInicioSQL = unixParaYYYYMMDD(req.query.since); dataFimSQL = unixParaYYYYMMDD(req.query.until);
        } else {
            const agora = new Date(new Date().toLocaleString("en-US", {timeZone: "America/Sao_Paulo"}));
            const day = agora.getDay();
            const seg = new Date(agora); seg.setDate(agora.getDate() - (day === 0 ? 6 : day - 1));
            const dom = new Date(seg); dom.setDate(seg.getDate() + 6);
            dataInicioSQL = formatarDataSQL(seg); dataFimSQL = formatarDataSQL(dom);    
        }

        const result = await pool.query(queryTickets, [dataInicioSQL, dataFimSQL]);
        const agentesMap = {};
        result.rows.forEach(row => {
            const nome = (row.agente || '').toUpperCase();
            if (!nome.match(/- SAC|- RET|- BKO|- SMS|- 48H/)) return;
            if (!agentesMap[nome]) agentesMap[nome] = { nome: row.agente, seg:0, ter:0, qua:0, qui:0, sex:0, sab:0, dom:0, total:0 };

            const diaStr = row.dia instanceof Date ? row.dia.toISOString().split('T')[0] : String(row.dia).split('T')[0];
            const dataData = new Date(diaStr + 'T12:00:00Z');
            const diaSemana = dataData.getUTCDay();
            const valor = parseInt(row.tickets) || 0;

            agentesMap[nome].total += valor;
            if(diaSemana === 1) agentesMap[nome].seg += valor;
            else if(diaSemana === 2) agentesMap[nome].ter += valor;
            else if(diaSemana === 3) agentesMap[nome].qua += valor;
            else if(diaSemana === 4) agentesMap[nome].qui += valor;
            else if(diaSemana === 5) agentesMap[nome].sex += valor;
            else if(diaSemana === 6) agentesMap[nome].sab += valor;
            else if(diaSemana === 0) agentesMap[nome].dom += valor;
        });

        const resultados = Object.values(agentesMap).map(a => { a.meta = Math.min(Math.round((a.total / 400) * 100), 100); return a; });
        resultados.sort((a, b) => b.total - a.total);
        res.json({ success: true, agentes: resultados });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// ==========================================
// 9. ROTA TICKETS GERAL
// ==========================================
app.get('/api/tickets-geral', async (req, res) => {
    try {
        let dataInicioSQL, dataFimSQL;
        if (req.query.since && req.query.until) {
            dataInicioSQL = unixParaYYYYMMDD(req.query.since); dataFimSQL = unixParaYYYYMMDD(req.query.until);
        } else {
            const agora = new Date(new Date().toLocaleString("en-US", {timeZone: "America/Sao_Paulo"}));
            const dInicio = new Date(agora.getFullYear(), agora.getMonth() - 1, 1);
            const dFim = new Date(agora.getFullYear(), agora.getMonth(), 0); 
            dataInicioSQL = formatarDataSQL(dInicio); dataFimSQL = formatarDataSQL(dFim);
        }

        const dInicio = new Date(dataInicioSQL + 'T12:00:00Z');
        const dFim = new Date(dataFimSQL + 'T12:00:00Z');
        const domingoBase = new Date(dInicio.getTime());
        domingoBase.setUTCDate(dInicio.getUTCDate() - dInicio.getUTCDay());
        const diffMsTotal = dFim.getTime() - domingoBase.getTime();
        const totalSemanas = Math.floor((diffMsTotal / (1000 * 60 * 60 * 24)) / 7) + 1; 
        const metaCalculada = totalSemanas * 400; 

        const result = await pool.query(queryTickets, [dataInicioSQL, dataFimSQL]);
        const agentesMap = {};
        result.rows.forEach(row => {
            const nome = (row.agente || '').toUpperCase();
            if (!nome.match(/- SAC|- RET|- BKO|- SMS|- 48H/)) return;
            if (!agentesMap[nome]) agentesMap[nome] = { nome: row.agente, semanas: new Array(totalSemanas).fill(0), total: 0 };

            const diaStr = row.dia instanceof Date ? row.dia.toISOString().split('T')[0] : String(row.dia).split('T')[0];
            const dataData = new Date(diaStr + 'T12:00:00Z');
            const diasAposDomingo = Math.round((dataData.getTime() - domingoBase.getTime()) / (1000 * 60 * 60 * 24));
            const semanaIndex = Math.floor(diasAposDomingo / 7);

            if (semanaIndex >= 0 && semanaIndex < totalSemanas) {
                const valor = parseInt(row.tickets) || 0;
                agentesMap[nome].semanas[semanaIndex] += valor;
                agentesMap[nome].total += valor;
            }
        });

        const resultados = Object.values(agentesMap).map(a => { a.meta = Math.min(Math.round((a.total / metaCalculada) * 100), 100); return a; });
        resultados.sort((a, b) => b.total - a.total);
        res.json({ success: true, agentes: resultados });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});


// ==========================================
// 10. ROTA DISTRIBUIÇÃO E CASOS (ADMIN-ONLY)
// ==========================================
app.get('/api/distribuicao', async (req, res) => {
    try {
        // 1. Query de Distribuição de Tickets por Inbox
        const qDist = `
            SELECT 
                u.name AS agente,
                t.name AS equipe_nome,
                i.name AS caixa,
                COUNT(c.id) AS qtd
            FROM conversations c
            LEFT JOIN users u ON u.id = c.assignee_id
            LEFT JOIN inboxes i ON i.id = c.inbox_id
            LEFT JOIN teams t ON t.id = c.team_id
            WHERE c.status = 0 
              AND c.account_id = 1
              AND (i.name IS NULL OR i.name != 'Atendimento | Brasil')
            GROUP BY u.name, t.name, i.name
        `;
        const resultDist = await pool.query(qDist);
        
        const distAgentes = {};
        const caixasSet = new Set();
        
        resultDist.rows.forEach(r => {
            let nomeAgente = (r.agente || '').toUpperCase();
            let cx = r.caixa || '(Sem Time)';
            let cxUpper = ((r.equipe_nome || '') + ' ' + cx).normalize('NFD').replace(/[\u0300-\u036f]/g, '').toUpperCase();
            
            caixasSet.add(cx);
            
            // Descobre a sigla do time baseada na caixa/inbox
            let siglaSetor = 'OUTROS';
            if (cxUpper.includes('RETEN') || cxUpper.includes('RET')) siglaSetor = 'RET';
            else if (cxUpper.includes('SAC')) siglaSetor = 'SAC';
            else if (cxUpper.includes('BACK') || cxUpper.includes('BKO')) siglaSetor = 'BKO';
            else if (cxUpper.includes('SMS')) siglaSetor = 'SMS';
            else if (cxUpper.includes('48')) siglaSetor = '48H';

            let nome;
            if (!nomeAgente) {
                if (siglaSetor === 'OUTROS') return; 
                nome = `SEM ATRIBUIR - ${siglaSetor}`;
            } else {
                // Time SÓ pelo nome do agente no Chatwoot. Entram apenas RET/SAC/BKO/SMS/48H;
                // LD, PRD, BR e quem não tem sigla são ignorados.
                // Pega "- RET", "RET" (sem traço) e "- RET" colado no nome.
                const mSig = nomeAgente.match(/[\s\-]+(RET|SAC|BKO|SMS|48H)\b/);
                if (!mSig) return;
                const sig = mSig[1];
                nome = nomeAgente.replace(/[\s\-]+(RET|SAC|BKO|SMS|48H)\b.*$/, '').trim() + ' - ' + sig;
            }
            
            if (!distAgentes[nome]) distAgentes[nome] = { nome, total: 0 };
            distAgentes[nome][cx] = parseInt(r.qtd) || 0;
            distAgentes[nome].total += parseInt(r.qtd) || 0;
        });

        // 2. Query Resumo Casos Agente - Matemática igualada ao Chatwoot
        const qCasos = `
            WITH Conv48 AS (
                SELECT DISTINCT tg.taggable_id AS conv_id
                FROM taggings tg
                JOIN tags t2 ON t2.id = tg.tag_id
                WHERE tg.taggable_type = 'Conversation' AND (t2.name ILIKE '%time-48h%' OR t2.name ILIKE 'painel-do-pedido%')
            ),
            OpenConversations AS (
                SELECT 
                    c.id, c.display_id, c.assignee_id, c.contact_id, c.first_reply_created_at, c.last_activity_at, c.team_id, c.inbox_id, c.created_at,
                    CASE
                        WHEN c.id IN (SELECT conv_id FROM Conv48) THEN '48H'
                        WHEN i.name = '[GEX] SMS Support' THEN 'SMS'
                        WHEN t.name ILIKE '%reten%' THEN 'RET'
                        WHEN t.name ILIKE '%sac%' THEN 'SAC'
                        WHEN t.name ILIKE '%back office%' OR t.name ILIKE '%backoffice%' OR t.name ILIKE '%bko%' THEN 'BKO'
                        WHEN t.name ILIKE '%sms%' THEN 'SMS'
                        ELSE 'OUTROS'
                    END AS setor,
                    (i.name = 'Atendimento | Brasil') AS so_48h   -- caixa Brasil: entra aqui só pela etiqueta 48H
                FROM conversations c
                LEFT JOIN teams t ON t.id = c.team_id
                LEFT JOIN inboxes i ON i.id = c.inbox_id
                WHERE c.status = 0 
                  AND c.account_id = 1
                  AND (i.name IS NULL OR i.name != 'Atendimento | Brasil' OR c.id IN (SELECT conv_id FROM Conv48))
            )
            SELECT 
                u.name AS agente,
                oc.setor AS setor,
                oc.id AS conv_id,
                oc.display_id,
                ct.name AS cliente,
                oc.first_reply_created_at,
                oc.last_activity_at,
                oc.created_at,
                oc.so_48h,
                lm.message_type AS last_msg_type, lm.created_at AS last_msg_at
            FROM OpenConversations oc
            LEFT JOIN users u ON u.id = oc.assignee_id
            LEFT JOIN contacts ct ON ct.id = oc.contact_id
            LEFT JOIN LATERAL (   -- última mensagem do cliente ou do agente (nota privada, bot, atividade e apagada não contam)
                SELECT m.message_type, m.created_at
                FROM messages m
                WHERE m.conversation_id = oc.id
                  AND m.account_id = 1
                  AND m.private = FALSE
                  AND (m.message_type = 0 OR (m.message_type IN (1, 3) AND m.sender_type = 'User'))
                  AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE
                ORDER BY m.created_at DESC
                LIMIT 1
            ) lm ON TRUE
        `;
        const resultCasos = await pool.query(qCasos);
        const resCasosMap = {};
        const agora = new Date();
        
        resultCasos.rows.forEach(r => {
            let nomeAgente = (r.agente || '').toUpperCase();
            let siglaSetor = r.setor || 'OUTROS';

            let nome;
            if (!nomeAgente) {
                if (siglaSetor === 'OUTROS') return;
                nome = `SEM ATRIBUIR - ${siglaSetor}`;
            } else {
                // Time SÓ pelo nome do agente no Chatwoot. Entram apenas RET/SAC/BKO/SMS/48H;
                // LD, PRD, BR e quem não tem sigla são ignorados.
                // Pega "- RET", "RET" (sem traço) e "- RET" colado no nome.
                const mSig = nomeAgente.match(/[\s\-]+(RET|SAC|BKO|SMS|48H)\b/);
                if (!mSig) return;
                const sig = mSig[1];
                nome = nomeAgente.replace(/[\s\-]+(RET|SAC|BKO|SMS|48H)\b.*$/, '').trim() + ' - ' + sig;
            }
            
            if (r.so_48h && !nome.endsWith(' - 48H')) return;   // caixa "Atendimento | Brasil": só conta no Time 48H; nos outros times continua fora, como antes
            if (!resCasosMap[nome]) resCasosMap[nome] = { nome, em_aberto: 0, retornos: 0, aguardando: 0, fora_sla: 0, total: 0, detalhes: [] };
            
            const dataBaseParaSLA = r.last_msg_at ? new Date(r.last_msg_at) : (r.last_activity_at ? new Date(r.last_activity_at) : new Date(r.created_at));   // conta da última mensagem
            const diffHoras = (agora - dataBaseParaSLA) / (1000 * 60 * 60);
            
            // SLA só conta quando a última mensagem é do cliente. Última mensagem do agente (ou sem mensagem) vai para "Em aberto".
            let statusLabel, ordem;
            
            if (r.last_msg_type !== 0) {
                resCasosMap[nome].em_aberto += 1;
                statusLabel = '🔵 Em aberto';
                ordem = 4;
            } else if (diffHoras > 48) {
                resCasosMap[nome].fora_sla += 1;
                statusLabel = '🔴 Fora do SLA';
                ordem = 1;
            } else if (diffHoras >= 24 && diffHoras <= 48) {
                resCasosMap[nome].aguardando += 1;
                statusLabel = '🟡 Aguardando';
                ordem = 2;
            } else {
                resCasosMap[nome].retornos += 1;
                statusLabel = '🟢 Retornos';
                ordem = 3;
            }
            
            resCasosMap[nome].total += 1;
            resCasosMap[nome].detalhes.push({
                id: r.display_id || r.conv_id,
                cliente: r.cliente || 'Cliente sem nome',
                status: statusLabel,
                ordem: ordem,
                horas_parado: Math.round(diffHoras)
            });
        });

        res.json({ 
            success: true, 
            distribuicao: Object.values(distAgentes).sort((a,b) => b.total - a.total),
            caixas: Array.from(caixasSet).sort(),
            casos: Object.values(resCasosMap).sort((a,b) => b.total - a.total)
        });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ==========================================
// DIAGNÓSTICO: setor dos casos SEM ATRIBUIR (temporário)
// Abrir em: localhost:3003/api/diag-setores
// ==========================================
app.get('/api/diag-setores', async (req, res) => {
    try {
        const q = `
            WITH Conv48 AS (
                SELECT DISTINCT tg.taggable_id AS conv_id
                FROM taggings tg JOIN tags t2 ON t2.id = tg.tag_id
                WHERE tg.taggable_type = 'Conversation' AND t2.name ILIKE '%time-48h%'
            )
            SELECT
                COALESCE(t.name, '(SEM TIME)') AS time_nome,
                COALESCE(i.name, '(sem inbox)') AS inbox_nome,
                CASE
                    WHEN c.id IN (SELECT conv_id FROM Conv48) THEN '48H'
                    WHEN i.name = '[GEX] SMS Support' THEN 'SMS'
                    WHEN t.name ILIKE '%reten%' THEN 'RET'
                    WHEN t.name ILIKE '%sac%' THEN 'SAC'
                    WHEN t.name ILIKE '%back office%' OR t.name ILIKE '%backoffice%' OR t.name ILIKE '%bko%' THEN 'BKO'
                    WHEN t.name ILIKE '%sms%' THEN 'SMS'
                    ELSE 'OUTROS'
                END AS setor,
                COUNT(*)::int AS qtd
            FROM conversations c
            LEFT JOIN teams t ON t.id = c.team_id
            LEFT JOIN inboxes i ON i.id = c.inbox_id
            WHERE c.status = 0 AND c.account_id = 1 AND c.assignee_id IS NULL
              AND (i.name IS NULL OR i.name != 'Atendimento | Brasil')
            GROUP BY t.name, i.name, setor
            ORDER BY setor, qtd DESC
        `;
        const r = await pool.query(q);
        const resumo = {};
        r.rows.forEach(x => { resumo[x.setor] = (resumo[x.setor]||0) + x.qtd; });
        res.json({ success: true, total_sem_atribuir: r.rows.reduce((a,x)=>a+x.qtd,0), resumo_por_setor: resumo, detalhe: r.rows });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ==========================================
// 11. ROTA DE PRODUTIVIDADE E TEMPO OCIOSO (ADMIN-ONLY)
// ==========================================
app.get('/api/produtividade', async (req, res) => {
    try {
        let dataInicioSQL, dataFimSQL;
        if (req.query.since && req.query.until) {
            dataInicioSQL = unixParaYYYYMMDD(req.query.since); 
            dataFimSQL = unixParaYYYYMMDD(req.query.until);
        } else {
            // Padrao: apenas o DIA ATUAL (o calendario do painel permite escolher outras datas)
            const agora = new Date(new Date().toLocaleString("en-US", {timeZone: "America/Sao_Paulo"}));
            dataInicioSQL = formatarDataSQL(agora); 
            dataFimSQL = formatarDataSQL(agora);    
        }

        const qProd = `
            SELECT 
                u.name AS agente,
                TO_CHAR(m.created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo', 'YYYY-MM-DD HH24:MI:SS') AS data_hora
            FROM messages m
            INNER JOIN users u ON u.id = m.sender_id
            WHERE m.account_id = 1
              AND m.sender_type = 'User'
              AND m.message_type = 1
              AND m.private = FALSE
              AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE
              AND m.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND m.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
            ORDER BY u.name, m.created_at ASC
        `;
        
        const result = await pool.query(qProd, [dataInicioSQL, dataFimSQL]);
        
        const relatorio = {};
        result.rows.forEach(r => {
            let nome = (r.agente || '').toUpperCase();
            if (!nome.match(/- SAC|- RET|- BKO|- SMS|- 48H/)) return;
            
            let d = new Date(r.data_hora.replace(' ', 'T'));
            let diaStr = r.data_hora.split(' ')[0];
            
            if (!relatorio[nome]) relatorio[nome] = { dias: {} };
            if (!relatorio[nome].dias[diaStr]) relatorio[nome].dias[diaStr] = [];
            relatorio[nome].dias[diaStr].push(d);
        });

        const formatHora = (d) => String(d.getHours()).padStart(2,'0') + ':' + String(d.getMinutes()).padStart(2,'0');

        const output = [];
        for (const [agente, dados] of Object.entries(relatorio)) {
            let totalTickets = 0;
            let totalMinutosAciosos = 0;
            let historicoPausas = [];
            let jornadas = [];
            
            let diasUteis = 0;
            let ticketsPorHora = new Array(24).fill(0);
            let ticketsPorDia = {};
            let ociosoPorDia = {};

            for (const [dia, horas] of Object.entries(dados.dias)) {
                totalTickets += horas.length;
                if (horas.length === 0) continue;
                
                let inicio = horas[0];
                let fim = horas[horas.length - 1];
                let objDia = dia.split('-').reverse().join('/');
                jornadas.push(`${objDia} (${formatHora(inicio)} as ${formatHora(fim)})`);

                let diaDaSemana = inicio.getDay(); // 0=Dom, 6=Sab
                let isFDS = (diaDaSemana === 0 || diaDaSemana === 6);
                
                if (!isFDS) diasUteis++;
                ticketsPorDia[objDia] = horas.length;
                ociosoPorDia[objDia] = 0;

                // Calcula os gaps de tempo entre as mensagens desse dia
                for (let i = 1; i < horas.length; i++) {
                    let msgAnterior = horas[i-1];
                    let msgAtual = horas[i];
                    let diffMinRaw = (msgAtual - msgAnterior) / 60000; // diferença em minutos
                    
                    if(!isFDS) {
                        let h = msgAtual.getHours();
                        ticketsPorHora[h] = (ticketsPorHora[h] || 0) + 1;
                    }

                    // Regra: Uma pausa é qualquer tempo inativo >= 20 minutos
                    if (diffMinRaw >= 20 && diffMinRaw < 60 * 12) {
                        let startMin = msgAnterior.getHours() * 60 + msgAnterior.getMinutes();
                        let endMin = msgAtual.getHours() * 60 + msgAtual.getMinutes();
                        
                        const overlap = (s1, e1, s2, e2) => Math.max(0, Math.min(e1, e2) - Math.max(s1, s2));
                        
                        let idleUtil = overlap(startMin, endMin, 9*60, 12*60+30) + overlap(startMin, endMin, 14*60, 18*60);
                        
                        let overlapAlmoco = overlap(startMin, endMin, 12*60+30, 14*60);
                        let isAlmoco = overlapAlmoco > 0;
                        
                        let strPausa = `${objDia} das ${formatHora(msgAnterior)} às ${formatHora(msgAtual)} (${Math.round(diffMinRaw)}m)`;

                        if (isFDS) {
                            historicoPausas.push(`🏖️ FDS: ${strPausa}`);
                        } else if (isAlmoco) {
                            if (idleUtil > 0) {
                                totalMinutosAciosos += idleUtil;
                                ociosoPorDia[objDia] += idleUtil;
                                historicoPausas.push(`🍽️ ALMOÇO (+ ${Math.round(idleUtil)}m ociosos): ${strPausa}`);
                            } else {
                                historicoPausas.push(`🍽️ ALMOÇO: ${strPausa}`);
                            }
                        } else if (idleUtil > 0) {
                            totalMinutosAciosos += idleUtil;
                            ociosoPorDia[objDia] += idleUtil;
                            historicoPausas.push(`⏸️ OCIOSO (${Math.round(idleUtil)}m úteis): ${strPausa}`);
                        }
                    }
                }
            }
            
            let horaMaisAtiva = 0, maxT = -1;
            let horaMenosAtiva = 0, minT = 999999;
            
            for(let h=9; h<18; h++) {
                if (h === 13) continue; // Pula horário de almoço na média
                if(ticketsPorHora[h] > maxT) { maxT = ticketsPorHora[h]; horaMaisAtiva = h; }
                if(ticketsPorHora[h] < minT) { minT = ticketsPorHora[h]; horaMenosAtiva = h; }
            }

            let diaMaisTickets = '-', valMaisTickets = 0;
            let diaMaisOcioso = '-', valMaisOcioso = 0;

            for (let d in ticketsPorDia) {
                if (ticketsPorDia[d] > valMaisTickets) { valMaisTickets = ticketsPorDia[d]; diaMaisTickets = d; }
            }
            for (let d in ociosoPorDia) {
                if (ociosoPorDia[d] > valMaisOcioso) { valMaisOcioso = ociosoPorDia[d]; diaMaisOcioso = d; }
            }

            let mediaOcioso = diasUteis > 0 ? (totalMinutosAciosos / diasUteis) : 0;

            output.push({
                nome: agente,
                tickets: totalTickets,
                jornada: jornadas.join('\n'),
                tempo_ocioso: Math.round(totalMinutosAciosos),
                maior_pico: maxT > 0 ? `${String(horaMaisAtiva).padStart(2,'0')}h às ${String(horaMaisAtiva+1).padStart(2,'0')}h` : '-',
                pausas: historicoPausas,
                detalhes: {
                    media_ocioso: Math.round(mediaOcioso),
                    hora_mais: maxT > 0 ? `${String(horaMaisAtiva).padStart(2,'0')}h (${maxT} tkts)` : '-',
                    hora_menos: minT !== 999999 && maxT > 0 ? `${String(horaMenosAtiva).padStart(2,'0')}h (${minT} tkts)` : '-',
                    dia_tickets: `${diaMaisTickets} (${valMaisTickets})`,
                    dia_ocioso: `${diaMaisOcioso} (${Math.round(valMaisOcioso)}m)`
                }
            });
        }

        output.sort((a, b) => b.tempo_ocioso - a.tempo_ocioso);
        res.json({ success: true, agentes: output });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// ==========================================
// 12. ROTA DE RECORRÊNCIA E RETORNO (CHATWOOT)
// ==========================================
app.get('/api/recorrencia', async (req, res) => {
    try {
        const q = `
        WITH ClientMessages AS (
            SELECT 
                COALESCE(NULLIF(c.email, ''), c.id::text) AS client_identity,
                m.created_at,
                LAG(m.created_at) OVER (PARTITION BY COALESCE(NULLIF(c.email, ''), c.id::text) ORDER BY m.created_at) as prev_msg_date
            FROM messages m
            JOIN contacts c ON c.id = m.sender_id
            WHERE m.sender_type = 'Contact'
              AND m.message_type = 0
              AND m.account_id = 1 -- 🔥 A BALA DE PRATA: Filtrando apenas a conta real
              AND m.created_at >= NOW() - INTERVAL '8 months' -- so os ultimos meses (a saida ja mostra 6); alivia a tabela messages
              AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE -- Ignora msgs apagadas
        ),
        Returns AS (
            SELECT 
                client_identity,
                created_at,
                prev_msg_date,
                EXTRACT(EPOCH FROM (created_at - prev_msg_date))/3600 AS hours_since_last,
                TO_CHAR(created_at AT TIME ZONE 'America/Sao_Paulo', 'YYYY-MM') as mes_retorno
            FROM ClientMessages
            WHERE prev_msg_date IS NOT NULL
        )
        SELECT 
            mes_retorno,
            COUNT(*) AS total_retornos,
            COUNT(DISTINCT client_identity) AS clientes_unicos,
            AVG(hours_since_last) AS media_horas
        FROM Returns 
        WHERE hours_since_last > 24
        GROUP BY mes_retorno
        ORDER BY mes_retorno DESC
        LIMIT 6;
        `;
        const result = await pool.query(q);
        res.json({ success: true, dados: result.rows });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// ==========================================
// 13. ROTA INTELIGÊNCIA DE PRODUTOS E ATRITO (ÚLTIMO RETORNO + FCR + SLA)
// ==========================================
app.get('/api/produtos-metricas', async (req, res) => {
    try {
        const q = `
        WITH ConversasBase AS (
            SELECT 
                c.id AS conversation_id,
                c.display_id,
                COALESCE(u.name, 'SEM ATRIBUIR') AS agente_nome,
                COALESCE(ct.name, 'Sem Nome') AS contato_nome,
                TRIM(BOTH '.' FROM INITCAP(LOWER(TRIM(COALESCE(c.custom_attributes->>'produtos', c.custom_attributes->>'produto', c.custom_attributes->>'Produto'))))) AS produto
            FROM conversations c
            LEFT JOIN users u ON u.id = c.assignee_id
            LEFT JOIN contacts ct ON ct.id = c.contact_id
            WHERE c.account_id = 1
              AND COALESCE(c.custom_attributes->>'produtos', c.custom_attributes->>'produto', c.custom_attributes->>'Produto') IS NOT NULL
              AND TRIM(COALESCE(c.custom_attributes->>'produtos', c.custom_attributes->>'produto', c.custom_attributes->>'Produto')) != ''
              AND c.created_at >= NOW() - INTERVAL '30 days'
        ),
        BaseMessages AS (
            SELECT 
                m.conversation_id,
                cb.display_id,
                cb.produto,
                cb.agente_nome,
                cb.contato_nome,
                m.message_type,
                m.created_at,
                LAG(m.created_at) OVER (PARTITION BY m.conversation_id ORDER BY m.created_at) as prev_msg_time,
                LAG(m.message_type) OVER (PARTITION BY m.conversation_id ORDER BY m.created_at) as prev_msg_type
            FROM messages m
            JOIN ConversasBase cb ON cb.conversation_id = m.conversation_id
            WHERE m.private = FALSE 
              AND m.account_id = 1 
              AND m.message_type IN (0, 1) 
              AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE
        ),
        UltimoRetorno AS (
            SELECT DISTINCT ON (conversation_id)
                conversation_id,
                EXTRACT(EPOCH FROM (created_at - prev_msg_time))/3600 AS gap_horas
            FROM BaseMessages
            WHERE message_type = 0 AND prev_msg_type = 1
            ORDER BY conversation_id, created_at DESC
        ),
        UltimaMensagem AS (
            SELECT DISTINCT ON (conversation_id)
                conversation_id,
                message_type,
                created_at
            FROM BaseMessages
            ORDER BY conversation_id, created_at DESC
        ),
        AgregacaoGeral AS (
            SELECT 
                conversation_id,
                MAX(display_id) AS display_id,
                produto,
                MAX(agente_nome) AS agente_nome,
                MAX(contato_nome) AS contato_nome,
                COUNT(*) FILTER (WHERE message_type = 0) AS qtd_msgs_cliente,
                SUM(CASE WHEN message_type = 0 AND prev_msg_type = 0 AND prev_msg_time IS NOT NULL AND EXTRACT(EPOCH FROM (created_at - prev_msg_time))/3600 <= 1 THEN 1 ELSE 0 END) AS qtd_floods,
                AVG(EXTRACT(EPOCH FROM (created_at - prev_msg_time))/60) FILTER (WHERE message_type = 1 AND prev_msg_type = 0) AS tmr_minutos
            FROM BaseMessages
            GROUP BY conversation_id, produto
        )
        SELECT 
            a.produto,
            COUNT(DISTINCT a.conversation_id) AS total_recebidas,
            COUNT(DISTINCT ur.conversation_id) AS total_retornos,
            
            COUNT(DISTINCT ur.conversation_id) FILTER (WHERE ur.gap_horas > 0 AND ur.gap_horas <= 24) AS retornos_24h,
            COUNT(DISTINCT ur.conversation_id) FILTER (WHERE ur.gap_horas > 24 AND ur.gap_horas <= 48) AS retornos_48h,
            COUNT(DISTINCT ur.conversation_id) FILTER (WHERE ur.gap_horas > 48) AS retornos_mais_48h,
            
            -- 🔥 O CÁLCULO DE SEM RETORNO DE VOLTA AO BANCO
            COUNT(DISTINCT um.conversation_id) FILTER (WHERE um.message_type = 1 AND EXTRACT(EPOCH FROM (NOW() AT TIME ZONE 'UTC' - um.created_at))/3600 > 48) AS sem_retorno_48h,
            
            COALESCE(SUM(a.qtd_floods), 0) AS flood_desespero,
            ROUND(AVG(a.qtd_msgs_cliente), 1) AS atrito_msg_por_conv,
            COALESCE(AVG(a.tmr_minutos), 0) AS sla_tmr_minutos,
            
            json_agg(
                json_build_object(
                    'id', a.display_id,
                    'agente', a.agente_nome,
                    'cliente', a.contato_nome,
                    'status', CASE 
                        WHEN um.message_type = 1 AND EXTRACT(EPOCH FROM (NOW() AT TIME ZONE 'UTC' - um.created_at))/3600 > 48 THEN 'Sem Retorno (>48h)'
                        WHEN ur.gap_horas > 0 AND ur.gap_horas <= 24 THEN 'Retorno < 24h'
                        WHEN ur.gap_horas > 24 AND ur.gap_horas <= 48 THEN 'Retorno 24-48h'
                        WHEN ur.gap_horas > 48 THEN 'Retorno > 48h'
                        ELSE 'Em Andamento / Novo'
                    END
                )
            ) AS detalhes
        FROM AgregacaoGeral a
        LEFT JOIN UltimoRetorno ur ON ur.conversation_id = a.conversation_id
        LEFT JOIN UltimaMensagem um ON um.conversation_id = a.conversation_id
        GROUP BY a.produto
        ORDER BY total_recebidas DESC;
        `;
        const result = await pool.query(q);
        res.json({ success: true, dados: result.rows });
    } catch (error) { 
        console.error("Erro Produtos:", error);
        res.status(500).json({ success: false, error: error.message }); 
    }
});

// ==========================================
// 🔎 PRODUTOS CITADOS — lista de produtos atualizada (07/10/2026)
// Produtos atuais das contas BuyGoods (conta 1: 185 · conta 2: 104) que a busca ainda não pegava:
// produtos novos e outras grafias de produtos que já estavam na lista (ex.: "SugarReset" e "Sugar Reset").
// As outras grafias aparecem na MESMA linha do produto (MENCOES_APELIDOS), sem contar o caso 2 vezes.
// ==========================================
const MENCOES_PRODUTOS_NOVOS = [
    'SugarReset', 'GlycoHarmony', 'CleanEye', 'HorseBoost', 'AlphaHoney', 'SlimRise', 'SonusZen', 'DermaEssential',
    'ManForceX', 'GlucoControl', 'Sodarmin', 'SugarControl', 'Memogut', 'SodaBoost', 'Denta Guard', 'ProstaRenew',
    'VigorPrime', 'Metabo Slim', 'NeuroCinammon', 'HorsePulse', 'Honey Balance', 'IronBoost', 'SodaHorsePro', 'SodaStallionPeak',
    'Oiltaro', 'Olicept', 'Breathi Zen', 'Blood Pril', 'Alpha Steel', 'Men Growth', 'Trim X', 'BreathEaseX',
    'RevitalGluco', 'NeuroCinamon'
];
const MENCOES_APELIDOS = {
    'SugarReset': 'Sugar Reset',
    'GlycoHarmony': 'Glyco Harmony',
    'CleanEye': 'Clean Eye',
    'HorseBoost': 'Horse Boost',
    'AlphaHoney': 'Alpha Honey',
    'SlimRise': 'Slim Rise',
    'SonusZen': 'Sonus Zen',
    'DermaEssential': 'Derma Essential',
    'ManForceX': 'Man ForceX',
    'GlucoControl': 'Gluco Control',
    'SugarControl': 'Sugar Control',
    'Denta Guard': 'DentaGuard',
    'ProstaRenew': 'Prosta Renew',
    'VigorPrime': 'Vigor Prime',
    'Metabo Slim': 'MetaboSlim',
    'NeuroCinammon': 'Neuro Cinnamon',
    'HorsePulse': 'Horse Pulse',
    'Honey Balance': 'HoneyBalance',
    'IronBoost': 'Iron Boost',
    'Breathi Zen': 'BreathiZen',
    'Blood Pril': 'BloodPril',
    'Alpha Steel': 'AlphaSteel',
    'Men Growth': "Men's Growth",
    'Trim X': 'TrimX',
    'RevitalGluco': 'Revital Gluco',
    'NeuroCinamon': 'Neuro Cinnamon'
};
const MENCOES_NOVOS_SQL = MENCOES_PRODUTOS_NOVOS.map(p => `'${p.replace(/'/g, "''")}'`).join(', ');
// Junta as linhas do mesmo produto escrito de jeitos diferentes (conta cada caso 1 vez); sem grafia nova, devolve igual ao que veio do banco
function mencoesUnificar(linhas) {
    const lista = linhas || [];
    const apelidoDe = (p) => MENCOES_APELIDOS[p] || p;
    if (!lista.some(r => apelidoDe(r.produto_mencionado) !== r.produto_mencionado)) return lista;
    const mapa = new Map();
    for (const r of lista) {
        const produto = apelidoDe(r.produto_mencionado), chave = r.equipe + '|' + produto;
        if (!mapa.has(chave)) mapa.set(chave, { ...r, produto_mencionado: produto, detalhes: [], ids: new Set() });
        const alvo = mapa.get(chave);
        (r.detalhes || []).forEach(d => { if (!alvo.ids.has(d.id)) { alvo.ids.add(d.id); alvo.detalhes.push(d); } });
    }
    return Array.from(mapa.values()).map(({ ids, ...r }) => ({ ...r, qtd_casos: String(ids.size) })).sort((a, b) => Number(b.qtd_casos) - Number(a.qtd_casos));
}

// ==========================================
// 14. ROTA DE PRODUTOS CITADOS (MINERAÇÃO DE TEXTO NA FILA)
// ==========================================
app.get('/api/mencoes-abertos', async (req, res) => {
    try {
        const q = `
        WITH OpenConversations AS (
            SELECT 
                c.id AS conv_id,
                c.display_id, 
                c.contact_id, 
                COALESCE(c.additional_attributes->>'subject', '') AS email_subject, 
                CASE 
                    WHEN i.name = '[GEX] SMS Support' THEN 'SMS'
                    WHEN t.name ILIKE '%retenção%' THEN 'RET'
                    WHEN t.name ILIKE '%sac%' THEN 'SAC'
                    WHEN t.name ILIKE '%back office%' THEN 'BKO'
                    WHEN c.team_id IS NULL THEN 'SEM ATRIBUIR'
                    ELSE 'OUTROS'
                END as equipe
            FROM conversations c
            LEFT JOIN teams t ON t.id = c.team_id
            LEFT JOIN inboxes i ON i.id = c.inbox_id
            WHERE c.status = 0 
              AND c.assignee_id IS NULL 
              AND c.account_id = 1 
              AND (i.name IS NULL OR i.name != 'Atendimento | Brasil')
        ),
        Keywords AS (
            SELECT unnest(ARRAY[
                'Alpha Max', 'BoostBurn', 'Clean Eye', 'Coffee Burn', 'DentaGuard', 'BioGutix', 'Dream Night', 
                'Eros Lift', 'Fit Burn', 'Flash Burn', 'Flexi Move', 'FloraZen', 'FocusVibe', 'Giant Max', 
                'Gluco Control', 'Gluco Pure', 'GlycoNaturals', 'Glycotide', 'Lipo Flow', 'Lipo Rise', 
                'Liver Revive', 'Manergy', 'Memo Revive', 'Memory Lift', 'Men''s Growth', 'Metarise', 
                'Mindora', 'Nerve Alive', 'Nerve Zen', 'Nerve Vital', 'Nervion', 'NeuroPezil', 'Neuro Silence', 
                'Oral Defense', 'Prime Age', 'Prostate Max', 'Red Burn', 'Relax Pure', 'Revital Gluco', 
                'SkinFlex Collagen', 'Slim Rise', 'Sonus Zen', 'Sugar Control', 'Sugar Drop', 'Vigor Boost', 
                'VirileForce', 'Vital Blood', 'Vital Green', 'VitaLust', 'Vivid Essence', 'VoluMax', 'Lipotide', 
                'HairLift', 'NailPure', 'BreathiZen', 'GoldenVita Pure', 'NeuronGold', 'Honey Sharp', 'Lipo Advance', 
                'Nervify', 'Power HoneyX', 'Neuro Drops', 'Sleep Protocol', 'Retikora', 'Gelatide', 'GelaBurn', 
                'Nervontix', 'Mentho Flow', 'OtoHear Drops', 'TrimX', 'Nervory', 'Man ForceX', 'Brainergy', 
                'Vision Vance', 'Braincept', 'Prosta Renew', 'GlycoPezil', 'Prosta Defender', 'CoffeeLean', 
                'Nerve Defender', 'Barisalt', 'VertiBalance', 'Derma Essential', 'Hearing Harmony', 'MemoPezil', 
                'Gelatine Sculpt', 'Memocept', 'Sleepem', 'JointBrex', 'VapoFil', 'HoneyCept', 'BloodPril', 
                'Longevant', 'Sleepidem', 'Alpha Honey', 'Blueberry GLP', 'Chocotide', 'HunterPower', 
                'Gluco Master', 'Slim Jelly', 'HunterPowerX', 'Leanrise', 'GlucoEnergy', 'Gelatide-1', 'NeuroSalt', 
                'Derma Clean', 'Skin Revive', 'Lean Jaro', 'Erefil', 'Honetide31', 'FlaxBurn', 'Liver Balance', 
                'Respiratory Support', 'PressureGuard', 'MetaboSlim', 'NeuroFlux', 'GlucoForce', 'MaxiDure', 
                'NeuroVix', 'Arthmira', 'Cutide', 'NeuroSharp', 'Neurozen', 'Prime Age Caps', 'BrainLive', 
                'Glyco Harmony', 'Cinna Harmony', 'Javatide', 'Mens Power', 'SlimTide', 'LeanBurn', 'Cognicept', 
                'Memo+50', 'LeanBurn Drops', 'Sugar Reset', 'Mojatide', 'GlucoVive', 'SugarVita Gummies', 
                'GlucoSteady', 'Memo Rise', 'Neuro Sharp Caps', 'NeuroBlast', 'Erecmax', 'Vigor Prime', 'GelaSlim', 
                'PeptiBurn Gummies', 'Lipotutide', 'Glucotide', 'JellyTide', 'MemoVance', 'TestoMax', 'Dermapure', 
                'Gumitide', 'Eronix', 'PowerZenX', 'PowerNox', 'Glyvoryn', 'Sugarzen', 'Sugarflex', 'SugarCalm', 
                'Glucovex', 'SugarPure', 'NerveHarmony', 'NeuroHarmony', 'Nerveyn', 'NerveMax', 'Nervetide', 
                'MindCervy', 'Mindoryx', 'FocusSnap', 'Leantide', 'TorchFat', 'MomBurn', 'Slim40', 'TestoHorse', 
                'Vigor40', 'NeuroOil', 'Horse Boost', 'Neuro Cinnamon', 'FocusLock', 'MemoGuard', 'Renew31', 
                'Tinizen', 'Slimpeak', 'SleepGood', 'FastBurn', 'Javacept', 'NeuroVex', 'Lipolean', 'TadaGummies', 
                'AlphaPulse', 'Eresurge', 'GlucoBliss', 'GlycoBalance', 'Sodatide', 'VigorRise', 'Horse Pulse', 
                'MindCept', 'MemoClear', 'HoneyHarmony', 'Glycoformin', 'OzemPeak', 'OzemSlim', 'SodaSlim', 
                'SodaBurn', 'Gumiflow', 'AlphaSteel', 'VigorFil', 'SodaFil', 'Sugarjaro', 'Sugariance', 'JellyFil', 
                'Memodyne', 'HoneyPezil', 'MemoHoney', 'Neuroflow', 'Gabaflow Mix', 'LyriBalm', 'JelloBurn', 
                'GlucoAloha', 'HorseFil', 'GelaFil', 'VapoCept', 'NerveHarmonny', 'SodaLean', 'Neurapezil', 
                'PrimeHoney', 'HoneyBalance', 'GlycoBloom', 'JellyBoost', 'Hydrofil', 'SteelPulse', 'Sugartide', 
                'Gumipic', 'Nervecept', 'Neuradyne', 'HorseSteel', 'Hydroryn', 'Honeyfil', 'Cognidyne', 'AlkaPic', 
                'AlkaBurn', 'GelaLean', 'AlkaTide', 'Gelacept', 'Gelanic', 'Gumipezil', 'Glycopic', 'SodaFit', 
                'Sweetide', 'Sodaryn', 'RoyalFil', 'Gelagen', 'Turmeric Harmony', 'Jellyblue', 'HoneyBoost', 
                'Iron Boost', 'HearBetter', 'Gelafen', 'Gelataro', 'OliveBrain', 'CartiVex', 'Glycofit', 
                'HoneyFlush', 'GiantMax', 'Vinetaro', 'Cardiopril', 'Cardiocept', 'MeltCore', 'SodaPeak', 
                'MatchaSlim', 'MatchaTide', 'CardioHarmony', 'SugarClear', 'SodaPower', 'Goldtin', 'Melonex', 
                'AlkaFit', 'NerveHoney', 'Roscept', 'Payarmin', 'Lympnex', 'GlycoGenesis', 'Nervactil', 
                'NeuroGolden', 'Marycept', 'YogTide', 'Rosedil', 'Retride', 'Olivaro', 'Lasiberry', 'USBREX', ${MENCOES_NOVOS_SQL}   -- + produtos atuais que faltavam (07/10/2026)
            ]) AS kw
        ),
        MatchedTickets AS (
            SELECT DISTINCT
                oc.equipe,
                k.kw AS produto_mencionado,
                oc.conv_id,
                oc.display_id,
                ct.name AS contato_nome,
                ct.email AS contato_email
            FROM OpenConversations oc
            JOIN messages m ON m.conversation_id = oc.conv_id AND m.message_type = 0 
            LEFT JOIN contacts ct ON ct.id = oc.contact_id
            CROSS JOIN Keywords k
            WHERE oc.equipe != 'OUTROS'
              AND (COALESCE(m.content, '') ILIKE '%' || k.kw || '%' OR oc.email_subject ILIKE '%' || k.kw || '%')
        )
        SELECT 
            equipe,
            produto_mencionado,
            COUNT(conv_id) as qtd_casos,
            json_agg(json_build_object(
                'id', display_id,
                'nome', COALESCE(contato_nome, 'Sem Nome'), 
                'email', COALESCE(contato_email, 'Sem Email')
            )) AS detalhes
        FROM MatchedTickets
        GROUP BY equipe, produto_mencionado
        ORDER BY qtd_casos DESC;
        `;
        const result = await pool.query(q);
        res.json({ success: true, dados: mencoesUnificar(result.rows) });
    } catch (error) { 
        console.error("Erro Rota Menções:", error);
        res.status(500).json({ success: false, error: error.message }); 
    }
});

// ==========================================
// 14b. PRODUTOS CITADOS — ABA "TODOS" (07/10/2026 · regra do período e retornos ajustados no mesmo dia)
// Tickets de qualquer status (aberto, pendente, adiado ou resolvido), não importa quem mandou a última mensagem.
// Período: só entra o ticket cuja 1ª MENSAGEM é do período, e o produto tem que ser citado pelo cliente DENTRO do período
// (em qualquer mensagem dele, ou no assunto do e-mail). Mesmas equipes da aba Abertos, sem a caixa "Atendimento | Brasil".
// Retorno (regra do Time 48H): o cliente escreveu de novo depois da 1ª resposta do agente; o tempo conta da última resposta do agente antes disso.
// Tabulação (ajuste seguinte): o ticket também entra se o agente marcou o produto no atributo "produto" da conversa (a mesma tabulação dos Produtos Tabulados),
// mesmo sem o cliente citar. Cada ticket vem com como entrou (citado / tabulado / os dois) e se tem a etiqueta "duplicado".
// ==========================================
const MENCOES_PRODUTOS_LISTA_ABERTOS = [   // cópia da lista da rota /api/mencoes-abertos (a mesma busca nas duas abas)
    'Alpha Max', 'BoostBurn', 'Clean Eye', 'Coffee Burn', 'DentaGuard', 'BioGutix', 'Dream Night', 'Eros Lift',
    'Fit Burn', 'Flash Burn', 'Flexi Move', 'FloraZen', 'FocusVibe', 'Giant Max', 'Gluco Control', 'Gluco Pure',
    'GlycoNaturals', 'Glycotide', 'Lipo Flow', 'Lipo Rise', 'Liver Revive', 'Manergy', 'Memo Revive', 'Memory Lift',
    "Men's Growth", 'Metarise', 'Mindora', 'Nerve Alive', 'Nerve Zen', 'Nerve Vital', 'Nervion', 'NeuroPezil',
    'Neuro Silence', 'Oral Defense', 'Prime Age', 'Prostate Max', 'Red Burn', 'Relax Pure', 'Revital Gluco', 'SkinFlex Collagen',
    'Slim Rise', 'Sonus Zen', 'Sugar Control', 'Sugar Drop', 'Vigor Boost', 'VirileForce', 'Vital Blood', 'Vital Green',
    'VitaLust', 'Vivid Essence', 'VoluMax', 'Lipotide', 'HairLift', 'NailPure', 'BreathiZen', 'GoldenVita Pure',
    'NeuronGold', 'Honey Sharp', 'Lipo Advance', 'Nervify', 'Power HoneyX', 'Neuro Drops', 'Sleep Protocol', 'Retikora',
    'Gelatide', 'GelaBurn', 'Nervontix', 'Mentho Flow', 'OtoHear Drops', 'TrimX', 'Nervory', 'Man ForceX',
    'Brainergy', 'Vision Vance', 'Braincept', 'Prosta Renew', 'GlycoPezil', 'Prosta Defender', 'CoffeeLean', 'Nerve Defender',
    'Barisalt', 'VertiBalance', 'Derma Essential', 'Hearing Harmony', 'MemoPezil', 'Gelatine Sculpt', 'Memocept', 'Sleepem',
    'JointBrex', 'VapoFil', 'HoneyCept', 'BloodPril', 'Longevant', 'Sleepidem', 'Alpha Honey', 'Blueberry GLP',
    'Chocotide', 'HunterPower', 'Gluco Master', 'Slim Jelly', 'HunterPowerX', 'Leanrise', 'GlucoEnergy', 'Gelatide-1',
    'NeuroSalt', 'Derma Clean', 'Skin Revive', 'Lean Jaro', 'Erefil', 'Honetide31', 'FlaxBurn', 'Liver Balance',
    'Respiratory Support', 'PressureGuard', 'MetaboSlim', 'NeuroFlux', 'GlucoForce', 'MaxiDure', 'NeuroVix', 'Arthmira',
    'Cutide', 'NeuroSharp', 'Neurozen', 'Prime Age Caps', 'BrainLive', 'Glyco Harmony', 'Cinna Harmony', 'Javatide',
    'Mens Power', 'SlimTide', 'LeanBurn', 'Cognicept', 'Memo+50', 'LeanBurn Drops', 'Sugar Reset', 'Mojatide',
    'GlucoVive', 'SugarVita Gummies', 'GlucoSteady', 'Memo Rise', 'Neuro Sharp Caps', 'NeuroBlast', 'Erecmax', 'Vigor Prime',
    'GelaSlim', 'PeptiBurn Gummies', 'Lipotutide', 'Glucotide', 'JellyTide', 'MemoVance', 'TestoMax', 'Dermapure',
    'Gumitide', 'Eronix', 'PowerZenX', 'PowerNox', 'Glyvoryn', 'Sugarzen', 'Sugarflex', 'SugarCalm',
    'Glucovex', 'SugarPure', 'NerveHarmony', 'NeuroHarmony', 'Nerveyn', 'NerveMax', 'Nervetide', 'MindCervy',
    'Mindoryx', 'FocusSnap', 'Leantide', 'TorchFat', 'MomBurn', 'Slim40', 'TestoHorse', 'Vigor40',
    'NeuroOil', 'Horse Boost', 'Neuro Cinnamon', 'FocusLock', 'MemoGuard', 'Renew31', 'Tinizen', 'Slimpeak',
    'SleepGood', 'FastBurn', 'Javacept', 'NeuroVex', 'Lipolean', 'TadaGummies', 'AlphaPulse', 'Eresurge',
    'GlucoBliss', 'GlycoBalance', 'Sodatide', 'VigorRise', 'Horse Pulse', 'MindCept', 'MemoClear', 'HoneyHarmony',
    'Glycoformin', 'OzemPeak', 'OzemSlim', 'SodaSlim', 'SodaBurn', 'Gumiflow', 'AlphaSteel', 'VigorFil',
    'SodaFil', 'Sugarjaro', 'Sugariance', 'JellyFil', 'Memodyne', 'HoneyPezil', 'MemoHoney', 'Neuroflow',
    'Gabaflow Mix', 'LyriBalm', 'JelloBurn', 'GlucoAloha', 'HorseFil', 'GelaFil', 'VapoCept', 'NerveHarmonny',
    'SodaLean', 'Neurapezil', 'PrimeHoney', 'HoneyBalance', 'GlycoBloom', 'JellyBoost', 'Hydrofil', 'SteelPulse',
    'Sugartide', 'Gumipic', 'Nervecept', 'Neuradyne', 'HorseSteel', 'Hydroryn', 'Honeyfil', 'Cognidyne',
    'AlkaPic', 'AlkaBurn', 'GelaLean', 'AlkaTide', 'Gelacept', 'Gelanic', 'Gumipezil', 'Glycopic',
    'SodaFit', 'Sweetide', 'Sodaryn', 'RoyalFil', 'Gelagen', 'Turmeric Harmony', 'Jellyblue', 'HoneyBoost',
    'Iron Boost', 'HearBetter', 'Gelafen', 'Gelataro', 'OliveBrain', 'CartiVex', 'Glycofit', 'HoneyFlush',
    'GiantMax', 'Vinetaro', 'Cardiopril', 'Cardiocept', 'MeltCore', 'SodaPeak', 'MatchaSlim', 'MatchaTide',
    'CardioHarmony', 'SugarClear', 'SodaPower', 'Goldtin', 'Melonex', 'AlkaFit', 'NerveHoney', 'Roscept',
    'Payarmin', 'Lympnex', 'GlycoGenesis', 'Nervactil', 'NeuroGolden', 'Marycept', 'YogTide', 'Rosedil',
    'Retride', 'Olivaro', 'Lasiberry', 'USBREX'
];
const MENCOES_PRODUTOS_LISTA = Array.from(new Set([...MENCOES_PRODUTOS_LISTA_ABERTOS, ...MENCOES_PRODUTOS_NOVOS]));
// 1º filtro rápido (busca de texto do Postgres): só olha de perto as mensagens que têm o nome de algum produto como palavra (ou frase, ex.: "sugar reset")
const MENCOES_TSQUERY = Array.from(new Set(MENCOES_PRODUTOS_LISTA
    .map(p => p.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean))
    .filter(t => t.length)
    .map(t => t.length === 1 ? t[0] : '(' + t.join(' <-> ') + ')'))).join(' | ');
// Faixa do retorno de cada ticket e os totais da linha (cada ticket conta 1 vez)
function mencoesFaixaRetorno(d) {
    if (!d.primeira_resp) return 'Sem resposta do agente';
    if (!d.retorno_em || d.retorno_horas == null) return 'Sem retorno';
    return d.retorno_horas <= 24 ? '< 24h' : (d.retorno_horas <= 48 ? '24-48h' : '> 48h');
}
// Aba Todos: junta as grafias do mesmo produto (igual ao mencoesUnificar) e, se o mesmo ticket vier pelas 2 grafias, soma como ele entrou (citado e/ou tabulado)
function mencoesUnificarTodos(linhas) {
    const mapa = new Map();
    for (const r of (linhas || [])) {
        const produto = MENCOES_APELIDOS[r.produto_mencionado] || r.produto_mencionado, chave = r.equipe + '|' + produto;
        if (!mapa.has(chave)) mapa.set(chave, { ...r, produto_mencionado: produto, detalhes: [], porId: new Map() });
        const alvo = mapa.get(chave);
        (r.detalhes || []).forEach(d => {
            const ja = alvo.porId.get(d.id);
            if (!ja) { const novo = { ...d }; alvo.porId.set(d.id, novo); alvo.detalhes.push(novo); }
            else { ja.por_texto = ja.por_texto || d.por_texto; ja.por_tab = ja.por_tab || d.por_tab; }
        });
    }
    return Array.from(mapa.values()).map(({ porId, ...r }) => ({
        ...r, qtd_casos: String(porId.size),
        detalhes: r.detalhes.map(d => ({ ...d, origem: d.por_texto && d.por_tab ? 'Citado e tabulado' : (d.por_tab ? 'Tabulado pelo agente' : 'Citado pelo cliente') }))
    })).sort((a, b) => Number(b.qtd_casos) - Number(a.qtd_casos));
}
function mencoesTotaisTodos(linhas) {
    return (linhas || []).map(r => {
        const detalhes = (r.detalhes || []).map(d => ({ ...d, faixa_retorno: mencoesFaixaRetorno(d) }));
        const conta = (f) => detalhes.filter(d => d.faixa_retorno === f).length;
        const r24 = conta('< 24h'), r48 = conta('24-48h'), rMais = conta('> 48h');
        return { ...r, detalhes, total_retornos: r24 + r48 + rMais, retornos_24h: r24, retornos_48h: r48, retornos_mais_48h: rMais };
    });
}
app.get('/api/mencoes-todos', async (req, res) => {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());

    if (!adms.includes(emailUser)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });

    try {
        let dataInicioSQL, dataFimSQL;
        if (req.query.since && req.query.until) {
            dataInicioSQL = unixParaYYYYMMDD(req.query.since);
            dataFimSQL = unixParaYYYYMMDD(req.query.until);
        } else {
            const agora = new Date(new Date().toLocaleString("en-US", {timeZone: "America/Sao_Paulo"}));
            const dInicio = new Date(agora.getFullYear(), agora.getMonth(), 1);
            dataInicioSQL = formatarDataSQL(dInicio);
            dataFimSQL = formatarDataSQL(agora);
        }

        const q = `
        WITH Palavras AS MATERIALIZED (
            SELECT kw, lower(kw) AS kwl FROM unnest($4::text[]) AS u(kw)
        ),
        Textos AS MATERIALIZED (
            SELECT m.conversation_id AS conv_id, lower(m.content) AS txt   -- texto do cliente no período
            FROM messages m
            WHERE m.account_id = 1
              AND m.message_type = 0
              AND m.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND m.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND to_tsvector('simple', left(COALESCE(m.content, ''), 50000)) @@ to_tsquery('simple', $3)
            UNION ALL
            SELECT c.id AS conv_id, lower(COALESCE(c.additional_attributes->>'subject', '')) AS txt   -- assunto do e-mail dos casos criados no período
            FROM conversations c
            WHERE c.account_id = 1
              AND c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND to_tsvector('simple', COALESCE(c.additional_attributes->>'subject', '')) @@ to_tsquery('simple', $3)
        ),
        Tabulados AS MATERIALIZED (   -- produto marcado pelo agente no atributo "produto" da conversa (a tabulação dos Produtos Tabulados), nos casos criados no período
            SELECT c.id AS conv_id,
                lower(TRIM(COALESCE(c.custom_attributes->>'produtos', c.custom_attributes->>'produto', c.custom_attributes->>'Produto'))) AS tab
            FROM conversations c
            WHERE c.account_id = 1
              AND c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND TRIM(COALESCE(c.custom_attributes->>'produtos', c.custom_attributes->>'produto', c.custom_attributes->>'Produto')) != ''
        ),
        Citacoes AS (   -- por_texto: o cliente citou (texto ou assunto) · por_tab: o agente tabulou o produto
            SELECT conv_id, kw, bool_or(por_texto) AS por_texto, bool_or(por_tab) AS por_tab
            FROM (
                SELECT tx.conv_id, p.kw, TRUE AS por_texto, FALSE AS por_tab
                FROM Textos tx
                JOIN Palavras p ON strpos(tx.txt, p.kwl) > 0   -- mesma regra da aba Abertos: o nome aparece no texto
                UNION ALL
                SELECT tb.conv_id, p.kw, FALSE, TRUE
                FROM Tabulados tb
                JOIN Palavras p ON strpos(tb.tab, p.kwl) > 0   -- tabulação com o nome de um produto da lista
                UNION ALL
                SELECT tb.conv_id, TRIM(BOTH '.' FROM INITCAP(tb.tab)), FALSE, TRUE   -- tabulação de produto que não está na lista: entra com o nome tabulado
                FROM Tabulados tb
                WHERE NOT EXISTS (SELECT 1 FROM Palavras p WHERE strpos(tb.tab, p.kwl) > 0)
            ) x
            GROUP BY conv_id, kw
        ),
        Tickets AS MATERIALIZED (   -- 1 linha por ticket citado: a 1ª mensagem do ticket e a 1ª resposta do agente
            SELECT
                c.id AS conv_id,
                (SELECT MIN(m0.created_at) FROM messages m0 WHERE m0.conversation_id = c.id AND m0.message_type IN (0, 1) AND m0.private = FALSE) AS primeira_msg,
                (SELECT MIN(mr.created_at) FROM messages mr WHERE mr.conversation_id = c.id AND mr.message_type = 1 AND mr.private = FALSE AND mr.sender_type = 'User') AS primeira_resp
            FROM conversations c
            WHERE c.id IN (SELECT conv_id FROM Citacoes)
        ),
        NoPeriodo AS (   -- só vale o ticket cuja 1ª mensagem é do período (ticket antigo com mensagem nova fica de fora)
            SELECT tk.*,
                (SELECT MIN(mc.created_at) FROM messages mc WHERE mc.conversation_id = tk.conv_id AND mc.message_type = 0 AND mc.private = FALSE
                   AND mc.created_at > tk.primeira_resp) AS retorno_em
            FROM Tickets tk
            WHERE tk.primeira_msg >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND tk.primeira_msg <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
        ),
        ComRetorno AS (   -- retorno do cliente (regra do Time 48H) e a última resposta do agente antes dele
            SELECT np.*,
                (SELECT MAX(ma.created_at) FROM messages ma WHERE ma.conversation_id = np.conv_id AND ma.message_type = 1 AND ma.private = FALSE
                   AND ma.sender_type = 'User' AND ma.created_at < np.retorno_em) AS resp_antes_retorno
            FROM NoPeriodo np
        ),
        Casos AS (
            SELECT
                CASE
                    WHEN i.name = '[GEX] SMS Support' THEN 'SMS'
                    WHEN t.name ILIKE '%retenção%' THEN 'RET'
                    WHEN t.name ILIKE '%sac%' THEN 'SAC'
                    WHEN t.name ILIKE '%back office%' THEN 'BKO'
                    WHEN c.team_id IS NULL THEN 'SEM ATRIBUIR'
                    ELSE 'OUTROS'
                END AS equipe,
                ci.kw AS produto_mencionado,
                c.id AS conv_id,
                c.display_id,
                CASE c.status WHEN 0 THEN 'Aberto' WHEN 1 THEN 'Resolvido' WHEN 2 THEN 'Pendente' WHEN 3 THEN 'Adiado' ELSE 'Outro' END AS situacao,
                ct.name AS contato_nome,
                ct.email AS contato_email,
                to_char((cr.primeira_msg AT TIME ZONE 'UTC') AT TIME ZONE 'America/Sao_Paulo', 'YYYY-MM-DD HH24:MI') AS primeira_msg,
                to_char((cr.primeira_resp AT TIME ZONE 'UTC') AT TIME ZONE 'America/Sao_Paulo', 'YYYY-MM-DD HH24:MI') AS primeira_resp,
                to_char((cr.retorno_em AT TIME ZONE 'UTC') AT TIME ZONE 'America/Sao_Paulo', 'YYYY-MM-DD HH24:MI') AS retorno_em,
                CASE WHEN cr.retorno_em IS NOT NULL AND cr.resp_antes_retorno IS NOT NULL
                     THEN ROUND((EXTRACT(EPOCH FROM (cr.retorno_em - cr.resp_antes_retorno)) / 3600)::numeric, 1)::float8 END AS retorno_horas,
                ci.por_texto,
                ci.por_tab,
                EXISTS (SELECT 1 FROM taggings tgd JOIN tags tdd ON tdd.id = tgd.tag_id   -- etiqueta "duplicado" (cliente abriu 2 tickets e um foi fechado como duplicado)
                        WHERE tgd.taggable_type = 'Conversation' AND tgd.taggable_id = c.id AND lower(tdd.name) = 'duplicado') AS duplicado
            FROM Citacoes ci
            JOIN ComRetorno cr ON cr.conv_id = ci.conv_id
            JOIN conversations c ON c.id = ci.conv_id
            LEFT JOIN teams t ON t.id = c.team_id
            LEFT JOIN inboxes i ON i.id = c.inbox_id
            LEFT JOIN contacts ct ON ct.id = c.contact_id
            WHERE (i.name IS NULL OR i.name != 'Atendimento | Brasil')
        )
        SELECT
            equipe,
            produto_mencionado,
            COUNT(conv_id) as qtd_casos,
            json_agg(json_build_object(
                'id', display_id,
                'nome', COALESCE(contato_nome, 'Sem Nome'),
                'email', COALESCE(contato_email, 'Sem Email'),
                'status', situacao,
                'primeira_msg', primeira_msg,
                'primeira_resp', primeira_resp,
                'retorno_em', retorno_em,
                'retorno_horas', retorno_horas,
                'por_texto', por_texto,
                'por_tab', por_tab,
                'duplicado', duplicado
            ) ORDER BY display_id DESC) AS detalhes
        FROM Casos
        WHERE equipe != 'OUTROS'
        GROUP BY equipe, produto_mencionado
        ORDER BY qtd_casos DESC;
        `;
        // Sem o JIT do Postgres: a compilação dele gastava ~3,5 s nesta consulta (em 1 dia, quase todo o tempo). Desligado SÓ aqui:
        // SET + consulta + RESET vão juntos no mesmo pedido (mesma conexão e mesmo freio do pool.query); se der erro, o banco desfaz o SET sozinho.
        const lit = (v) => "'" + String(v).replace(/'/g, "''") + "'";
        let result;
        if (/^\d{4}-\d{2}-\d{2}$/.test(dataInicioSQL) && /^\d{4}-\d{2}-\d{2}$/.test(dataFimSQL)) {
            const qSemJit = q.replace(/\$1/g, lit(dataInicioSQL)).replace(/\$2/g, lit(dataFimSQL)).replace(/\$3/g, lit(MENCOES_TSQUERY))
                .replace('$4::text[]', 'ARRAY[' + MENCOES_PRODUTOS_LISTA.map(lit).join(', ') + ']::text[]');
            try { result = (await pool.query('SET jit = off; ' + qSemJit + '; RESET jit;'))[1]; }
            catch (e) { if (!/jit/i.test(String(e && e.message))) throw e; }   // banco sem a opção jit: roda do jeito normal abaixo
        }
        if (!result) result = await pool.query(q, [dataInicioSQL, dataFimSQL, MENCOES_TSQUERY, MENCOES_PRODUTOS_LISTA]);
        res.json({ success: true, dados: mencoesTotaisTodos(mencoesUnificarTodos(result.rows)), periodo: { inicio: dataInicioSQL, fim: dataFimSQL } });
    } catch (error) {
        console.error("Erro Rota Menções (Todos):", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==========================================
// 15. ROTA DE AUDITORIA DE TICKETS (QUALIDADE)
// ==========================================
app.get('/api/qualidade-tickets', async (req, res) => {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    
    if (!adms.includes(emailUser)) {
        return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
    }
    
    try {
        let dataInicioSQL, dataFimSQL;
        if (req.query.since && req.query.until) {
            dataInicioSQL = unixParaYYYYMMDD(req.query.since);
            dataFimSQL = unixParaYYYYMMDD(req.query.until);
        } else {
            // Padrão: DIA ATUAL (o calendário fica pra escolher um período maior, ex.: o mês todo)
            const agora = new Date(new Date().toLocaleString("en-US", {timeZone: "America/Sao_Paulo"}));
            dataInicioSQL = formatarDataSQL(agora);
            dataFimSQL = formatarDataSQL(agora);
        }

        const q = `
        WITH BaseAcoes AS (
            SELECT 
                m.conversation_id,
                c.display_id,
                m.message_type,
                m.content,
                m.created_at AS m_created_at,
                c.status AS conv_status,
                -- 🔥 O HISTORIADOR: Tenta pegar o tempo exato no momento que o botão foi clicado!
                COALESCE(m.content_attributes->>'snoozed_until', c.snoozed_until::text) AS snoozed_until,
                COALESCE(
                    (CASE WHEN m.message_type = 1 THEN u_sender.name END), 
                    SUBSTRING(m.content FROM '(?i)por (.*? - (?:RET|SAC|BKO|SMS))'), 
                    u_assignee.name 
                ) AS agente_nome
            FROM messages m
            JOIN conversations c ON c.id = m.conversation_id
            LEFT JOIN users u_sender ON u_sender.id = m.sender_id
            LEFT JOIN users u_assignee ON u_assignee.id = c.assignee_id
            WHERE m.account_id = 1
              AND m.message_type IN (1, 2) 
              AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE
              AND m.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND m.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
        ),
        AcoesValidas AS (
            SELECT * FROM BaseAcoes WHERE agente_nome IS NOT NULL AND agente_nome != ''
        ),
        ConversasAgrupadas AS (
            SELECT 
                agente_nome,
                CASE 
                    WHEN agente_nome ILIKE '%- RET%' THEN 'RET'
                    WHEN agente_nome ILIKE '%- SAC%' THEN 'SAC'
                    WHEN agente_nome ILIKE '%- BKO%' THEN 'BKO'
                    WHEN agente_nome ILIKE '%- SMS%' THEN 'SMS'
                    WHEN agente_nome ILIKE '%- 48H%' THEN '48H'
                    ELSE 'OUTROS'
                END AS equipe,
                display_id,
                conversation_id,
                COUNT(CASE WHEN message_type = 2 AND content ILIKE '%adiad%' THEN 1 END) AS qtd_adiado,
                COUNT(CASE WHEN message_type = 2 AND content ILIKE '%resolvid%' THEN 1 END) AS qtd_resolvido,
                json_agg(
                    json_build_object(
                        'tipo', message_type,
                        'texto', COALESCE(content, 'Ação do Sistema'),
                        'data', m_created_at,
                        'snooze', snoozed_until,
                        'status_conv', conv_status
                    ) ORDER BY m_created_at ASC
                ) AS eventos
            FROM AcoesValidas
            GROUP BY agente_nome, display_id, conversation_id
        )
        SELECT 
            agente_nome,
            equipe,
            COUNT(DISTINCT conversation_id) AS total_alterados,
            SUM(CASE WHEN qtd_adiado > 0 THEN 1 ELSE 0 END) AS total_adiados,
            SUM(CASE WHEN qtd_resolvido > 0 THEN 1 ELSE 0 END) AS total_resolvidos,
            json_agg(
                json_build_object(
                    'id', display_id,
                    'conversation_id', conversation_id,
                    'adiados', qtd_adiado,
                    'resolvidos', qtd_resolvido,
                    'eventos', eventos
                ) ORDER BY display_id DESC
            ) AS detalhes
        FROM ConversasAgrupadas
        WHERE equipe != 'OUTROS'
        GROUP BY agente_nome, equipe
        ORDER BY total_alterados DESC;
        `;
        const result = await pool.query(q, [dataInicioSQL, dataFimSQL]);

        // 🅱️ ENRIQUECER com o snooze capturado (planilha) — recupera a escolha até em conversas reabertas
        try {
            const sheetsLog = getSheetsRW();
            const rlog = await sheetsLog.spreadsheets.values.get({ spreadsheetId: SNOOZE_SHEET_ID, range: `${SNOOZE_ABA}!A2:F100000` });
            const snoozeMap = {};
            for (const row of (rlog.data.values || [])) {
                const convId = row[1]; if (!convId) continue;
                const ts = new Date(row[0]).getTime();
                const until = (row[3] && String(row[3]).trim()) ? String(row[3]).trim() : null;
                (snoozeMap[String(convId)] = snoozeMap[String(convId)] || []).push({ ts, until });
            }
            const JANELA = 30 * 60 * 1000; // 30 min de tolerância entre o evento e a captura
            for (const linha of result.rows) {
                for (const d of (linha.detalhes || [])) {
                    const capturas = snoozeMap[String(d.conversation_id)] || [];
                    for (const ev of (d.eventos || [])) {
                        if (!((ev.texto || '').toLowerCase().includes('adiad'))) continue;
                        if (ev.snooze) { ev.snooze_tipo = 'timed'; continue; } // já tem tempo vivo
                        const tEv = new Date(ev.data).getTime();
                        let melhor = null, melhorDif = Infinity;
                        for (const c of capturas) { const dif = Math.abs(c.ts - tEv); if (dif < melhorDif) { melhorDif = dif; melhor = c; } }
                        if (melhor && melhorDif <= JANELA) {
                            if (melhor.until) { ev.snooze = melhor.until; ev.snooze_tipo = 'timed'; }
                            else { ev.snooze_tipo = 'proxima'; }
                        } else {
                            ev.snooze_tipo = (Number(ev.status_conv) === 3) ? 'proxima' : 'desconhecido';
                        }
                    }
                }
            }
        } catch (e) { console.error('[qualidade] enriquecer snooze falhou:', e.message); }

        res.json({ success: true, dados: result.rows });
    } catch (error) { 
        console.error("Erro Rota Monitoria:", error);
        res.status(500).json({ success: false, error: error.message }); 
    }
});

// ==========================================
// 16. ROTA DE URGÊNCIA: REEMBOLSOS PAGAMERICAN (COM GOOGLE SHEETS)
// ==========================================
app.get('/api/reembolsos-pagamerican', async (req, res) => {
    // 🔥 COLE SEU LINK DO GOOGLE AQUI DENTRO DAS ASPAS:
    const URL_PLANILHA = "https://script.google.com/macros/s/AKfycbxLqWTExvo0824oEpWUJYbDIzVdK4q9S3eeElIo0n8eliTCYueQjOJIB0AOCPuDnl1LSw/exec";

    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    
    if (!adms.includes(emailUser)) {
        return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
    }
    
    try {
        // 1. LER O COFRE DO GOOGLE SHEETS
        // LOG (prioridade). Imutável: 1 por ticket, mantém o antigo.
        // OTIMIZACAO: o log do Google (fetch) roda em PARALELO com a query do banco (antes era sequencial) — tempo total cai p/ o maior dos dois, nao a soma
        const _pLog = (async () => {
            let logMap = {};
            try {
                const _r = await fetch(URL_PLANILHA, { redirect: 'follow' });
                const _t = (await _r.text()).trim();
                const dadosPlanilha = (_t.startsWith('[') || _t.startsWith('{')) ? JSON.parse(_t) : [];
                if (Array.isArray(dadosPlanilha)) dadosPlanilha.forEach(l => {
                    const tk = String(l.ticket || l[0] || '').trim();
                    if (!tk || logMap[tk] || /sem reembolso/i.test(String(l.tipo || l[2] || ''))) return;
                    const dl = new Date(l.data_hora || l[1]);
                    logMap[tk] = { data: isNaN(dl) ? null : dl, tipo: l.tipo || '', pedido: l.pedido || '', produto: l.produto || '', cliente: l.cliente || '', email: l.email || '' };
                });
            } catch (err) { console.log("Aviso: falha ao ler o log de reembolso.", err.message); }
            return logMap;
        })();

        // 2. FILTRO DE DATAS DO PAINEL
        let dInicio, dFim;
        if (req.query.since && req.query.until) {
            dInicio = new Date(parseInt(req.query.since) * 1000);
            dFim = new Date(parseInt(req.query.until) * 1000);
        } else {
            const agora = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Sao_Paulo" }));
            dInicio = new Date(agora.getFullYear(), agora.getMonth(), 1);
            dFim = agora;
        }
        const dCorte = new Date(dInicio); dCorte.setDate(dCorte.getDate() - 90); const dCorteSQL = dCorte.toISOString().slice(0, 10); // E: filtro de data movido pro banco (periodo + 90 dias de margem) — reduz o scan sem cortar resultado

        // 3. LER O BANCO DO CHATWOOT (100% LEITURA, SEM FILTRAR DATA AQUI)
        const q = `
        SELECT 
            c.id AS conv_id,
            c.display_id,
            COALESCE(u.name, 'SEM ATRIBUIR') AS agente_nome,
            ct.name AS contato_nome,
            ct.email AS contato_email,
            c.updated_at AS data_fallback,
            COALESCE(c.custom_attributes->>'tipo_de_retencao_de_reembolso', ct.custom_attributes->>'tipo_de_retencao_de_reembolso', '') AS tipo_retencao,
            COALESCE(
                NULLIF(TRIM(c.custom_attributes->>'order_number'), ''), 
                NULLIF(TRIM(ct.custom_attributes->>'order_number'), ''),
                NULLIF(TRIM(c.custom_attributes->>'numero_do_pedido'), ''), 
                NULLIF(TRIM(ct.custom_attributes->>'numero_do_pedido'), ''),
                NULLIF(TRIM(c.custom_attributes->>'numero_pedido'), ''), 
                NULLIF(TRIM(ct.custom_attributes->>'numero_pedido'), ''),
                NULLIF(TRIM(c.custom_attributes->>'Número do Pedido'), ''), 
                ''
            ) AS pedido_limpo,
            COALESCE(NULLIF(TRIM(c.custom_attributes->>'produtos'),''), NULLIF(TRIM(c.custom_attributes->>'produto'),''), NULLIF(TRIM(c.custom_attributes->>'Produto'),''), NULLIF(TRIM(ct.custom_attributes->>'produtos'),''), NULLIF(TRIM(ct.custom_attributes->>'produto'),''), NULLIF(TRIM(ct.custom_attributes->>'Produto'),''), '') AS produto_nome
        FROM conversations c
        LEFT JOIN users u ON u.id = c.assignee_id
        LEFT JOIN contacts ct ON ct.id = c.contact_id
        WHERE c.account_id = 1
          AND c.updated_at >= $1::timestamp
          AND (
              COALESCE(c.custom_attributes::text, '') ILIKE ANY(ARRAY['%pagamerican%', '%pagamerica%', '%pag american%', '%pag_american%']) OR
              COALESCE(ct.custom_attributes::text, '') ILIKE ANY(ARRAY['%pagamerican%', '%pagamerica%', '%pag american%', '%pag_american%'])
          )
          AND COALESCE(c.custom_attributes->>'tipo_de_retencao_de_reembolso', ct.custom_attributes->>'tipo_de_retencao_de_reembolso', '') != ''
          AND COALESCE(c.custom_attributes->>'tipo_de_retencao_de_reembolso', ct.custom_attributes->>'tipo_de_retencao_de_reembolso', '') NOT ILIKE '%sem reembolso%'
        `;
        const [logMap, result] = await Promise.all([_pLog, pool.query(q, [dCorteSQL])]);

        // 4. CRUZAMENTO DE DADOS (NODE.JS FAZ O TRABALHO PESADO)
        const resumoAgentes = {};
        
        result.rows.forEach(tk => {
            const L = logMap[String(tk.display_id)];
            const noLog = !!(L && L.data);
            const fonte = noLog ? 'Log' : 'Conversa';
            const dataReal    = noLog ? L.data      : new Date(tk.data_fallback);
            const tipoReal    = (noLog && L.tipo)    ? L.tipo    : tk.tipo_retencao;
            const pedidoReal  = (noLog && L.pedido)  ? L.pedido  : tk.pedido_limpo;
            const produtoReal = (noLog && L.produto) ? L.produto : (tk.produto_nome || 'Não informado');
            const clienteReal = (noLog && L.cliente) ? L.cliente : (tk.contato_nome || 'Sem Nome');
            const emailReal   = (noLog && L.email)   ? L.email   : (tk.contato_email || 'Sem Email');

            if (dataReal >= dInicio && dataReal <= dFim) {
                const agente = tk.agente_nome;
                if (!resumoAgentes[agente]) resumoAgentes[agente] = { agente_nome: agente, total_reembolsos: 0, r_10_30: 0, r_40_50: 0, r_60_90: 0, r_100: 0, r_outros: 0, detalhes: [] };
                resumoAgentes[agente].total_reembolsos++;
                const tipo = String(tipoReal).toLowerCase();
                if (tipo.includes('10 a 30%')) resumoAgentes[agente].r_10_30++;
                else if (tipo.includes('40 a 50%')) resumoAgentes[agente].r_40_50++;
                else if (tipo.includes('60 a 90%')) resumoAgentes[agente].r_60_90++;
                else if (tipo.includes('100%')) resumoAgentes[agente].r_100++;
                else resumoAgentes[agente].r_outros++;
                resumoAgentes[agente].detalhes.push({
                    id: tk.display_id, nome: clienteReal, email: emailReal,
                    data: dataReal, tipo: tipoReal, pedido: pedidoReal, produto: produtoReal,
                    fonte: fonte
                });
            }
        });

        // 5. ORGANIZAR E ENVIAR PARA O PAINEL
        const arrayFinal = Object.values(resumoAgentes).map(ag => {
            ag.detalhes.sort((a, b) => b.data - a.data); // Ordena detalhes do mais novo pro mais velho
            return ag;
        });
        arrayFinal.sort((a, b) => b.total_reembolsos - a.total_reembolsos); // Ordena o ranking de agentes

        res.json({ success: true, dados: arrayFinal });
    } catch (error) { 
        console.error("Erro PagAmerican:", error);
        res.status(500).json({ success: false, error: "Erro interno no servidor." }); 
    }
});

// ==========================================
// 17. ROTA: TIME 48 HORAS (ETIQUETAS + RETORNOS)
// ==========================================
app.get('/api/time48', async (req, res) => {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    
    if (!adms.includes(emailUser)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
    
    try {
        let dataInicioSQL, dataFimSQL;
        if (req.query.since && req.query.until) {
            dataInicioSQL = unixParaYYYYMMDD(req.query.since);
            dataFimSQL = unixParaYYYYMMDD(req.query.until);
        } else {
            const agora = new Date(new Date().toLocaleString("en-US", {timeZone: "America/Sao_Paulo"}));
            const dInicio = new Date(agora.getFullYear(), agora.getMonth(), 1);   // sem data escolhida = mês atual (do dia 1º até hoje); outro período pelo calendário
            dataInicioSQL = formatarDataSQL(dInicio);
            dataFimSQL = formatarDataSQL(agora);
        }

        // 🛡️ Conversas com as etiquetas buscadas UMA vez: as consultas abaixo só leem essas conversas, sem varrer todas as conversas do Chatwoot
        const idsTime = (await pool.query(`SELECT DISTINCT t.taggable_id AS id FROM taggings t JOIN tags tg ON tg.id = t.tag_id WHERE t.taggable_type = 'Conversation' AND (tg.name ILIKE '%time-48h%' OR tg.name ILIKE 'painel-do-pedido%')`)).rows.map(r => r.id);
        const q = `
        WITH CasosFiltrados AS (
            SELECT DISTINCT
                c.id AS conv_id,
                c.display_id,
                COALESCE(u.name, 'SEM ATRIBUIR') AS agente,
                c.created_at,
                (SELECT MIN(mr.created_at) FROM messages mr WHERE mr.conversation_id = c.id AND mr.message_type = 1 AND mr.private = FALSE AND mr.sender_type = 'User') AS primeira_resp_agente
            FROM conversations c
            LEFT JOIN users u ON u.id = c.assignee_id
            WHERE c.account_id = 1
              AND c.id = ANY($3::bigint[])
              AND c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
        ),
        PorTicket AS (
            -- 🛡️ cada ticket é calculado UMA vez (antes os subselects de TMC/TMR rodavam de novo pra cada mensagem do ticket)
            SELECT
                cf.conv_id,
                cf.agente,
                GREATEST((SELECT COUNT(*) FROM messages mp WHERE mp.conversation_id = cf.conv_id AND mp.private = FALSE), 1) AS peso,
                EXISTS (SELECT 1 FROM messages mt WHERE mt.conversation_id = cf.conv_id AND mt.private = FALSE AND mt.message_type = 0 AND mt.created_at > cf.primeira_resp_agente) AS teve_retorno,
                (SELECT COUNT(*) FROM messages me WHERE me.conversation_id = cf.conv_id AND me.private = FALSE AND me.message_type = 1 AND me.sender_type = 'User' AND (me.content_attributes->>'deleted')::boolean IS NOT TRUE) AS msgs_enviadas,
                EXTRACT(EPOCH FROM (
                    (SELECT MIN(m1.created_at) FROM messages m1 WHERE m1.conversation_id = cf.conv_id AND m1.message_type = 1 AND m1.private = FALSE AND m1.sender_type = 'User') - cf.created_at   -- TMC: 1ª mensagem do AGENTE (bot e automação não contam)
                )::interval) AS tmc_seg,
                (SELECT AVG(EXTRACT(EPOCH FROM (resp.created_at - msg.created_at)::interval))
                    FROM messages msg
                    JOIN messages resp ON resp.conversation_id = msg.conversation_id
                                      AND resp.message_type = 1
                                      AND resp.private = FALSE
                                      AND resp.sender_type = 'User'   -- TMR: só resposta do AGENTE
                                      AND resp.created_at > msg.created_at
                    WHERE msg.conversation_id = cf.conv_id
                      AND msg.message_type = 0
                      AND msg.private = FALSE
                      AND NOT EXISTS (
                          SELECT 1 FROM messages m_mid
                          WHERE m_mid.conversation_id = msg.conversation_id
                            AND m_mid.created_at > msg.created_at
                            AND m_mid.created_at < resp.created_at
                            AND NOT (m_mid.message_type IN (1, 3) AND m_mid.private = FALSE AND m_mid.sender_type IS DISTINCT FROM 'User')   -- bot/automação no meio não conta
                      )
                ) AS tmr_seg
            FROM CasosFiltrados cf
        ),
        StatsAgente AS (
            -- mesmos números de antes: TMC e TMR seguem ponderados pela quantidade de mensagens públicas do ticket (como a média por mensagem fazia)
            SELECT
                agente,
                COUNT(*) AS total_tickets,
                COUNT(*) FILTER (WHERE teve_retorno) AS retornos,
                SUM(msgs_enviadas)::bigint AS mensagens_enviadas,
                COALESCE(SUM(tmc_seg * peso) / NULLIF(SUM(peso) FILTER (WHERE tmc_seg IS NOT NULL), 0) / 60, 0) AS tmc_minutos,
                COALESCE(SUM(tmr_seg * peso) / NULLIF(SUM(peso) FILTER (WHERE tmr_seg IS NOT NULL), 0) / 60, 0) AS tmr_minutos
            FROM PorTicket
            GROUP BY agente
        )
        SELECT 
            agente,
            total_tickets AS tickets,
            retornos,
            mensagens_enviadas AS mensagens,
            tmc_minutos AS tmc_medio_minutos,
            tmr_minutos AS tmr_medio_minutos
        FROM StatsAgente
        ORDER BY total_tickets DESC;
        `;
        const result = await pool.query(q, [dataInicioSQL, dataFimSQL, idsTime]);

        // Lista de tickets por agente (para o "Ver Tickets" abrir as conversas, igual aos demais paineis)
        const qDetalhes = `
            SELECT DISTINCT
                COALESCE(u.name, 'SEM ATRIBUIR') AS agente,
                c.display_id,
                c.id AS conv_id,
                ct.name AS cliente
            FROM conversations c
            LEFT JOIN users u ON u.id = c.assignee_id
            LEFT JOIN contacts ct ON ct.id = c.contact_id
            WHERE c.account_id = 1
              AND c.id = ANY($3::bigint[])
              AND c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
            ORDER BY c.display_id DESC;
        `;
        const detResult = await pool.query(qDetalhes, [dataInicioSQL, dataFimSQL, idsTime]);
        const detalhesPorAgente = {};
        detResult.rows.forEach(r => {
            if (!detalhesPorAgente[r.agente]) detalhesPorAgente[r.agente] = [];
            detalhesPorAgente[r.agente].push({ id: r.display_id || r.conv_id, cliente: r.cliente || 'Cliente sem nome' });
        });

        // Em aberto agora (status Aberta no Chatwoot) de todo o período, sem filtro de data — por agente
        const qAbertos = `
            SELECT COALESCE(u.name, 'SEM ATRIBUIR') AS agente, COUNT(DISTINCT c.id) AS em_aberto
            FROM conversations c
            LEFT JOIN users u ON u.id = c.assignee_id
            WHERE c.account_id = 1
              AND c.status = 0
              AND c.id = ANY($1::bigint[])
            GROUP BY 1;
        `;
        const abResult = await pool.query(qAbertos, [idsTime]);
        const abertosPorAgente = {};
        abResult.rows.forEach(r => { abertosPorAgente[r.agente] = parseInt(r.em_aberto) || 0; });
        // Abertos criados fora do período escolhido: entram no "Ver Tickets" pra bater com a coluna Em Aberto
        const qAbertosFora = `
            SELECT DISTINCT
                COALESCE(u.name, 'SEM ATRIBUIR') AS agente,
                c.display_id,
                c.id AS conv_id,
                ct.name AS cliente
            FROM conversations c
            LEFT JOIN users u ON u.id = c.assignee_id
            LEFT JOIN contacts ct ON ct.id = c.contact_id
            WHERE c.account_id = 1
              AND c.status = 0
              AND c.id = ANY($3::bigint[])
              AND NOT (c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                   AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo')
            ORDER BY c.display_id DESC;
        `;
        const foraResult = await pool.query(qAbertosFora, [dataInicioSQL, dataFimSQL, idsTime]);
        foraResult.rows.forEach(r => {
            if (!detalhesPorAgente[r.agente]) detalhesPorAgente[r.agente] = [];
            detalhesPorAgente[r.agente].push({ id: r.display_id || r.conv_id, cliente: r.cliente || 'Cliente sem nome', fora_periodo: true });
        });
        // Detalhe de cada ticket p/ o "Ver Tickets": situação no Chatwoot, retorno do cliente (depois da 1ª resposta do agente), mensagens do agente e etiquetas
        const qInfo = `
            SELECT x.*, COALESCE(x.ultima_msg_cliente > x.primeira_resp_agente, FALSE) AS teve_retorno
            FROM (
                SELECT
                    c.display_id,
                    c.id AS conv_id,
                    c.status,
                    c.created_at,
                    (SELECT MIN(mr.created_at) FROM messages mr WHERE mr.conversation_id = c.id AND mr.message_type = 1 AND mr.private = FALSE AND mr.sender_type = 'User') AS primeira_resp_agente,
                    (SELECT MAX(mc.created_at) FROM messages mc WHERE mc.conversation_id = c.id AND mc.message_type = 0 AND mc.private = FALSE) AS ultima_msg_cliente,
                    (SELECT COUNT(*) FROM messages ma WHERE ma.conversation_id = c.id AND ma.message_type = 1 AND ma.private = FALSE AND ma.sender_type = 'User' AND (ma.content_attributes->>'deleted')::boolean IS NOT TRUE) AS msgs_agente,
                    (SELECT string_agg(DISTINCT tg2.name, ', ' ORDER BY tg2.name) FROM taggings t2 JOIN tags tg2 ON tg2.id = t2.tag_id
                      WHERE t2.taggable_id = c.id AND t2.taggable_type = 'Conversation' AND (tg2.name ILIKE '%time-48h%' OR tg2.name ILIKE 'painel-do-pedido%')) AS etiquetas
                FROM conversations c
                WHERE c.account_id = 1
                  AND c.id = ANY($3::bigint[])
                  AND ((c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                    AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo') OR c.status = 0)
            ) x;
        `;
        const infoResult = await pool.query(qInfo, [dataInicioSQL, dataFimSQL, idsTime]);
        const infoPorId = {};
        infoResult.rows.forEach(r => {
            infoPorId[String(r.display_id || r.conv_id)] = {
                status: r.status, teve_retorno: r.teve_retorno === true, ultimo_retorno: r.teve_retorno ? r.ultima_msg_cliente : null,
                msgs_agente: parseInt(r.msgs_agente) || 0, etiquetas: r.etiquetas || '', criado_em: r.created_at
            };
        });
        Object.values(detalhesPorAgente).forEach(lista => lista.forEach(tk => Object.assign(tk, infoPorId[String(tk.id)] || {})));
        // SLA do Time 48H por ticket: há quanto tempo está em aberto, quanto o cliente levou pra retornar e há quanto tempo o agente espera o cliente
        const qSla = `
            SELECT
                y.display_id,
                y.conv_id,
                CASE WHEN y.status = 0 THEN (EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - y.created_at)) / 60)::float8 END AS aberto_ha_min,
                CASE WHEN y.primeiro_retorno_em IS NOT NULL AND y.resp_antes_retorno IS NOT NULL
                     THEN (EXTRACT(EPOCH FROM (y.primeiro_retorno_em - y.resp_antes_retorno)) / 60)::float8 END AS retorno_cliente_min,
                CASE WHEN y.status = 0 AND y.ultima_resp_agente IS NOT NULL AND (y.ultima_msg_cliente IS NULL OR y.ultima_resp_agente > y.ultima_msg_cliente)
                     THEN (EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - y.ultima_resp_agente)) / 60)::float8 END AS aguardando_cliente_min,
                CASE WHEN y.status = 0 AND y.ultima_msg_cliente IS NOT NULL AND (y.ultima_resp_agente IS NULL OR y.ultima_msg_cliente > y.ultima_resp_agente)
                     THEN (EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - y.ultima_msg_cliente)) / 60)::float8 END AS cliente_esperando_min
            FROM (
                SELECT z.*,
                    (SELECT MAX(mr.created_at) FROM messages mr WHERE mr.conversation_id = z.conv_id AND mr.message_type = 1 AND mr.private = FALSE
                       AND mr.sender_type = 'User' AND mr.created_at < z.primeiro_retorno_em) AS resp_antes_retorno
                FROM (
                  SELECT w.*,
                    (SELECT MIN(mc.created_at) FROM messages mc WHERE mc.conversation_id = w.conv_id AND mc.message_type = 0 AND mc.private = FALSE
                       AND mc.created_at > w.primeira_resp_sla) AS primeiro_retorno_em
                  FROM (
                    SELECT
                        c.display_id,
                        c.id AS conv_id,
                        c.status,
                        c.created_at,
                        (SELECT MIN(mr.created_at) FROM messages mr WHERE mr.conversation_id = c.id AND mr.message_type = 1 AND mr.private = FALSE AND mr.sender_type = 'User') AS primeira_resp_sla,
                        (SELECT MAX(mr.created_at) FROM messages mr WHERE mr.conversation_id = c.id AND mr.message_type = 1 AND mr.private = FALSE AND mr.sender_type = 'User') AS ultima_resp_agente,
                        (SELECT MAX(mc.created_at) FROM messages mc WHERE mc.conversation_id = c.id AND mc.message_type = 0 AND mc.private = FALSE) AS ultima_msg_cliente
                    FROM conversations c
                    WHERE c.account_id = 1
                      AND c.id = ANY($3::bigint[])
                      AND ((c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                        AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo') OR c.status = 0)
                  ) w
                ) z
            ) y;
        `;
        const slaResult = await pool.query(qSla, [dataInicioSQL, dataFimSQL, idsTime]);
        const slaPorId = {};
        slaResult.rows.forEach(r => {
            slaPorId[String(r.display_id || r.conv_id)] = { aberto_ha_min: r.aberto_ha_min, retorno_cliente_min: r.retorno_cliente_min, aguardando_cliente_min: r.aguardando_cliente_min, cliente_esperando_min: r.cliente_esperando_min };
        });
        Object.values(detalhesPorAgente).forEach(lista => lista.forEach(tk => Object.assign(tk, slaPorId[String(tk.id)] || {})));
        const dados = result.rows.map(r => ({ ...r, detalhes: detalhesPorAgente[r.agente] || [] }));
        dados.forEach(d => { d.em_aberto = abertosPorAgente[d.agente] || 0; });
        // Agente com caso em aberto mas sem ticket recebido no período escolhido: entra na tabela com 0 recebidos
        Object.keys(abertosPorAgente).forEach(ag => {
            if (!dados.some(d => d.agente === ag)) dados.push({ agente: ag, tickets: 0, retornos: 0, mensagens: 0, tmc_medio_minutos: 0, tmr_medio_minutos: 0, detalhes: detalhesPorAgente[ag] || [], em_aberto: abertosPorAgente[ag] });
        });
        // SLA por agente: média do tempo de retorno do cliente, média do tempo em aberto e quantos abertos passaram de 48h
        dados.forEach(d => {
            const dets = d.detalhes || [];
            const ab = dets.filter(t => t.aberto_ha_min != null), rt = dets.filter(t => !t.fora_periodo && t.retorno_cliente_min != null);
            d.sla_retorno_medio_min = rt.length ? rt.reduce((s, t) => s + t.retorno_cliente_min, 0) / rt.length : null;
            d.sla_aberto_medio_min = ab.length ? ab.reduce((s, t) => s + t.aberto_ha_min, 0) / ab.length : null;
            d.sla_aberto_fora = dets.filter(t => t.cliente_esperando_min != null && t.cliente_esperando_min > 48 * 60).length;   // fora do SLA = cliente mandou a última mensagem e está há +48h sem resposta do agente
        });
        res.json({ success: true, dados: dados });
    } catch (error) { 
        console.error("Erro Time 48h:", error);
        res.status(500).json({ success: false, error: error.message }); 
    }
});

// ==========================================
// 17.1 ROTA: TIME 48 HORAS POR ETIQUETA (abas "Etiqueta 48H" e "Etiqueta Painel")
// Mesmas colunas e mesma lógica da /api/time48, filtrando só as etiquetas marcadas.
// Conversa com 2+ etiquetas marcadas conta 1 vez. 100% leitura.
// ==========================================
app.get('/api/time48-etiquetas', async (req, res) => {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    
    if (!adms.includes(emailUser)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
    
    try {
        // Etiquetas marcadas na aba (?etiquetas=a,b,c) — só grupos time-48h* e painel-do-pedido* (máx. 30)
        const etiquetas = [...new Set(String(req.query.etiquetas || '').split(',')
            .map(e => e.trim().toLowerCase())
            .filter(e => /^(time-48h|painel-do-pedido)[a-z0-9-]*$/.test(e)))].slice(0, 30);
        if (etiquetas.length === 0) return res.json({ success: true, dados: [], etiquetas: [] });

        let dataInicioSQL, dataFimSQL;
        if (req.query.since && req.query.until) {
            dataInicioSQL = unixParaYYYYMMDD(req.query.since);
            dataFimSQL = unixParaYYYYMMDD(req.query.until);
        } else {
            const agora = new Date(new Date().toLocaleString("en-US", {timeZone: "America/Sao_Paulo"}));
            const dInicio = new Date(agora.getFullYear(), agora.getMonth(), 1);
            dataInicioSQL = formatarDataSQL(dInicio);
            dataFimSQL = formatarDataSQL(agora);
        }

        // 🛡️ Conversas com as etiquetas buscadas UMA vez: as consultas abaixo só leem essas conversas, sem varrer todas as conversas do Chatwoot
        const idsSel = (await pool.query(`SELECT DISTINCT t.taggable_id AS id FROM taggings t JOIN tags tg ON tg.id = t.tag_id WHERE t.taggable_type = 'Conversation' AND lower(tg.name) = ANY($1::text[])`, [etiquetas])).rows.map(r => r.id);
        const q = `
        WITH CasosFiltrados AS (
            SELECT DISTINCT
                c.id AS conv_id,
                c.display_id,
                COALESCE(u.name, 'SEM ATRIBUIR') AS agente,
                c.created_at,
                (SELECT MIN(mr.created_at) FROM messages mr WHERE mr.conversation_id = c.id AND mr.message_type = 1 AND mr.private = FALSE AND mr.sender_type = 'User') AS primeira_resp_agente
            FROM conversations c
            LEFT JOIN users u ON u.id = c.assignee_id
            WHERE c.account_id = 1
              AND c.id = ANY($3::bigint[])
              AND c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
        ),
        PorTicket AS (
            -- 🛡️ cada ticket é calculado UMA vez (antes os subselects de TMC/TMR rodavam de novo pra cada mensagem do ticket)
            SELECT
                cf.conv_id,
                cf.agente,
                GREATEST((SELECT COUNT(*) FROM messages mp WHERE mp.conversation_id = cf.conv_id AND mp.private = FALSE), 1) AS peso,
                EXISTS (SELECT 1 FROM messages mt WHERE mt.conversation_id = cf.conv_id AND mt.private = FALSE AND mt.message_type = 0 AND mt.created_at > cf.primeira_resp_agente) AS teve_retorno,
                (SELECT COUNT(*) FROM messages me WHERE me.conversation_id = cf.conv_id AND me.private = FALSE AND me.message_type = 1 AND me.sender_type = 'User' AND (me.content_attributes->>'deleted')::boolean IS NOT TRUE) AS msgs_enviadas,
                EXTRACT(EPOCH FROM (
                    (SELECT MIN(m1.created_at) FROM messages m1 WHERE m1.conversation_id = cf.conv_id AND m1.message_type = 1 AND m1.private = FALSE AND m1.sender_type = 'User') - cf.created_at   -- TMC: 1ª mensagem do AGENTE (bot e automação não contam)
                )::interval) AS tmc_seg,
                (SELECT AVG(EXTRACT(EPOCH FROM (resp.created_at - msg.created_at)::interval))
                    FROM messages msg
                    JOIN messages resp ON resp.conversation_id = msg.conversation_id
                                      AND resp.message_type = 1
                                      AND resp.private = FALSE
                                      AND resp.sender_type = 'User'   -- TMR: só resposta do AGENTE
                                      AND resp.created_at > msg.created_at
                    WHERE msg.conversation_id = cf.conv_id
                      AND msg.message_type = 0
                      AND msg.private = FALSE
                      AND NOT EXISTS (
                          SELECT 1 FROM messages m_mid
                          WHERE m_mid.conversation_id = msg.conversation_id
                            AND m_mid.created_at > msg.created_at
                            AND m_mid.created_at < resp.created_at
                            AND NOT (m_mid.message_type IN (1, 3) AND m_mid.private = FALSE AND m_mid.sender_type IS DISTINCT FROM 'User')   -- bot/automação no meio não conta
                      )
                ) AS tmr_seg
            FROM CasosFiltrados cf
        ),
        StatsAgente AS (
            -- mesmos números de antes: TMC e TMR seguem ponderados pela quantidade de mensagens públicas do ticket (como a média por mensagem fazia)
            SELECT
                agente,
                COUNT(*) AS total_tickets,
                COUNT(*) FILTER (WHERE teve_retorno) AS retornos,
                SUM(msgs_enviadas)::bigint AS mensagens_enviadas,
                COALESCE(SUM(tmc_seg * peso) / NULLIF(SUM(peso) FILTER (WHERE tmc_seg IS NOT NULL), 0) / 60, 0) AS tmc_minutos,
                COALESCE(SUM(tmr_seg * peso) / NULLIF(SUM(peso) FILTER (WHERE tmr_seg IS NOT NULL), 0) / 60, 0) AS tmr_minutos
            FROM PorTicket
            GROUP BY agente
        )
        SELECT 
            agente,
            total_tickets AS tickets,
            retornos,
            mensagens_enviadas AS mensagens,
            tmc_minutos AS tmc_medio_minutos,
            tmr_minutos AS tmr_medio_minutos
        FROM StatsAgente
        ORDER BY total_tickets DESC;
        `;
        const result = await pool.query(q, [dataInicioSQL, dataFimSQL, idsSel]);

        // Lista de tickets por agente (para o "Ver Tickets" abrir as conversas, igual aos demais paineis)
        const qDetalhes = `
            SELECT DISTINCT
                COALESCE(u.name, 'SEM ATRIBUIR') AS agente,
                c.display_id,
                c.id AS conv_id,
                ct.name AS cliente
            FROM conversations c
            LEFT JOIN users u ON u.id = c.assignee_id
            LEFT JOIN contacts ct ON ct.id = c.contact_id
            WHERE c.account_id = 1
              AND c.id = ANY($3::bigint[])
              AND c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
            ORDER BY c.display_id DESC;
        `;
        const detResult = await pool.query(qDetalhes, [dataInicioSQL, dataFimSQL, idsSel]);
        const detalhesPorAgente = {};
        detResult.rows.forEach(r => {
            if (!detalhesPorAgente[r.agente]) detalhesPorAgente[r.agente] = [];
            detalhesPorAgente[r.agente].push({ id: r.display_id || r.conv_id, cliente: r.cliente || 'Cliente sem nome' });
        });

        // Em aberto agora (status Aberta no Chatwoot) dos tickets recebidos no período — por agente
        const qAbertos = `
            SELECT COALESCE(u.name, 'SEM ATRIBUIR') AS agente, COUNT(DISTINCT c.id) AS em_aberto
            FROM conversations c
            LEFT JOIN users u ON u.id = c.assignee_id
            WHERE c.account_id = 1
              AND c.status = 0
              AND c.id = ANY($3::bigint[])
              AND c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
            GROUP BY 1;
        `;
        const abResult = await pool.query(qAbertos, [dataInicioSQL, dataFimSQL, idsSel]);
        const abertosPorAgente = {};
        abResult.rows.forEach(r => { abertosPorAgente[r.agente] = parseInt(r.em_aberto) || 0; });
        // Detalhe de cada ticket p/ o "Ver Tickets": situação no Chatwoot, retorno do cliente (depois da 1ª resposta do agente), mensagens do agente e etiquetas
        const qInfo = `
            SELECT x.*, COALESCE(x.ultima_msg_cliente > x.primeira_resp_agente, FALSE) AS teve_retorno
            FROM (
                SELECT
                    c.display_id,
                    c.id AS conv_id,
                    c.status,
                    c.created_at,
                    (SELECT MIN(mr.created_at) FROM messages mr WHERE mr.conversation_id = c.id AND mr.message_type = 1 AND mr.private = FALSE AND mr.sender_type = 'User') AS primeira_resp_agente,
                    (SELECT MAX(mc.created_at) FROM messages mc WHERE mc.conversation_id = c.id AND mc.message_type = 0 AND mc.private = FALSE) AS ultima_msg_cliente,
                    (SELECT COUNT(*) FROM messages ma WHERE ma.conversation_id = c.id AND ma.message_type = 1 AND ma.private = FALSE AND ma.sender_type = 'User' AND (ma.content_attributes->>'deleted')::boolean IS NOT TRUE) AS msgs_agente,
                    (SELECT string_agg(DISTINCT tg2.name, ', ' ORDER BY tg2.name) FROM taggings t2 JOIN tags tg2 ON tg2.id = t2.tag_id
                      WHERE t2.taggable_id = c.id AND t2.taggable_type = 'Conversation' AND (tg2.name ILIKE '%time-48h%' OR tg2.name ILIKE 'painel-do-pedido%')) AS etiquetas
                FROM conversations c
                WHERE c.account_id = 1
                  AND c.id = ANY($3::bigint[])
                  AND c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                  AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
            ) x;
        `;
        const infoResult = await pool.query(qInfo, [dataInicioSQL, dataFimSQL, idsSel]);
        const infoPorId = {};
        infoResult.rows.forEach(r => {
            infoPorId[String(r.display_id || r.conv_id)] = {
                status: r.status, teve_retorno: r.teve_retorno === true, ultimo_retorno: r.teve_retorno ? r.ultima_msg_cliente : null,
                msgs_agente: parseInt(r.msgs_agente) || 0, etiquetas: r.etiquetas || '', criado_em: r.created_at
            };
        });
        Object.values(detalhesPorAgente).forEach(lista => lista.forEach(tk => Object.assign(tk, infoPorId[String(tk.id)] || {})));
        // SLA do Time 48H por ticket: há quanto tempo está em aberto, quanto o cliente levou pra retornar e há quanto tempo o agente espera o cliente
        const qSla = `
            SELECT
                y.display_id,
                y.conv_id,
                CASE WHEN y.status = 0 THEN (EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - y.created_at)) / 60)::float8 END AS aberto_ha_min,
                CASE WHEN y.primeiro_retorno_em IS NOT NULL AND y.resp_antes_retorno IS NOT NULL
                     THEN (EXTRACT(EPOCH FROM (y.primeiro_retorno_em - y.resp_antes_retorno)) / 60)::float8 END AS retorno_cliente_min,
                CASE WHEN y.status = 0 AND y.ultima_resp_agente IS NOT NULL AND (y.ultima_msg_cliente IS NULL OR y.ultima_resp_agente > y.ultima_msg_cliente)
                     THEN (EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - y.ultima_resp_agente)) / 60)::float8 END AS aguardando_cliente_min,
                CASE WHEN y.status = 0 AND y.ultima_msg_cliente IS NOT NULL AND (y.ultima_resp_agente IS NULL OR y.ultima_msg_cliente > y.ultima_resp_agente)
                     THEN (EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - y.ultima_msg_cliente)) / 60)::float8 END AS cliente_esperando_min
            FROM (
                SELECT z.*,
                    (SELECT MAX(mr.created_at) FROM messages mr WHERE mr.conversation_id = z.conv_id AND mr.message_type = 1 AND mr.private = FALSE
                       AND mr.sender_type = 'User' AND mr.created_at < z.primeiro_retorno_em) AS resp_antes_retorno
                FROM (
                  SELECT w.*,
                    (SELECT MIN(mc.created_at) FROM messages mc WHERE mc.conversation_id = w.conv_id AND mc.message_type = 0 AND mc.private = FALSE
                       AND mc.created_at > w.primeira_resp_sla) AS primeiro_retorno_em
                  FROM (
                    SELECT
                        c.display_id,
                        c.id AS conv_id,
                        c.status,
                        c.created_at,
                        (SELECT MIN(mr.created_at) FROM messages mr WHERE mr.conversation_id = c.id AND mr.message_type = 1 AND mr.private = FALSE AND mr.sender_type = 'User') AS primeira_resp_sla,
                        (SELECT MAX(mr.created_at) FROM messages mr WHERE mr.conversation_id = c.id AND mr.message_type = 1 AND mr.private = FALSE AND mr.sender_type = 'User') AS ultima_resp_agente,
                        (SELECT MAX(mc.created_at) FROM messages mc WHERE mc.conversation_id = c.id AND mc.message_type = 0 AND mc.private = FALSE) AS ultima_msg_cliente
                    FROM conversations c
                    WHERE c.account_id = 1
                      AND c.id = ANY($3::bigint[])
                      AND c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                      AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                  ) w
                ) z
            ) y;
        `;
        const slaResult = await pool.query(qSla, [dataInicioSQL, dataFimSQL, idsSel]);
        const slaPorId = {};
        slaResult.rows.forEach(r => {
            slaPorId[String(r.display_id || r.conv_id)] = { aberto_ha_min: r.aberto_ha_min, retorno_cliente_min: r.retorno_cliente_min, aguardando_cliente_min: r.aguardando_cliente_min, cliente_esperando_min: r.cliente_esperando_min };
        });
        Object.values(detalhesPorAgente).forEach(lista => lista.forEach(tk => Object.assign(tk, slaPorId[String(tk.id)] || {})));
        const dados = result.rows.map(r => ({ ...r, detalhes: detalhesPorAgente[r.agente] || [] }));
        dados.forEach(d => { d.em_aberto = abertosPorAgente[d.agente] || 0; });
        // SLA por agente: média do tempo de retorno do cliente, média do tempo em aberto e quantos abertos passaram de 48h
        dados.forEach(d => {
            const dets = d.detalhes || [];
            const ab = dets.filter(t => t.aberto_ha_min != null), rt = dets.filter(t => t.retorno_cliente_min != null);
            d.sla_retorno_medio_min = rt.length ? rt.reduce((s, t) => s + t.retorno_cliente_min, 0) / rt.length : null;
            d.sla_aberto_medio_min = ab.length ? ab.reduce((s, t) => s + t.aberto_ha_min, 0) / ab.length : null;
            d.sla_aberto_fora = dets.filter(t => t.cliente_esperando_min != null && t.cliente_esperando_min > 48 * 60).length;   // fora do SLA = cliente mandou a última mensagem e está há +48h sem resposta do agente
        });
        res.json({ success: true, dados: dados, etiquetas: etiquetas });
    } catch (error) { 
        console.error("Erro Time 48h (etiquetas):", error);
        res.status(500).json({ success: false, error: error.message }); 
    }
});

// ==========================================
// 15.2 TIME 48H — TODOS OS AGENTES (sub-aba "👥 Todos os Agentes"): quem ENVIOU mensagem nos tickets com etiqueta 48H/Painel, de qualquer time
// ==========================================
app.get('/api/time48-agentes', async (req, res) => {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());

    if (!adms.includes(emailUser)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });

    try {
        let dataInicioSQL, dataFimSQL;
        if (req.query.since && req.query.until) {
            dataInicioSQL = unixParaYYYYMMDD(req.query.since);
            dataFimSQL = unixParaYYYYMMDD(req.query.until);
        } else {
            const agora = new Date(new Date().toLocaleString("en-US", {timeZone: "America/Sao_Paulo"}));
            const dInicio = new Date(agora.getFullYear(), agora.getMonth(), 1);
            dataInicioSQL = formatarDataSQL(dInicio);
            dataFimSQL = formatarDataSQL(agora);
        }

        // Mesmas etiquetas da Visão Geral (time-48h* e painel-do-pedido*). O PERÍODO aqui é a data em que o agente ENVIOU a mensagem (o ticket pode ser de qualquer data)
        const idsSel = (await pool.query(`SELECT DISTINCT t.taggable_id AS id FROM taggings t JOIN tags tg ON tg.id = t.tag_id WHERE t.taggable_type = 'Conversation' AND (tg.name ILIKE '%time-48h%' OR tg.name ILIKE 'painel-do-pedido%')`)).rows.map(r => r.id);

        // 1 linha por agente × ticket: só entra quem mandou mensagem pública (não apagada) no ticket — de qualquer time, sem filtro por " - RET", " - SMS" etc.
        const q = `
        WITH AgenteTicket AS (
            -- mensagens que cada agente ENVIOU no período, nos tickets com etiqueta 48H/Painel (de qualquer data)
            SELECT m.conversation_id AS conv_id, m.sender_id AS user_id, COUNT(*) AS msgs, MIN(m.created_at) AS primeira_msg
            FROM messages m
            WHERE m.conversation_id = ANY($3::bigint[])
              AND m.message_type = 1 AND m.private = FALSE AND m.sender_type = 'User' AND m.sender_id IS NOT NULL   -- só agente identificado
              AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE
              AND m.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND m.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
            GROUP BY m.conversation_id, m.sender_id
        ),
        Casos AS (
            SELECT c.id AS conv_id, c.display_id, c.created_at, c.status, ct.name AS cliente
            FROM conversations c
            LEFT JOIN contacts ct ON ct.id = c.contact_id
            WHERE c.account_id = 1
              AND c.id IN (SELECT DISTINCT conv_id FROM AgenteTicket)
        ),
        PrimeiroContato AS (
            -- 1º contato do ticket = 1ª mensagem pública de agente (mesma regra do TMC da Visão Geral); o TMC fica com quem mandou essa mensagem
            SELECT DISTINCT ON (m.conversation_id) m.conversation_id AS conv_id, m.sender_id AS user_id, m.created_at
            FROM messages m
            JOIN Casos k ON k.conv_id = m.conversation_id
            WHERE m.message_type = 1 AND m.private = FALSE AND m.sender_type = 'User'
            ORDER BY m.conversation_id, m.created_at, m.id
        )
        SELECT
            agt.conv_id, agt.user_id, agt.msgs, agt.primeira_msg,
            k.display_id, k.created_at, k.status, k.cliente,
            COALESCE(u.name, 'Agente #' || agt.user_id) AS agente,
            GREATEST((SELECT COUNT(*) FROM messages mp WHERE mp.conversation_id = agt.conv_id AND mp.private = FALSE), 1) AS peso,
            (SELECT MAX(mt.created_at) FROM messages mt WHERE mt.conversation_id = agt.conv_id AND mt.private = FALSE AND mt.message_type = 0 AND mt.created_at > agt.primeira_msg) AS ultimo_retorno,
            CASE WHEN pc.user_id = agt.user_id
                  AND pc.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                  AND pc.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                 THEN EXTRACT(EPOCH FROM (pc.created_at - k.created_at)::interval) END AS tmc_seg,   -- TMC: 1º contato do ticket feito por este agente DENTRO do período
            (SELECT AVG(EXTRACT(EPOCH FROM (resp.created_at - msg.created_at)::interval))
                FROM messages msg
                JOIN messages resp ON resp.conversation_id = msg.conversation_id
                                  AND resp.message_type = 1
                                  AND resp.private = FALSE
                                  AND resp.sender_type = 'User'
                                  AND resp.sender_id = agt.user_id   -- TMR: só as respostas DESTE agente
                                  AND resp.created_at > msg.created_at
                                  AND resp.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                                  AND resp.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'   -- ... enviadas no período
                WHERE msg.conversation_id = agt.conv_id
                  AND msg.message_type = 0
                  AND msg.private = FALSE
                  AND NOT EXISTS (
                      SELECT 1 FROM messages m_mid
                      WHERE m_mid.conversation_id = msg.conversation_id
                        AND m_mid.created_at > msg.created_at
                        AND m_mid.created_at < resp.created_at
                        AND NOT (m_mid.message_type IN (1, 3) AND m_mid.private = FALSE AND m_mid.sender_type IS DISTINCT FROM 'User')   -- bot/automação no meio não conta
                  )
            ) AS tmr_seg
        FROM AgenteTicket agt
        JOIN Casos k ON k.conv_id = agt.conv_id
        LEFT JOIN PrimeiroContato pc ON pc.conv_id = agt.conv_id
        LEFT JOIN users u ON u.id = agt.user_id
        ORDER BY k.display_id DESC;
        `;
        const linhas = (await pool.query(q, [dataInicioSQL, dataFimSQL, idsSel])).rows;

        // Por ticket (mesmas regras do "Ver Tickets" das outras abas): etiquetas do time e SLA (aberto há, retorno do cliente, aguardando, cliente sem resposta)
        const qTicket = `
            SELECT
                y.conv_id,
                y.etiquetas,
                CASE WHEN y.status = 0 THEN (EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - y.created_at)) / 60)::float8 END AS aberto_ha_min,
                CASE WHEN y.primeiro_retorno_em IS NOT NULL AND y.resp_antes_retorno IS NOT NULL
                     THEN (EXTRACT(EPOCH FROM (y.primeiro_retorno_em - y.resp_antes_retorno)) / 60)::float8 END AS retorno_cliente_min,
                CASE WHEN y.status = 0 AND y.ultima_resp_agente IS NOT NULL AND (y.ultima_msg_cliente IS NULL OR y.ultima_resp_agente > y.ultima_msg_cliente)
                     THEN (EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - y.ultima_resp_agente)) / 60)::float8 END AS aguardando_cliente_min,
                CASE WHEN y.status = 0 AND y.ultima_msg_cliente IS NOT NULL AND (y.ultima_resp_agente IS NULL OR y.ultima_msg_cliente > y.ultima_resp_agente)
                     THEN (EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - y.ultima_msg_cliente)) / 60)::float8 END AS cliente_esperando_min
            FROM (
                SELECT z.*,
                    (SELECT MAX(mr.created_at) FROM messages mr WHERE mr.conversation_id = z.conv_id AND mr.message_type = 1 AND mr.private = FALSE
                       AND mr.sender_type = 'User' AND mr.created_at < z.primeiro_retorno_em) AS resp_antes_retorno
                FROM (
                  SELECT w.*,
                    (SELECT MIN(mc.created_at) FROM messages mc WHERE mc.conversation_id = w.conv_id AND mc.message_type = 0 AND mc.private = FALSE
                       AND mc.created_at > w.primeira_resp_sla) AS primeiro_retorno_em
                  FROM (
                    SELECT
                        c.id AS conv_id,
                        c.status,
                        c.created_at,
                        (SELECT string_agg(DISTINCT tg2.name, ', ' ORDER BY tg2.name) FROM taggings t2 JOIN tags tg2 ON tg2.id = t2.tag_id
                          WHERE t2.taggable_id = c.id AND t2.taggable_type = 'Conversation' AND (tg2.name ILIKE '%time-48h%' OR tg2.name ILIKE 'painel-do-pedido%')) AS etiquetas,
                        (SELECT MIN(mr.created_at) FROM messages mr WHERE mr.conversation_id = c.id AND mr.message_type = 1 AND mr.private = FALSE AND mr.sender_type = 'User') AS primeira_resp_sla,
                        (SELECT MAX(mr.created_at) FROM messages mr WHERE mr.conversation_id = c.id AND mr.message_type = 1 AND mr.private = FALSE AND mr.sender_type = 'User') AS ultima_resp_agente,
                        (SELECT MAX(mc.created_at) FROM messages mc WHERE mc.conversation_id = c.id AND mc.message_type = 0 AND mc.private = FALSE) AS ultima_msg_cliente
                    FROM conversations c
                    WHERE c.account_id = 1
                      AND c.id = ANY($1::bigint[])
                  ) w
                ) z
            ) y;
        `;
        const porTicket = {};
        const idsAtendidos = [...new Set(linhas.map(r => r.conv_id))];
        if (idsAtendidos.length) (await pool.query(qTicket, [idsAtendidos])).rows.forEach(r => { porTicket[String(r.conv_id)] = r; });

        // Junta por agente: mesmos números da Visão Geral, mas contando para quem ENVIOU a mensagem
        const porAgente = {};
        const ticketsDistintos = new Set(), abertosDistintos = new Set();
        let totalMsgs = 0;
        linhas.forEach(r => {
            const nome = r.agente;
            if (!porAgente[nome]) porAgente[nome] = { agente: nome, tickets: 0, em_aberto: 0, retornos: 0, mensagens: 0, _tmcP: 0, _tmcS: 0, _tmrP: 0, _tmrS: 0, detalhes: [] };
            const a = porAgente[nome];
            const msgs = parseInt(r.msgs) || 0, peso = parseInt(r.peso) || 1;
            const status = parseInt(r.status);
            a.tickets += 1;
            if (status === 0) a.em_aberto += 1;
            if (r.ultimo_retorno) a.retornos += 1;
            a.mensagens += msgs;
            if (r.tmc_seg !== null && r.tmc_seg !== undefined) { a._tmcS += Number(r.tmc_seg) * peso; a._tmcP += peso; }
            if (r.tmr_seg !== null && r.tmr_seg !== undefined) { a._tmrS += Number(r.tmr_seg) * peso; a._tmrP += peso; }
            ticketsDistintos.add(String(r.conv_id));
            if (status === 0) abertosDistintos.add(String(r.conv_id));
            totalMsgs += msgs;
            const tk = porTicket[String(r.conv_id)] || {};
            a.detalhes.push({
                id: r.display_id || r.conv_id,
                cliente: r.cliente || 'Cliente sem nome',
                status: status,
                teve_retorno: !!r.ultimo_retorno,                 // cliente voltou a escrever depois da 1ª mensagem DESTE agente no período
                ultimo_retorno: r.ultimo_retorno || null,
                msgs_agente: msgs,                                // mensagens DESTE agente no ticket, enviadas no período
                etiquetas: tk.etiquetas || '',
                criado_em: r.created_at,
                aberto_ha_min: tk.aberto_ha_min ?? null,
                retorno_cliente_min: tk.retorno_cliente_min ?? null,
                aguardando_cliente_min: tk.aguardando_cliente_min ?? null,
                cliente_esperando_min: tk.cliente_esperando_min ?? null
            });
        });
        const dados = Object.values(porAgente).map(a => {
            const dets = a.detalhes;
            const ab = dets.filter(t => t.aberto_ha_min != null), rt = dets.filter(t => t.retorno_cliente_min != null);
            return {
                agente: a.agente,
                tickets: a.tickets,
                em_aberto: a.em_aberto,
                retornos: a.retornos,
                mensagens: a.mensagens,
                tmc_medio_minutos: a._tmcP ? a._tmcS / a._tmcP / 60 : 0,
                tmr_medio_minutos: a._tmrP ? a._tmrS / a._tmrP / 60 : 0,
                sla_retorno_medio_min: rt.length ? rt.reduce((s, t) => s + t.retorno_cliente_min, 0) / rt.length : null,
                sla_aberto_medio_min: ab.length ? ab.reduce((s, t) => s + t.aberto_ha_min, 0) / ab.length : null,
                sla_aberto_fora: dets.filter(t => t.cliente_esperando_min != null && t.cliente_esperando_min > 48 * 60).length,
                detalhes: dets
            };
        }).sort((x, y) => (y.tickets - x.tickets) || (y.mensagens - x.mensagens) || x.agente.localeCompare(y.agente));

        res.json({
            success: true,
            dados: dados,
            resumo: { agentes: dados.length, tickets: ticketsDistintos.size, em_aberto: abertosDistintos.size, mensagens: totalMsgs },
            periodo: { inicio: dataInicioSQL, fim: dataFimSQL }
        });
    } catch (error) {
        console.error("Erro Time 48h (todos os agentes):", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==========================================
// 15.3 TIME 48H — ⏳ VISÃO GERAL, 🏷️ ETIQUETA 48H E 📦 ETIQUETA PAINEL COM A MESMA REGRA DO 👥 TODOS OS AGENTES (06/10/2026)
// Período = data em que o agente ENVIOU a mensagem · o ticket conta para quem respondeu · TMC/TMR só de mensagem de agente
// ?so_time=1 = só os agentes do Time 48H (Visão Geral) · ?etiquetas=a,b,c = só as etiquetas marcadas (abas de etiqueta, todos os agentes)
// ==========================================
app.get('/api/time48-atendimento', async (req, res) => {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());

    if (!adms.includes(emailUser)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });

    try {
        let dataInicioSQL, dataFimSQL;
        if (req.query.since && req.query.until) {
            dataInicioSQL = unixParaYYYYMMDD(req.query.since);
            dataFimSQL = unixParaYYYYMMDD(req.query.until);
        } else {
            const agora = new Date(new Date().toLocaleString("en-US", {timeZone: "America/Sao_Paulo"}));
            const dInicio = new Date(agora.getFullYear(), agora.getMonth(), 1);
            dataInicioSQL = formatarDataSQL(dInicio);
            dataFimSQL = formatarDataSQL(agora);
        }

        // Etiquetas marcadas na aba (?etiquetas=a,b,c), igual às abas de etiqueta; sem o parâmetro = as duas (time-48h* e painel-do-pedido*), igual ao 👥 Todos os Agentes
        const temEtiquetas = req.query.etiquetas !== undefined;
        const etiquetas = [...new Set(String(req.query.etiquetas || '').split(',')
            .map(e => e.trim().toLowerCase())
            .filter(e => /^(time-48h|painel-do-pedido)[a-z0-9-]*$/.test(e)))].slice(0, 30);
        if (temEtiquetas && etiquetas.length === 0) return res.json({ success: true, dados: [], etiquetas: [] });
        const soTime = req.query.so_time === '1';   // ⏳ Visão Geral: só os agentes do Time 48H (" - 48H" no nome)
        // O PERÍODO aqui é a data em que o agente ENVIOU a mensagem (o ticket pode ser de qualquer data)
        const idsSel = temEtiquetas
            ? (await pool.query(`SELECT DISTINCT t.taggable_id AS id FROM taggings t JOIN tags tg ON tg.id = t.tag_id WHERE t.taggable_type = 'Conversation' AND lower(tg.name) = ANY($1::text[])`, [etiquetas])).rows.map(r => r.id)
            : (await pool.query(`SELECT DISTINCT t.taggable_id AS id FROM taggings t JOIN tags tg ON tg.id = t.tag_id WHERE t.taggable_type = 'Conversation' AND (tg.name ILIKE '%time-48h%' OR tg.name ILIKE 'painel-do-pedido%')`)).rows.map(r => r.id);

        // 1 linha por agente × ticket: só entra quem mandou mensagem pública (não apagada) no ticket — de qualquer time, sem filtro por " - RET", " - SMS" etc.
        const q = `
        WITH AgenteTicket AS (
            -- mensagens que cada agente ENVIOU no período, nos tickets com etiqueta 48H/Painel (de qualquer data)
            SELECT m.conversation_id AS conv_id, m.sender_id AS user_id, COUNT(*) AS msgs, MIN(m.created_at) AS primeira_msg
            FROM messages m
            WHERE m.conversation_id = ANY($3::bigint[])
              AND m.message_type = 1 AND m.private = FALSE AND m.sender_type = 'User' AND m.sender_id IS NOT NULL   -- só agente identificado
              AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE
              AND m.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND m.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
            GROUP BY m.conversation_id, m.sender_id
        ),
        Casos AS (
            SELECT c.id AS conv_id, c.display_id, c.created_at, c.status, ct.name AS cliente
            FROM conversations c
            LEFT JOIN contacts ct ON ct.id = c.contact_id
            WHERE c.account_id = 1
              AND c.id IN (SELECT DISTINCT conv_id FROM AgenteTicket)
        ),
        PrimeiroContato AS (
            -- 1º contato do ticket = 1ª mensagem pública de agente (mesma regra do TMC da Visão Geral); o TMC fica com quem mandou essa mensagem
            SELECT DISTINCT ON (m.conversation_id) m.conversation_id AS conv_id, m.sender_id AS user_id, m.created_at
            FROM messages m
            JOIN Casos k ON k.conv_id = m.conversation_id
            WHERE m.message_type = 1 AND m.private = FALSE AND m.sender_type = 'User'
            ORDER BY m.conversation_id, m.created_at, m.id
        )
        SELECT
            agt.conv_id, agt.user_id, agt.msgs, agt.primeira_msg,
            k.display_id, k.created_at, k.status, k.cliente,
            COALESCE(u.name, 'Agente #' || agt.user_id) AS agente,
            GREATEST((SELECT COUNT(*) FROM messages mp WHERE mp.conversation_id = agt.conv_id AND mp.private = FALSE), 1) AS peso,
            (SELECT MAX(mt.created_at) FROM messages mt WHERE mt.conversation_id = agt.conv_id AND mt.private = FALSE AND mt.message_type = 0 AND mt.created_at > agt.primeira_msg) AS ultimo_retorno,
            CASE WHEN pc.user_id = agt.user_id
                  AND pc.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                  AND pc.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                 THEN EXTRACT(EPOCH FROM (pc.created_at - k.created_at)::interval) END AS tmc_seg,   -- TMC: 1º contato do ticket feito por este agente DENTRO do período
            (SELECT AVG(EXTRACT(EPOCH FROM (resp.created_at - msg.created_at)::interval))
                FROM messages msg
                JOIN messages resp ON resp.conversation_id = msg.conversation_id
                                  AND resp.message_type = 1
                                  AND resp.private = FALSE
                                  AND resp.sender_type = 'User'
                                  AND resp.sender_id = agt.user_id   -- TMR: só as respostas DESTE agente
                                  AND resp.created_at > msg.created_at
                                  AND resp.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                                  AND resp.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'   -- ... enviadas no período
                WHERE msg.conversation_id = agt.conv_id
                  AND msg.message_type = 0
                  AND msg.private = FALSE
                  AND NOT EXISTS (
                      SELECT 1 FROM messages m_mid
                      WHERE m_mid.conversation_id = msg.conversation_id
                        AND m_mid.created_at > msg.created_at
                        AND m_mid.created_at < resp.created_at
                        AND NOT (m_mid.message_type IN (1, 3) AND m_mid.private = FALSE AND m_mid.sender_type IS DISTINCT FROM 'User')   -- bot/automação no meio não conta
                  )
            ) AS tmr_seg
        FROM AgenteTicket agt
        JOIN Casos k ON k.conv_id = agt.conv_id
        LEFT JOIN PrimeiroContato pc ON pc.conv_id = agt.conv_id
        LEFT JOIN users u ON u.id = agt.user_id
        ORDER BY k.display_id DESC;
        `;
        const linhas = (await pool.query(q, [dataInicioSQL, dataFimSQL, idsSel])).rows.filter(r => !soTime || /[\s\-]48H\b/i.test(String(r.agente || '')));

        // Por ticket (mesmas regras do "Ver Tickets" das outras abas): etiquetas do time e SLA (aberto há, retorno do cliente, aguardando, cliente sem resposta)
        const qTicket = `
            SELECT
                y.conv_id,
                y.etiquetas,
                CASE WHEN y.status = 0 THEN (EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - y.created_at)) / 60)::float8 END AS aberto_ha_min,
                CASE WHEN y.primeiro_retorno_em IS NOT NULL AND y.resp_antes_retorno IS NOT NULL
                     THEN (EXTRACT(EPOCH FROM (y.primeiro_retorno_em - y.resp_antes_retorno)) / 60)::float8 END AS retorno_cliente_min,
                CASE WHEN y.status = 0 AND y.ultima_resp_agente IS NOT NULL AND (y.ultima_msg_cliente IS NULL OR y.ultima_resp_agente > y.ultima_msg_cliente)
                     THEN (EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - y.ultima_resp_agente)) / 60)::float8 END AS aguardando_cliente_min,
                CASE WHEN y.status = 0 AND y.ultima_msg_cliente IS NOT NULL AND (y.ultima_resp_agente IS NULL OR y.ultima_msg_cliente > y.ultima_resp_agente)
                     THEN (EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - y.ultima_msg_cliente)) / 60)::float8 END AS cliente_esperando_min
            FROM (
                SELECT z.*,
                    (SELECT MAX(mr.created_at) FROM messages mr WHERE mr.conversation_id = z.conv_id AND mr.message_type = 1 AND mr.private = FALSE
                       AND mr.sender_type = 'User' AND mr.created_at < z.primeiro_retorno_em) AS resp_antes_retorno
                FROM (
                  SELECT w.*,
                    (SELECT MIN(mc.created_at) FROM messages mc WHERE mc.conversation_id = w.conv_id AND mc.message_type = 0 AND mc.private = FALSE
                       AND mc.created_at > w.primeira_resp_sla) AS primeiro_retorno_em
                  FROM (
                    SELECT
                        c.id AS conv_id,
                        c.status,
                        c.created_at,
                        (SELECT string_agg(DISTINCT tg2.name, ', ' ORDER BY tg2.name) FROM taggings t2 JOIN tags tg2 ON tg2.id = t2.tag_id
                          WHERE t2.taggable_id = c.id AND t2.taggable_type = 'Conversation' AND (tg2.name ILIKE '%time-48h%' OR tg2.name ILIKE 'painel-do-pedido%')) AS etiquetas,
                        (SELECT MIN(mr.created_at) FROM messages mr WHERE mr.conversation_id = c.id AND mr.message_type = 1 AND mr.private = FALSE AND mr.sender_type = 'User') AS primeira_resp_sla,
                        (SELECT MAX(mr.created_at) FROM messages mr WHERE mr.conversation_id = c.id AND mr.message_type = 1 AND mr.private = FALSE AND mr.sender_type = 'User') AS ultima_resp_agente,
                        (SELECT MAX(mc.created_at) FROM messages mc WHERE mc.conversation_id = c.id AND mc.message_type = 0 AND mc.private = FALSE) AS ultima_msg_cliente
                    FROM conversations c
                    WHERE c.account_id = 1
                      AND c.id = ANY($1::bigint[])
                  ) w
                ) z
            ) y;
        `;
        const porTicket = {};
        const idsAtendidos = [...new Set(linhas.map(r => r.conv_id))];
        if (idsAtendidos.length) (await pool.query(qTicket, [idsAtendidos])).rows.forEach(r => { porTicket[String(r.conv_id)] = r; });

        // Junta por agente: mesmos números da Visão Geral, mas contando para quem ENVIOU a mensagem
        const porAgente = {};
        const ticketsDistintos = new Set(), abertosDistintos = new Set(), retornosDistintos = new Set();
        let totalMsgs = 0;
        linhas.forEach(r => {
            const nome = r.agente;
            if (!porAgente[nome]) porAgente[nome] = { agente: nome, tickets: 0, em_aberto: 0, retornos: 0, mensagens: 0, _tmcP: 0, _tmcS: 0, _tmrP: 0, _tmrS: 0, detalhes: [] };
            const a = porAgente[nome];
            const msgs = parseInt(r.msgs) || 0, peso = parseInt(r.peso) || 1;
            const status = parseInt(r.status);
            a.tickets += 1;
            if (status === 0) a.em_aberto += 1;
            if (r.ultimo_retorno) a.retornos += 1;
            a.mensagens += msgs;
            if (r.tmc_seg !== null && r.tmc_seg !== undefined) { a._tmcS += Number(r.tmc_seg) * peso; a._tmcP += peso; }
            if (r.tmr_seg !== null && r.tmr_seg !== undefined) { a._tmrS += Number(r.tmr_seg) * peso; a._tmrP += peso; }
            ticketsDistintos.add(String(r.conv_id));
            if (status === 0) abertosDistintos.add(String(r.conv_id));
            if (r.ultimo_retorno) retornosDistintos.add(String(r.conv_id));
            totalMsgs += msgs;
            const tk = porTicket[String(r.conv_id)] || {};
            a.detalhes.push({
                id: r.display_id || r.conv_id,
                cliente: r.cliente || 'Cliente sem nome',
                status: status,
                teve_retorno: !!r.ultimo_retorno,                 // cliente voltou a escrever depois da 1ª mensagem DESTE agente no período
                ultimo_retorno: r.ultimo_retorno || null,
                msgs_agente: msgs,                                // mensagens DESTE agente no ticket, enviadas no período
                etiquetas: tk.etiquetas || '',
                criado_em: r.created_at,
                aberto_ha_min: tk.aberto_ha_min ?? null,
                retorno_cliente_min: tk.retorno_cliente_min ?? null,
                aguardando_cliente_min: tk.aguardando_cliente_min ?? null,
                cliente_esperando_min: tk.cliente_esperando_min ?? null
            });
        });
        const dados = Object.values(porAgente).map(a => {
            const dets = a.detalhes;
            const ab = dets.filter(t => t.aberto_ha_min != null), rt = dets.filter(t => t.retorno_cliente_min != null);
            return {
                agente: a.agente,
                tickets: a.tickets,
                em_aberto: a.em_aberto,
                retornos: a.retornos,
                mensagens: a.mensagens,
                tmc_medio_minutos: a._tmcP ? a._tmcS / a._tmcP / 60 : 0,
                tmr_medio_minutos: a._tmrP ? a._tmrS / a._tmrP / 60 : 0,
                sla_retorno_medio_min: rt.length ? rt.reduce((s, t) => s + t.retorno_cliente_min, 0) / rt.length : null,
                sla_aberto_medio_min: ab.length ? ab.reduce((s, t) => s + t.aberto_ha_min, 0) / ab.length : null,
                sla_aberto_fora: dets.filter(t => t.cliente_esperando_min != null && t.cliente_esperando_min > 48 * 60).length,
                detalhes: dets
            };
        }).sort((x, y) => (y.tickets - x.tickets) || (y.mensagens - x.mensagens) || x.agente.localeCompare(y.agente));

        res.json({
            success: true,
            dados: dados,
            resumo: { agentes: dados.length, tickets: ticketsDistintos.size, em_aberto: abertosDistintos.size, retornos: retornosDistintos.size, mensagens: totalMsgs },
            periodo: { inicio: dataInicioSQL, fim: dataFimSQL },
            etiquetas: etiquetas
        });
    } catch (error) {
        console.error("Erro Time 48h (atendimento):", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==========================================
// 15.4 TICKETS OPERAÇÃO — 🧑‍💻 ATENDIMENTO POR AGENTE (06/10/2026)
// Mesma regra e colunas do 👥 Todos os Agentes do Time 48H, mas com TODOS os tickets (não só os de etiqueta 48H/Painel)
// Período = data em que o agente ENVIOU a mensagem · o ticket conta para quem respondeu · o time vem da sigla no nome do agente
// ?agente_id=N = os tickets de 1 agente ("Ver Tickets") · ?detalhes=1 = os tickets de todos (Excel; ?time=RET limita ao time)
// ==========================================
function atdTimeDoAgente(nome) {
    const m = String(nome || '').toUpperCase().match(/[\s\-]+(RET|SAC|BKO|SMS|48H|LD)\b/);
    return m ? m[1] : 'OUTROS';
}
app.get('/api/atendimento-agentes', async (req, res) => {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());

    if (!adms.includes(emailUser)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });

    try {
        let dataInicioSQL, dataFimSQL;
        if (req.query.since && req.query.until) {
            dataInicioSQL = unixParaYYYYMMDD(req.query.since);
            dataFimSQL = unixParaYYYYMMDD(req.query.until);
        } else {
            const agora = new Date(new Date().toLocaleString("en-US", {timeZone: "America/Sao_Paulo"}));
            const dInicio = new Date(agora.getFullYear(), agora.getMonth(), 1);
            dataInicioSQL = formatarDataSQL(dInicio);
            dataFimSQL = formatarDataSQL(agora);
        }
        const agenteId = /^\d+$/.test(String(req.query.agente_id || '')) ? parseInt(req.query.agente_id, 10) : null;
        const comDetalhes = req.query.detalhes === '1' || agenteId !== null;
        const TIMES = ['RET', 'SAC', 'BKO', 'SMS', '48H'];
        const timeSel = TIMES.includes(String(req.query.time || '').toUpperCase()) ? String(req.query.time).toUpperCase() : null;

        // 1 linha por agente × ticket: só entra quem mandou mensagem pública (não apagada) no período — qualquer ticket, qualquer time
        const q = `
        WITH AgenteTicket AS (
            SELECT m.conversation_id AS conv_id, m.sender_id AS user_id, COUNT(*) AS msgs, MIN(m.created_at) AS primeira_msg
            FROM messages m
            WHERE m.account_id = 1
              AND ($3::bigint IS NULL OR m.sender_id = $3::bigint)   -- "Ver Tickets": só o agente escolhido
              AND m.message_type = 1 AND m.private = FALSE AND m.sender_type = 'User' AND m.sender_id IS NOT NULL   -- só agente identificado
              AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE
              AND m.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND m.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
            GROUP BY m.conversation_id, m.sender_id
        ),
        Casos AS (
            SELECT c.id AS conv_id, c.display_id, c.created_at, c.status, ct.name AS cliente
            FROM conversations c
            LEFT JOIN contacts ct ON ct.id = c.contact_id
            WHERE c.account_id = 1
              AND c.id IN (SELECT DISTINCT conv_id FROM AgenteTicket)
        ),
        PrimeiroContato AS (
            -- 1º contato do ticket = 1ª mensagem pública de agente (mesma regra do TMC do Time 48H); o TMC fica com quem mandou essa mensagem
            SELECT DISTINCT ON (m.conversation_id) m.conversation_id AS conv_id, m.sender_id AS user_id, m.created_at
            FROM messages m
            JOIN Casos k ON k.conv_id = m.conversation_id
            WHERE m.message_type = 1 AND m.private = FALSE AND m.sender_type = 'User'
            ORDER BY m.conversation_id, m.created_at, m.id
        )
        SELECT
            agt.conv_id, agt.user_id, agt.msgs, agt.primeira_msg,
            k.display_id, k.created_at, k.status, k.cliente,
            COALESCE(u.name, 'Agente #' || agt.user_id) AS agente,
            GREATEST((SELECT COUNT(*) FROM messages mp WHERE mp.conversation_id = agt.conv_id AND mp.private = FALSE), 1) AS peso,
            (SELECT MAX(mt.created_at) FROM messages mt WHERE mt.conversation_id = agt.conv_id AND mt.private = FALSE AND mt.message_type = 0 AND mt.created_at > agt.primeira_msg) AS ultimo_retorno,
            CASE WHEN pc.user_id = agt.user_id
                  AND pc.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                  AND pc.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                 THEN EXTRACT(EPOCH FROM (pc.created_at - k.created_at)::interval) END AS tmc_seg,   -- TMC: 1º contato do ticket feito por este agente DENTRO do período
            (SELECT AVG(EXTRACT(EPOCH FROM (resp.created_at - msg.created_at)::interval))
                FROM messages msg
                JOIN messages resp ON resp.conversation_id = msg.conversation_id
                                  AND resp.message_type = 1
                                  AND resp.private = FALSE
                                  AND resp.sender_type = 'User'
                                  AND resp.sender_id = agt.user_id   -- TMR: só as respostas DESTE agente
                                  AND resp.created_at > msg.created_at
                                  AND resp.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                                  AND resp.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'   -- ... enviadas no período
                WHERE msg.conversation_id = agt.conv_id
                  AND msg.message_type = 0
                  AND msg.private = FALSE
                  AND NOT EXISTS (
                      SELECT 1 FROM messages m_mid
                      WHERE m_mid.conversation_id = msg.conversation_id
                        AND m_mid.created_at > msg.created_at
                        AND m_mid.created_at < resp.created_at
                        AND NOT (m_mid.message_type IN (1, 3) AND m_mid.private = FALSE AND m_mid.sender_type IS DISTINCT FROM 'User')   -- bot/automação no meio não conta
                  )
            ) AS tmr_seg
        FROM AgenteTicket agt
        JOIN Casos k ON k.conv_id = agt.conv_id
        LEFT JOIN PrimeiroContato pc ON pc.conv_id = agt.conv_id
        LEFT JOIN users u ON u.id = agt.user_id
        ORDER BY k.display_id DESC;
        `;
        const todasLinhas = (await pool.query(q, [dataInicioSQL, dataFimSQL, agenteId])).rows;
        todasLinhas.forEach(r => { r.time = atdTimeDoAgente(r.agente); });
        const linhas = timeSel ? todasLinhas.filter(r => r.time === timeSel) : todasLinhas;

        // Por ticket (mesmas regras do "Ver Tickets" do Time 48H): etiquetas e SLA (aberto há, retorno do cliente, aguardando, cliente sem resposta)
        const qTicket = `
            SELECT
                y.conv_id,
                y.etiquetas,
                CASE WHEN y.status = 0 THEN (EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - y.created_at)) / 60)::float8 END AS aberto_ha_min,
                CASE WHEN y.primeiro_retorno_em IS NOT NULL AND y.resp_antes_retorno IS NOT NULL
                     THEN (EXTRACT(EPOCH FROM (y.primeiro_retorno_em - y.resp_antes_retorno)) / 60)::float8 END AS retorno_cliente_min,
                CASE WHEN y.status = 0 AND y.ultima_resp_agente IS NOT NULL AND (y.ultima_msg_cliente IS NULL OR y.ultima_resp_agente > y.ultima_msg_cliente)
                     THEN (EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - y.ultima_resp_agente)) / 60)::float8 END AS aguardando_cliente_min,
                CASE WHEN y.status = 0 AND y.ultima_msg_cliente IS NOT NULL AND (y.ultima_resp_agente IS NULL OR y.ultima_msg_cliente > y.ultima_resp_agente)
                     THEN (EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - y.ultima_msg_cliente)) / 60)::float8 END AS cliente_esperando_min
            FROM (
                SELECT z.*,
                    (SELECT MAX(mr.created_at) FROM messages mr WHERE mr.conversation_id = z.conv_id AND mr.message_type = 1 AND mr.private = FALSE
                       AND mr.sender_type = 'User' AND mr.created_at < z.primeiro_retorno_em) AS resp_antes_retorno
                FROM (
                  SELECT w.*,
                    (SELECT MIN(mc.created_at) FROM messages mc WHERE mc.conversation_id = w.conv_id AND mc.message_type = 0 AND mc.private = FALSE
                       AND mc.created_at > w.primeira_resp_sla) AS primeiro_retorno_em
                  FROM (
                    SELECT
                        c.id AS conv_id,
                        c.status,
                        c.created_at,
                        (SELECT string_agg(DISTINCT tg2.name, ', ' ORDER BY tg2.name) FROM taggings t2 JOIN tags tg2 ON tg2.id = t2.tag_id
                          WHERE t2.taggable_id = c.id AND t2.taggable_type = 'Conversation') AS etiquetas,
                        (SELECT MIN(mr.created_at) FROM messages mr WHERE mr.conversation_id = c.id AND mr.message_type = 1 AND mr.private = FALSE AND mr.sender_type = 'User') AS primeira_resp_sla,
                        (SELECT MAX(mr.created_at) FROM messages mr WHERE mr.conversation_id = c.id AND mr.message_type = 1 AND mr.private = FALSE AND mr.sender_type = 'User') AS ultima_resp_agente,
                        (SELECT MAX(mc.created_at) FROM messages mc WHERE mc.conversation_id = c.id AND mc.message_type = 0 AND mc.private = FALSE) AS ultima_msg_cliente
                    FROM conversations c
                    WHERE c.account_id = 1
                      AND c.id = ANY($1::bigint[])
                  ) w
                ) z
            ) y;
        `;
        const porTicket = {};
        const idsAtendidos = [...new Set(linhas.map(r => r.conv_id))];
        if (idsAtendidos.length) (await pool.query(qTicket, [idsAtendidos])).rows.forEach(r => { porTicket[String(r.conv_id)] = r; });

        // Junta por agente: mesmos números do 👥 Todos os Agentes, contando para quem ENVIOU a mensagem
        const porAgente = {};
        linhas.forEach(r => {
            const nome = r.agente;
            if (!porAgente[nome]) porAgente[nome] = { agente: nome, user_id: r.user_id, time: r.time, tickets: 0, em_aberto: 0, retornos: 0, mensagens: 0, _tmcP: 0, _tmcS: 0, _tmrP: 0, _tmrS: 0, detalhes: [] };
            const a = porAgente[nome];
            const msgs = parseInt(r.msgs) || 0, peso = parseInt(r.peso) || 1;
            const status = parseInt(r.status);
            a.tickets += 1;
            if (status === 0) a.em_aberto += 1;
            if (r.ultimo_retorno) a.retornos += 1;
            a.mensagens += msgs;
            if (r.tmc_seg !== null && r.tmc_seg !== undefined) { a._tmcS += Number(r.tmc_seg) * peso; a._tmcP += peso; }
            if (r.tmr_seg !== null && r.tmr_seg !== undefined) { a._tmrS += Number(r.tmr_seg) * peso; a._tmrP += peso; }
            const tk = porTicket[String(r.conv_id)] || {};
            a.detalhes.push({
                id: r.display_id || r.conv_id,
                cliente: r.cliente || 'Cliente sem nome',
                status: status,
                teve_retorno: !!r.ultimo_retorno,                 // cliente voltou a escrever depois da 1ª mensagem DESTE agente no período
                ultimo_retorno: r.ultimo_retorno || null,
                msgs_agente: msgs,                                // mensagens DESTE agente no ticket, enviadas no período
                etiquetas: tk.etiquetas || '',
                criado_em: r.created_at,
                aberto_ha_min: tk.aberto_ha_min ?? null,
                retorno_cliente_min: tk.retorno_cliente_min ?? null,
                aguardando_cliente_min: tk.aguardando_cliente_min ?? null,
                cliente_esperando_min: tk.cliente_esperando_min ?? null
            });
        });
        const dados = Object.values(porAgente).map(a => {
            const dets = a.detalhes;
            const ab = dets.filter(t => t.aberto_ha_min != null), rt = dets.filter(t => t.retorno_cliente_min != null);
            const linha = {
                agente: a.agente,
                user_id: a.user_id,
                time: a.time,
                tickets: a.tickets,
                em_aberto: a.em_aberto,
                retornos: a.retornos,
                mensagens: a.mensagens,
                tmc_medio_minutos: a._tmcP ? a._tmcS / a._tmcP / 60 : 0,
                tmr_medio_minutos: a._tmrP ? a._tmrS / a._tmrP / 60 : 0,
                sla_retorno_medio_min: rt.length ? rt.reduce((s, t) => s + t.retorno_cliente_min, 0) / rt.length : null,
                sla_aberto_medio_min: ab.length ? ab.reduce((s, t) => s + t.aberto_ha_min, 0) / ab.length : null,
                sla_aberto_fora: dets.filter(t => t.cliente_esperando_min != null && t.cliente_esperando_min > 48 * 60).length
            };
            if (comDetalhes) linha.detalhes = dets;   // a lista de tickets só vai quando pedida (Ver Tickets / Excel): o mês inteiro de todos os times é grande
            return linha;
        }).sort((x, y) => (y.tickets - x.tickets) || (y.mensagens - x.mensagens) || x.agente.localeCompare(y.agente));

        // Resumo por time sem repetir ticket (ticket atendido por 2 agentes do mesmo time conta 1 vez)
        const porTime = {};
        ['TODOS', ...TIMES].forEach(t => {
            const tks = new Set(), abs = new Set(), rets = new Set(), ags = new Set();
            let msgs = 0;
            linhas.forEach(r => {
                if (t !== 'TODOS' && r.time !== t) return;
                const id = String(r.conv_id);
                tks.add(id); ags.add(r.agente);
                if (parseInt(r.status) === 0) abs.add(id);
                if (r.ultimo_retorno) rets.add(id);
                msgs += parseInt(r.msgs) || 0;
            });
            porTime[t] = { agentes: ags.size, tickets: tks.size, em_aberto: abs.size, retornos: rets.size, mensagens: msgs };
        });

        res.json({ success: true, dados: dados, por_time: porTime, periodo: { inicio: dataInicioSQL, fim: dataFimSQL } });
    } catch (error) {
        console.error("Erro Atendimento por Agente:", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==========================================
// 15.5 TICKETS OPERAÇÃO — 📥 RECEBIMENTO DE TICKETS (06/10/2026)
// Conversas NOVAS criadas no período, separadas por time pela mesma regra do Status de Casos:
// etiqueta 48H/Painel → 48H · caixa [GEX] SMS Support → SMS · time do Chatwoot → RET/SAC/BKO/SMS · sem time → OUTROS
// (a caixa "Atendimento | Brasil" só entra com etiqueta 48H) · compara com o período anterior do mesmo tamanho · hoje = dia parcial
// ==========================================
app.get('/api/recebimento-tickets', async (req, res) => {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());

    if (!adms.includes(emailUser)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });

    try {
        let dataInicioSQL, dataFimSQL;
        if (req.query.since && req.query.until) {
            dataInicioSQL = unixParaYYYYMMDD(req.query.since);
            dataFimSQL = unixParaYYYYMMDD(req.query.until);
        } else {
            const agora = new Date(new Date().toLocaleString("en-US", {timeZone: "America/Sao_Paulo"}));
            const dInicio = new Date(agora.getFullYear(), agora.getMonth(), 1);
            dataInicioSQL = formatarDataSQL(dInicio);
            dataFimSQL = formatarDataSQL(agora);
        }
        const DIA_MS = 86400000;
        const ymd = d => d.toISOString().slice(0, 10);
        const dIni = new Date(dataInicioSQL + 'T00:00:00Z'), dFim = new Date(dataFimSQL + 'T00:00:00Z');
        const dias = Math.round((dFim - dIni) / DIA_MS) + 1;
        if (!(dias >= 1) || dias > 400) return res.status(400).json({ success: false, error: 'Período inválido (escolha de 1 a 400 dias).' });
        const antIni = new Date(dIni.getTime() - dias * DIA_MS), antFim = new Date(dIni.getTime() - DIA_MS);   // período anterior, do mesmo tamanho
        const hojeBR = formatarDataSQL(new Date(new Date().toLocaleString("en-US", {timeZone: "America/Sao_Paulo"})));

        const base = (selecao) => `
            WITH Conv48 AS (
                SELECT DISTINCT tg.taggable_id AS conv_id
                FROM taggings tg
                JOIN tags t2 ON t2.id = tg.tag_id
                WHERE tg.taggable_type = 'Conversation' AND (t2.name ILIKE '%time-48h%' OR t2.name ILIKE 'painel-do-pedido%')
            ),
            Recebidos AS (
                SELECT
                    c.status,
                    c.assignee_id,
                    (c.created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo') AS criado_br,
                    CASE
                        WHEN c.id IN (SELECT conv_id FROM Conv48) THEN '48H'
                        WHEN i.name = '[GEX] SMS Support' THEN 'SMS'
                        WHEN t.name ILIKE '%reten%' THEN 'RET'
                        WHEN t.name ILIKE '%sac%' THEN 'SAC'
                        WHEN t.name ILIKE '%back office%' OR t.name ILIKE '%backoffice%' OR t.name ILIKE '%bko%' THEN 'BKO'
                        WHEN t.name ILIKE '%sms%' THEN 'SMS'
                        ELSE 'OUTROS'
                    END AS setor
                FROM conversations c
                LEFT JOIN teams t ON t.id = c.team_id
                LEFT JOIN inboxes i ON i.id = c.inbox_id
                WHERE c.account_id = 1
                  AND c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                  AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                  AND (i.name IS NULL OR i.name != 'Atendimento | Brasil' OR c.id IN (SELECT conv_id FROM Conv48))
            )
            ${selecao}`;
        const linhas = (await pool.query(base(`
            SELECT setor, TO_CHAR(criado_br, 'YYYY-MM-DD') AS dia, EXTRACT(HOUR FROM criado_br)::int AS hora, status, (assignee_id IS NULL) AS sem_agente, COUNT(*)::int AS qtd
            FROM Recebidos GROUP BY 1, 2, 3, 4, 5`), [dataInicioSQL, dataFimSQL])).rows;
        const linhasAnt = (await pool.query(base(`SELECT setor, COUNT(*)::int AS qtd FROM Recebidos GROUP BY 1`), [ymd(antIni), ymd(antFim)])).rows;

        const TIMES = ['RET', 'SAC', 'BKO', 'SMS', '48H', 'OUTROS'];
        const zerado = () => { const o = { total: 0 }; TIMES.forEach(t => { o[t] = 0; }); return o; };
        const porDia = {};
        for (let i = 0; i < dias; i++) {
            const d = new Date(dIni.getTime() + i * DIA_MS), dia = ymd(d);
            porDia[dia] = Object.assign({ dia: dia, dow: d.getUTCDay(), parcial: dia === hojeBR }, zerado());   // dow: 0 = domingo ... 6 = sábado
        }
        const porHora = Array.from({ length: 24 }, (_, h) => Object.assign({ hora: h }, zerado()));
        const situacao = {};
        ['TODOS', ...TIMES].forEach(t => { situacao[t] = { abertos: 0, sem_agente: 0, pendentes: 0, adiados: 0, resolvidos: 0 }; });
        const porTime = zerado();
        linhas.forEach(r => {
            const t = TIMES.includes(r.setor) ? r.setor : 'OUTROS', n = parseInt(r.qtd) || 0, st = parseInt(r.status);
            porTime.total += n; porTime[t] += n;
            if (porDia[r.dia]) { porDia[r.dia].total += n; porDia[r.dia][t] += n; }
            if (porHora[r.hora]) { porHora[r.hora].total += n; porHora[r.hora][t] += n; }
            [situacao.TODOS, situacao[t]].forEach(s => {
                if (st === 0) { s.abertos += n; if (r.sem_agente) s.sem_agente += n; }
                else if (st === 1) s.resolvidos += n;
                else if (st === 2) s.pendentes += n;
                else if (st === 3) s.adiados += n;
            });
        });
        const anterior = zerado();
        linhasAnt.forEach(r => { const t = TIMES.includes(r.setor) ? r.setor : 'OUTROS', n = parseInt(r.qtd) || 0; anterior.total += n; anterior[t] += n; });

        res.json({
            success: true,
            periodo: { inicio: dataInicioSQL, fim: dataFimSQL, dias: dias, hoje: hojeBR },
            por_time: porTime,
            por_dia: Object.values(porDia),
            por_hora: porHora,
            situacao: situacao,
            anterior: { inicio: ymd(antIni), fim: ymd(antFim), dias: dias, por_time: anterior }
        });
    } catch (error) {
        console.error("Erro Recebimento de Tickets:", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==========================================
// 16.1 ROTA DE URGÊNCIA: REEMBOLSOS BUYGOODS (COM GOOGLE SHEETS)
// ==========================================
app.get('/api/reembolsos-buygoods', async (req, res) => {
    // 🔥 COLE O MESMO LINK DO GOOGLE AQUI:
    const URL_PLANILHA = "https://script.google.com/macros/s/AKfycbxLqWTExvo0824oEpWUJYbDIzVdK4q9S3eeElIo0n8eliTCYueQjOJIB0AOCPuDnl1LSw/exec";

    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    
    if (!adms.includes(emailUser)) {
        return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
    }
    
    try {
        // 1. LER O COFRE DO GOOGLE SHEETS (O mesmo cofre serve para todos!)
        // LOG (prioridade). Imutável: 1 por ticket, mantém o antigo.
        // OTIMIZACAO: o log do Google (fetch) roda em PARALELO com a query do banco (antes era sequencial) — tempo total cai p/ o maior dos dois, nao a soma
        const _pLog = (async () => {
            let logMap = {};
            try {
                const _r = await fetch(URL_PLANILHA, { redirect: 'follow' });
                const _t = (await _r.text()).trim();
                const dadosPlanilha = (_t.startsWith('[') || _t.startsWith('{')) ? JSON.parse(_t) : [];
                if (Array.isArray(dadosPlanilha)) dadosPlanilha.forEach(l => {
                    const tk = String(l.ticket || l[0] || '').trim();
                    if (!tk || logMap[tk] || /sem reembolso/i.test(String(l.tipo || l[2] || ''))) return;
                    const dl = new Date(l.data_hora || l[1]);
                    logMap[tk] = { data: isNaN(dl) ? null : dl, tipo: l.tipo || '', pedido: l.pedido || '', produto: l.produto || '', cliente: l.cliente || '', email: l.email || '' };
                });
            } catch (err) { console.log("Aviso: falha ao ler o log de reembolso.", err.message); }
            return logMap;
        })();

        let dInicio, dFim;
        if (req.query.since && req.query.until) {
            dInicio = new Date(parseInt(req.query.since) * 1000);
            dFim = new Date(parseInt(req.query.until) * 1000);
        } else {
            const agora = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Sao_Paulo" }));
            dInicio = new Date(agora.getFullYear(), agora.getMonth(), 1);
            dFim = agora;
        }
        const dCorte = new Date(dInicio); dCorte.setDate(dCorte.getDate() - 90); const dCorteSQL = dCorte.toISOString().slice(0, 10); // E: filtro de data movido pro banco (periodo + 90 dias de margem) — reduz o scan sem cortar resultado

        // 3. LER O BANCO DO CHATWOOT (FILTRO BUYGOODS)
        const q = `
        SELECT 
            c.id AS conv_id,
            c.display_id,
            COALESCE(u.name, 'SEM ATRIBUIR') AS agente_nome,
            ct.name AS contato_nome,
            ct.email AS contato_email,
            c.updated_at AS data_fallback,
            COALESCE(c.custom_attributes->>'tipo_de_retencao_de_reembolso', ct.custom_attributes->>'tipo_de_retencao_de_reembolso', '') AS tipo_retencao,
            COALESCE(
                NULLIF(TRIM(c.custom_attributes->>'order_number'), ''), 
                NULLIF(TRIM(ct.custom_attributes->>'order_number'), ''),
                NULLIF(TRIM(c.custom_attributes->>'numero_do_pedido'), ''), 
                NULLIF(TRIM(ct.custom_attributes->>'numero_do_pedido'), ''),
                NULLIF(TRIM(c.custom_attributes->>'numero_pedido'), ''), 
                NULLIF(TRIM(ct.custom_attributes->>'numero_pedido'), ''),
                NULLIF(TRIM(c.custom_attributes->>'Número do Pedido'), ''), 
                ''
            ) AS pedido_limpo,
            COALESCE(NULLIF(TRIM(c.custom_attributes->>'produtos'),''), NULLIF(TRIM(c.custom_attributes->>'produto'),''), NULLIF(TRIM(c.custom_attributes->>'Produto'),''), NULLIF(TRIM(ct.custom_attributes->>'produtos'),''), NULLIF(TRIM(ct.custom_attributes->>'produto'),''), NULLIF(TRIM(ct.custom_attributes->>'Produto'),''), '') AS produto_nome
        FROM conversations c
        LEFT JOIN users u ON u.id = c.assignee_id
        LEFT JOIN contacts ct ON ct.id = c.contact_id
        WHERE c.account_id = 1
          AND c.updated_at >= $1::timestamp
          AND (
              -- 🔥 VARIAÇÕES DO BUYGOODS AQUI
              COALESCE(c.custom_attributes::text, '') ILIKE ANY(ARRAY['%buygoods%', '%buygods%']) OR
              COALESCE(ct.custom_attributes::text, '') ILIKE ANY(ARRAY['%buygoods%', '%buygods%'])
          )
          AND COALESCE(c.custom_attributes->>'tipo_de_retencao_de_reembolso', ct.custom_attributes->>'tipo_de_retencao_de_reembolso', '') != ''
          AND COALESCE(c.custom_attributes->>'tipo_de_retencao_de_reembolso', ct.custom_attributes->>'tipo_de_retencao_de_reembolso', '') NOT ILIKE '%sem reembolso%'
        `;
        const [logMap, result] = await Promise.all([_pLog, pool.query(q, [dCorteSQL])]);

        // 4. CRUZAMENTO DE DADOS (Exatamente a mesma lógica)
        const resumoAgentes = {};
        
        result.rows.forEach(tk => {
            const L = logMap[String(tk.display_id)];
            const noLog = !!(L && L.data);
            const fonte = noLog ? 'Log' : 'Conversa';
            const dataReal    = noLog ? L.data      : new Date(tk.data_fallback);
            const tipoReal    = (noLog && L.tipo)    ? L.tipo    : tk.tipo_retencao;
            const pedidoReal  = (noLog && L.pedido)  ? L.pedido  : tk.pedido_limpo;
            const produtoReal = (noLog && L.produto) ? L.produto : (tk.produto_nome || 'Não informado');
            const clienteReal = (noLog && L.cliente) ? L.cliente : (tk.contato_nome || 'Sem Nome');
            const emailReal   = (noLog && L.email)   ? L.email   : (tk.contato_email || 'Sem Email');

            if (dataReal >= dInicio && dataReal <= dFim) {
                const agente = tk.agente_nome;
                if (!resumoAgentes[agente]) resumoAgentes[agente] = { agente_nome: agente, total_reembolsos: 0, r_10_30: 0, r_40_50: 0, r_60_90: 0, r_100: 0, r_outros: 0, detalhes: [] };
                resumoAgentes[agente].total_reembolsos++;
                const tipo = String(tipoReal).toLowerCase();
                if (tipo.includes('10 a 30%')) resumoAgentes[agente].r_10_30++;
                else if (tipo.includes('40 a 50%')) resumoAgentes[agente].r_40_50++;
                else if (tipo.includes('60 a 90%')) resumoAgentes[agente].r_60_90++;
                else if (tipo.includes('100%')) resumoAgentes[agente].r_100++;
                else resumoAgentes[agente].r_outros++;
                resumoAgentes[agente].detalhes.push({
                    id: tk.display_id, nome: clienteReal, email: emailReal,
                    data: dataReal, tipo: tipoReal, pedido: pedidoReal, produto: produtoReal,
                    fonte: fonte
                });
            }
        });

        const arrayFinal = Object.values(resumoAgentes).map(ag => {
            ag.detalhes.sort((a, b) => b.data - a.data);
            return ag;
        });
        arrayFinal.sort((a, b) => b.total_reembolsos - a.total_reembolsos);

        res.json({ success: true, dados: arrayFinal });
    } catch (error) { 
        console.error("Erro BuyGoods:", error);
        res.status(500).json({ success: false, error: "Erro interno no servidor." }); 
    }
});

app.get('/api/reembolsos-cartpanda', async (req, res) => {
    // 🔥 COLE O MESMO LINK DO GOOGLE AQUI:
    const URL_PLANILHA = "https://script.google.com/macros/s/AKfycbxLqWTExvo0824oEpWUJYbDIzVdK4q9S3eeElIo0n8eliTCYueQjOJIB0AOCPuDnl1LSw/exec";

    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    
    if (!adms.includes(emailUser)) {
        return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
    }
    
    try {
        // 1. LER O COFRE DO GOOGLE SHEETS (O mesmo cofre serve para todos!)
        // LOG (prioridade). Imutável: 1 por ticket, mantém o antigo.
        // OTIMIZACAO: o log do Google (fetch) roda em PARALELO com a query do banco (antes era sequencial) — tempo total cai p/ o maior dos dois, nao a soma
        const _pLog = (async () => {
            let logMap = {};
            try {
                const _r = await fetch(URL_PLANILHA, { redirect: 'follow' });
                const _t = (await _r.text()).trim();
                const dadosPlanilha = (_t.startsWith('[') || _t.startsWith('{')) ? JSON.parse(_t) : [];
                if (Array.isArray(dadosPlanilha)) dadosPlanilha.forEach(l => {
                    const tk = String(l.ticket || l[0] || '').trim();
                    if (!tk || logMap[tk] || /sem reembolso/i.test(String(l.tipo || l[2] || ''))) return;
                    const dl = new Date(l.data_hora || l[1]);
                    logMap[tk] = { data: isNaN(dl) ? null : dl, tipo: l.tipo || '', pedido: l.pedido || '', produto: l.produto || '', cliente: l.cliente || '', email: l.email || '' };
                });
            } catch (err) { console.log("Aviso: falha ao ler o log de reembolso.", err.message); }
            return logMap;
        })();

        let dInicio, dFim;
        if (req.query.since && req.query.until) {
            dInicio = new Date(parseInt(req.query.since) * 1000);
            dFim = new Date(parseInt(req.query.until) * 1000);
        } else {
            const agora = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Sao_Paulo" }));
            dInicio = new Date(agora.getFullYear(), agora.getMonth(), 1);
            dFim = agora;
        }
        const dCorte = new Date(dInicio); dCorte.setDate(dCorte.getDate() - 90); const dCorteSQL = dCorte.toISOString().slice(0, 10); // E: filtro de data movido pro banco (periodo + 90 dias de margem) — reduz o scan sem cortar resultado

        // 3. LER O BANCO DO CHATWOOT (FILTRO CARTPANDA)
        const q = `
        SELECT 
            c.id AS conv_id,
            c.display_id,
            COALESCE(u.name, 'SEM ATRIBUIR') AS agente_nome,
            ct.name AS contato_nome,
            ct.email AS contato_email,
            c.updated_at AS data_fallback,
            COALESCE(c.custom_attributes->>'tipo_de_retencao_de_reembolso', ct.custom_attributes->>'tipo_de_retencao_de_reembolso', '') AS tipo_retencao,
            COALESCE(
                NULLIF(TRIM(c.custom_attributes->>'order_number'), ''), 
                NULLIF(TRIM(ct.custom_attributes->>'order_number'), ''),
                NULLIF(TRIM(c.custom_attributes->>'numero_do_pedido'), ''), 
                NULLIF(TRIM(ct.custom_attributes->>'numero_do_pedido'), ''),
                NULLIF(TRIM(c.custom_attributes->>'numero_pedido'), ''), 
                NULLIF(TRIM(ct.custom_attributes->>'numero_pedido'), ''),
                NULLIF(TRIM(c.custom_attributes->>'Número do Pedido'), ''), 
                ''
            ) AS pedido_limpo,
            COALESCE(NULLIF(TRIM(c.custom_attributes->>'produtos'),''), NULLIF(TRIM(c.custom_attributes->>'produto'),''), NULLIF(TRIM(c.custom_attributes->>'Produto'),''), NULLIF(TRIM(ct.custom_attributes->>'produtos'),''), NULLIF(TRIM(ct.custom_attributes->>'produto'),''), NULLIF(TRIM(ct.custom_attributes->>'Produto'),''), '') AS produto_nome
        FROM conversations c
        LEFT JOIN users u ON u.id = c.assignee_id
        LEFT JOIN contacts ct ON ct.id = c.contact_id
        WHERE c.account_id = 1
          AND c.updated_at >= $1::timestamp
          AND (
              -- 🔥 VARIAÇÕES DO CARTPANDA AQUI
              COALESCE(c.custom_attributes::text, '') ILIKE ANY(ARRAY['%cartpanda%', '%cart panda%', '%cart_panda%', '%cart-panda%']) OR
              COALESCE(ct.custom_attributes::text, '') ILIKE ANY(ARRAY['%cartpanda%', '%cart panda%', '%cart_panda%', '%cart-panda%'])
          )
          AND COALESCE(c.custom_attributes->>'tipo_de_retencao_de_reembolso', ct.custom_attributes->>'tipo_de_retencao_de_reembolso', '') != ''
          AND COALESCE(c.custom_attributes->>'tipo_de_retencao_de_reembolso', ct.custom_attributes->>'tipo_de_retencao_de_reembolso', '') NOT ILIKE '%sem reembolso%'
        `;
        const [logMap, result] = await Promise.all([_pLog, pool.query(q, [dCorteSQL])]);

        // 4. CRUZAMENTO DE DADOS (Exatamente a mesma lógica)
        const resumoAgentes = {};
        
        result.rows.forEach(tk => {
            const L = logMap[String(tk.display_id)];
            const noLog = !!(L && L.data);
            const fonte = noLog ? 'Log' : 'Conversa';
            const dataReal    = noLog ? L.data      : new Date(tk.data_fallback);
            const tipoReal    = (noLog && L.tipo)    ? L.tipo    : tk.tipo_retencao;
            const pedidoReal  = (noLog && L.pedido)  ? L.pedido  : tk.pedido_limpo;
            const produtoReal = (noLog && L.produto) ? L.produto : (tk.produto_nome || 'Não informado');
            const clienteReal = (noLog && L.cliente) ? L.cliente : (tk.contato_nome || 'Sem Nome');
            const emailReal   = (noLog && L.email)   ? L.email   : (tk.contato_email || 'Sem Email');

            if (dataReal >= dInicio && dataReal <= dFim) {
                const agente = tk.agente_nome;
                if (!resumoAgentes[agente]) resumoAgentes[agente] = { agente_nome: agente, total_reembolsos: 0, r_10_30: 0, r_40_50: 0, r_60_90: 0, r_100: 0, r_outros: 0, detalhes: [] };
                resumoAgentes[agente].total_reembolsos++;
                const tipo = String(tipoReal).toLowerCase();
                if (tipo.includes('10 a 30%')) resumoAgentes[agente].r_10_30++;
                else if (tipo.includes('40 a 50%')) resumoAgentes[agente].r_40_50++;
                else if (tipo.includes('60 a 90%')) resumoAgentes[agente].r_60_90++;
                else if (tipo.includes('100%')) resumoAgentes[agente].r_100++;
                else resumoAgentes[agente].r_outros++;
                resumoAgentes[agente].detalhes.push({
                    id: tk.display_id, nome: clienteReal, email: emailReal,
                    data: dataReal, tipo: tipoReal, pedido: pedidoReal, produto: produtoReal,
                    fonte: fonte
                });
            }
        });

        const arrayFinal = Object.values(resumoAgentes).map(ag => {
            ag.detalhes.sort((a, b) => b.data - a.data);
            return ag;
        });
        arrayFinal.sort((a, b) => b.total_reembolsos - a.total_reembolsos);

        res.json({ success: true, dados: arrayFinal });
    } catch (error) { 
        console.error("Erro CartPanda:", error);
        res.status(500).json({ success: false, error: "Erro interno no servidor." }); 
    }
});

// ==========================================
// 18. 🩻 RAIO-X DO SNOOZE (diagnóstico do log de auditoria) — SOMENTE ADMIN
// Abra no navegador (logado): https://SEU-DASH/api/raio-x-snooze
// ==========================================
app.get('/api/raio-x-snooze', async (req, res) => {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    if (!adms.includes(emailUser)) {
        return res.status(403).send('<h1>Acesso restrito a administradores.</h1>');
    }

    const blocos = [];
    async function testar(titulo, sql) {
        try {
            const r = await pool.query(sql);
            blocos.push({ titulo, ok: true, linhas: r.rows });
        } catch (e) {
            blocos.push({ titulo, ok: false, erro: e.message });
        }
    }

    await testar('1) Tabela "audits" existe?',
        `SELECT to_regclass('public.audits') AS audits_existe`);

    await testar('2) Tipo da coluna audited_changes',
        `SELECT column_name, data_type FROM information_schema.columns
         WHERE table_name = 'audits' AND column_name IN ('audited_changes','action','auditable_type')`);

    await testar('3) Qtd de audits de snooze (via JSONB "?")',
        `SELECT COUNT(*) AS total FROM audits
         WHERE auditable_type = 'Conversation' AND audited_changes ? 'snoozed_until'`);

    await testar('3b) Qtd de audits de snooze (via TEXTO) — fallback',
        `SELECT COUNT(*) AS total FROM audits
         WHERE auditable_type = 'Conversation' AND audited_changes::text ILIKE '%snoozed_until%'`);

    await testar('4) Amostras (JSONB): valor escolhido do snooze',
        `SELECT auditable_id AS conversa, created_at,
                audited_changes -> 'snoozed_until' AS mudanca_snooze,
                audited_changes -> 'snoozed_until' ->> 1 AS valor_novo
         FROM audits
         WHERE auditable_type = 'Conversation' AND audited_changes ? 'snoozed_until'
         ORDER BY created_at DESC LIMIT 15`);

    await testar('4b) Amostras (TEXTO cru) — fallback',
        `SELECT auditable_id AS conversa, created_at, LEFT(audited_changes::text, 300) AS audited_changes_cru
         FROM audits
         WHERE auditable_type = 'Conversation' AND audited_changes::text ILIKE '%snoozed_until%'
         ORDER BY created_at DESC LIMIT 15`);

    await testar('5) 🎯 PROVA FINAL: adiamento x audit correspondente',
        `SELECT m.conversation_id AS conversa, m.created_at AS hora_adiamento,
                aud.created_at AS hora_audit,
                aud.audited_changes -> 'snoozed_until' ->> 1 AS snooze_escolhido
         FROM messages m
         LEFT JOIN LATERAL (
             SELECT a.created_at, a.audited_changes
             FROM audits a
             WHERE a.auditable_type = 'Conversation'
               AND a.auditable_id = m.conversation_id
               AND a.audited_changes ? 'snoozed_until'
               AND a.created_at BETWEEN m.created_at - interval '15 seconds' AND m.created_at + interval '15 seconds'
             ORDER BY abs(extract(epoch from (a.created_at - m.created_at))) LIMIT 1
         ) aud ON true
         WHERE m.account_id = 1 AND m.message_type = 2 AND m.content ILIKE '%adiad%'
         ORDER BY m.created_at DESC LIMIT 15`);

    await testar('6) 🔬 O que vem DENTRO de cada adiamento (content_attributes + snooze vivo)',
        `SELECT m.conversation_id AS conversa, m.created_at AS hora,
                m.content_attributes AS atributos_da_mensagem,
                c.status AS status_atual_num, c.snoozed_until AS snooze_vivo
         FROM messages m
         JOIN conversations c ON c.id = m.conversation_id
         WHERE m.account_id = 1 AND m.message_type = 2 AND m.content ILIKE '%adiad%'
         ORDER BY m.created_at DESC LIMIT 15`);

    let html = `<!doctype html><html lang="pt-br"><head><meta charset="utf-8"><title>Raio-X Snooze</title>
    <style>
      body{font-family:system-ui,Segoe UI,Arial;background:#0f172a;color:#e2e8f0;padding:24px;}
      h1{color:#22d3ee;} h2{color:#93c5fd;margin-top:26px;border-bottom:1px solid #334155;padding-bottom:6px;font-size:16px;}
      .ok{color:#34d399;} .fail{color:#f87171;}
      table{border-collapse:collapse;width:100%;margin-top:8px;font-size:13px;}
      th,td{border:1px solid #334155;padding:6px 8px;text-align:left;vertical-align:top;}
      th{background:#1e293b;color:#cbd5e1;} tr:nth-child(even){background:#111c30;}
      .box{background:#1e293b;padding:10px 14px;border-radius:8px;margin-top:6px;}
      code{color:#fbbf24;}
    </style></head><body>
    <h1>🩻 Raio-X do Snooze — log de auditoria</h1>
    <p>Se o bloco <b>5</b> mostrar <code>snooze_escolhido</code> com data (ex.: 2026-09-17T20:30) ou vazio (= próxima resposta), dá pra corrigir de vez. <b>Tire print desta página inteira e me mande.</b></p>`;

    for (const b of blocos) {
        html += `<h2>${b.titulo} — ${b.ok ? '<span class="ok">OK</span>' : '<span class="fail">FALHOU</span>'}</h2>`;
        if (!b.ok) { html += `<div class="box fail">Erro: ${String(b.erro).replace(/</g,'&lt;')}</div>`; continue; }
        if (!b.linhas.length) { html += `<div class="box">(sem linhas)</div>`; continue; }
        const cols = Object.keys(b.linhas[0]);
        html += '<table><tr>' + cols.map(c => `<th>${c}</th>`).join('') + '</tr>';
        for (const row of b.linhas) {
            html += '<tr>' + cols.map(c => {
                let v = row[c];
                if (v === null || v === undefined) v = '<i style="color:#64748b">null</i>';
                else v = String(typeof v === 'object' ? JSON.stringify(v) : v).replace(/</g,'&lt;');
                return `<td>${v}</td>`;
            }).join('') + '</tr>';
        }
        html += '</table>';
    }
    html += '</body></html>';
    res.send(html);
});



// ==========================================
// 19. 🩻 RAIO-X DO BANCO (somente leitura) — SOMENTE ADMIN
// Abra: /api/raio-x  (visão geral)  |  /api/raio-x?tabela=conversations (detalhe)
// NÃO altera nada: executa apenas SELECT.
// ==========================================
app.get('/api/raio-x', async (req, res) => {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    if (!adms.includes(emailUser)) {
        return res.status(403).send('<h1>Acesso restrito a administradores.</h1>');
    }

    const esc = (v) => (v === null || v === undefined) ? '<i style="color:#64748b">null</i>'
        : String(typeof v === 'object' ? JSON.stringify(v) : v).replace(/</g, '&lt;');
    const estilo = `<style>
      body{font-family:system-ui,Segoe UI,Arial;background:#0f172a;color:#e2e8f0;padding:24px;}
      h1{color:#22d3ee;} h2{color:#93c5fd;margin-top:22px;border-bottom:1px solid #334155;padding-bottom:6px;font-size:16px;}
      a{color:#38bdf8;text-decoration:none;} a:hover{text-decoration:underline;}
      table{border-collapse:collapse;width:100%;margin-top:8px;font-size:13px;}
      th,td{border:1px solid #334155;padding:6px 8px;text-align:left;vertical-align:top;max-width:340px;overflow:hidden;text-overflow:ellipsis;}
      th{background:#1e293b;color:#cbd5e1;} tr:nth-child(even){background:#111c30;}
      .tag{background:#1e293b;color:#fbbf24;padding:2px 6px;border-radius:4px;font-size:11px;}
      .aviso{background:#064e3b;color:#a7f3d0;padding:8px 12px;border-radius:8px;display:inline-block;margin-bottom:10px;}
    </style>`;

    try {
        const tabsRes = await pool.query(
            `SELECT table_name FROM information_schema.tables
             WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name`);
        const tabelasValidas = tabsRes.rows.map(r => r.table_name);
        const tabela = (req.query.tabela || '').trim();

        let html = `<!doctype html><html lang="pt-br"><head><meta charset="utf-8"><title>Raio-X do Banco</title>${estilo}</head><body>`;
        html += `<h1>🩻 Raio-X do Banco — somente leitura</h1><div class="aviso">🔒 Modo leitura: só executa SELECT. Nada é criado, alterado ou apagado.</div>`;

        if (tabela && tabelasValidas.includes(tabela)) {
            // ----- DETALHE DE UMA TABELA (validada contra a lista real) -----
            const cols = await pool.query(
                `SELECT column_name, data_type, is_nullable FROM information_schema.columns
                 WHERE table_schema='public' AND table_name=$1 ORDER BY ordinal_position`, [tabela]);
            const amostra = await pool.query(`SELECT * FROM "${tabela}" LIMIT 20`); // tabela já validada = seguro

            html += `<p><a href="/api/raio-x">&larr; voltar pra lista</a></p>`;
            html += `<h2>Tabela: ${tabela} — ${cols.rows.length} colunas</h2>`;
            html += '<table><tr><th>Coluna</th><th>Tipo</th><th>Aceita null?</th></tr>';
            for (const c of cols.rows) html += `<tr><td>${esc(c.column_name)}</td><td>${esc(c.data_type)}</td><td>${esc(c.is_nullable)}</td></tr>`;
            html += '</table>';

            html += `<h2>Amostra (20 primeiras linhas)</h2>`;
            if (!amostra.rows.length) { html += '<p>(tabela vazia)</p>'; }
            else {
                const ck = Object.keys(amostra.rows[0]);
                html += '<table><tr>' + ck.map(c => `<th>${esc(c)}</th>`).join('') + '</tr>';
                for (const row of amostra.rows) html += '<tr>' + ck.map(c => `<td>${esc(row[c])}</td>`).join('') + '</tr>';
                html += '</table>';
            }
        } else {
            // ----- VISÃO GERAL: TODAS AS TABELAS + Nº APROX. DE LINHAS -----
            const contagem = await pool.query(
                `SELECT relname AS tabela, n_live_tup AS linhas_aprox
                 FROM pg_stat_user_tables ORDER BY n_live_tup DESC`);
            const mapaCont = {}; contagem.rows.forEach(r => mapaCont[r.tabela] = r.linhas_aprox);

            html += `<h2>${tabelasValidas.length} tabelas no banco (clique pra explorar)</h2>`;
            html += '<table><tr><th>Tabela</th><th>Linhas (aprox.)</th></tr>';
            const ordenadas = [...tabelasValidas].sort((a,b) => (mapaCont[b]||0) - (mapaCont[a]||0));
            for (const t of ordenadas) {
                html += `<tr><td><a href="/api/raio-x?tabela=${encodeURIComponent(t)}">${esc(t)}</a></td><td>${esc(mapaCont[t] ?? '?')}</td></tr>`;
            }
            html += '</table>';
            html += `<p style="margin-top:16px;color:#94a3b8">Dica: pra ver o snooze do jeito que o agente escolheu, abra <a href="/api/raio-x-snooze">/api/raio-x-snooze</a>.</p>`;
        }
        html += '</body></html>';
        res.send(html);
    } catch (e) {
        res.status(500).send(`<body style="background:#0f172a;color:#f87171;font-family:system-ui;padding:24px"><h1>Erro (nada foi alterado)</h1><pre>${String(e.message).replace(/</g,'&lt;')}</pre></body>`);
    }
});


// ==========================================
// 🅱️ RAIO-X DO WEBHOOK DE SNOOZE (lê a planilha capturada) — SOMENTE ADMIN
// Abra: /api/raio-x-webhook
// ==========================================
app.get('/api/raio-x-webhook', async (req, res) => {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    if (!adms.includes(emailUser)) return res.status(403).send('<h1>Acesso restrito a administradores.</h1>');

    const esc = (v) => (v === null || v === undefined) ? '<i style="color:#64748b">null</i>'
        : String(typeof v === 'object' ? JSON.stringify(v) : v).replace(/</g, '&lt;');

    let linhas = [], erroSheets = null;
    try {
        const sheets = getSheetsRW();
        const r = await sheets.spreadsheets.values.get({ spreadsheetId: SNOOZE_SHEET_ID, range: `${SNOOZE_ABA}!A1:F5000` });
        linhas = r.data.values || [];
    } catch (e) { erroSheets = e.message; }

    let html = `<!doctype html><html lang="pt-br"><head><meta charset="utf-8"><title>Raio-X Webhook Snooze</title>
    <style>body{font-family:system-ui,Segoe UI,Arial;background:#0f172a;color:#e2e8f0;padding:24px;}
    h1{color:#22d3ee;}h2{color:#93c5fd;margin-top:22px;border-bottom:1px solid #334155;padding-bottom:6px;font-size:16px;}
    table{border-collapse:collapse;width:100%;margin-top:8px;font-size:13px;}th,td{border:1px solid #334155;padding:6px 8px;text-align:left;vertical-align:top;}
    th{background:#1e293b;}tr:nth-child(even){background:#111c30;}pre{background:#1e293b;padding:10px;border-radius:8px;overflow:auto;font-size:12px;}
    .aviso{background:#064e3b;color:#a7f3d0;padding:8px 12px;border-radius:8px;display:inline-block;}.fail{background:#7f1d1d;color:#fecaca;padding:8px 12px;border-radius:8px;display:inline-block;}</style></head><body>
    <h1>🅱️ Raio-X do Webhook de Snooze</h1>
    <div class="aviso">🔒 Grava/lê só na planilha separada. O banco do Chatwoot não é tocado.</div>`;

    if (erroSheets) html += `<h2 class="fail">Erro ao ler a planilha</h2><pre>${esc(erroSheets)}</pre><p>Confira: planilha compartilhada como <b>Editor</b> com a service account, aba <code>${SNOOZE_ABA}</code>, e <code>GOOGLE_PRIVATE_KEY</code> no ambiente.</p>`;

    const dados = linhas.length > 1 ? linhas.slice(1) : [];
    html += `<h2>Adiamentos capturados na planilha: ${dados.length}</h2>`;
    if (dados.length) {
        const head = linhas[0];
        html += '<table><tr>' + head.map(c => `<th>${esc(c)}</th>`).join('') + '</tr>';
        for (const row of dados.slice(-40).reverse()) html += '<tr>' + head.map((_, i) => `<td>${esc(row[i])}</td>`).join('') + '</tr>';
        html += '</table>';
    } else if (!erroSheets) {
        html += `<p>Vazio. Confira: (1) webhook criado no Chatwoot; (2) houve um adiamento COM tempo depois disso.</p>`;
    }

    html += `<h2>Últimos payloads crus recebidos (confira se vem o snoozed_until)</h2>`;
    if (snoozeRawRecentes.length) { for (const rr of snoozeRawRecentes) html += `<pre>${esc(JSON.stringify(rr, null, 2))}</pre>`; }
    else html += `<p>(nenhum payload recebido ainda — faça um adiamento de teste)</p>`;

    html += '</body></html>';
    res.send(html);
});


// ==========================================
// 20. 📊 RESUMO EXECUTIVO (estilo Cockpit) p/ Evolução de Recorrência — SOMENTE ADMIN
// ==========================================
app.get('/api/resumo-recorrencia', async (req, res) => {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    if (!adms.includes(emailUser)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });

    try {
        let ini, fim;
        if (req.query.since && req.query.until) {
            ini = unixParaYYYYMMDD(req.query.since); fim = unixParaYYYYMMDD(req.query.until);
        } else {
            const agora = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Sao_Paulo" }));
            ini = formatarDataSQL(new Date(agora.getFullYear(), agora.getMonth(), 1));
            fim = formatarDataSQL(agora);
        }
        const P = [ini, fim];
        const roda = async (sql, params = P) => { try { return (await pool.query(sql, params)).rows; } catch (e) { console.error('[resumo]', e.message); return null; } };
        const JAN = "created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo' AND created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'";
        // 🔥 Só Casos Reais: fora Spam, Duplicado, Redirecionamento ClickBank e Automação ClickBank (igual ao Cockpit)
        const JUNK = "(SELECT tg.taggable_id FROM taggings tg JOIN tags t ON t.id = tg.tag_id WHERE tg.taggable_type = 'Conversation' AND lower(t.name) IN ('spam','duplicado','redirecionamento-clickbank','automacao-clickbank'))";

        const [cont, sla, porDia, fila, entre, prod, heat] = await Promise.all([
            roda(`SELECT COUNT(*) AS total,
                     COUNT(*) FILTER (WHERE first_reply_created_at IS NOT NULL) AS com_resp,
                     COUNT(*) FILTER (WHERE first_reply_created_at IS NOT NULL AND first_reply_created_at - created_at <= interval '24 hours') AS ate24,
                     COUNT(*) FILTER (WHERE first_reply_created_at IS NOT NULL AND first_reply_created_at - created_at <= interval '1 hour') AS ate1
                   FROM conversations WHERE account_id = 1 AND id NOT IN ${JUNK} AND ${JAN}`),
            roda(`SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (first_reply_created_at - created_at))) AS med,
                     AVG(EXTRACT(EPOCH FROM (first_reply_created_at - created_at))) AS media
                   FROM conversations WHERE account_id = 1 AND first_reply_created_at IS NOT NULL AND id NOT IN ${JUNK} AND ${JAN}`),
            roda(`SELECT DATE(created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo') AS dia, COUNT(*) AS n
                   FROM conversations WHERE account_id = 1 AND id NOT IN ${JUNK} AND ${JAN} GROUP BY 1 ORDER BY 1`),
            roda(`SELECT COUNT(*) FILTER (WHERE status = 0) AS abertas,
                     COUNT(*) FILTER (WHERE status = 0 AND first_reply_created_at IS NULL) AS sem_resp
                   FROM conversations WHERE account_id = 1 AND id NOT IN ${JUNK}`, []),
            roda(`SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY value) AS med
                   FROM reporting_events WHERE account_id = 1 AND name = 'reply_time' AND conversation_id NOT IN ${JUNK} AND ${JAN}`),
            roda(`WITH atv AS (
                     SELECT DISTINCT m.sender_id AS ag, DATE(m.created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo') AS dia, m.conversation_id AS conv
                     FROM messages m
                     WHERE m.sender_type = 'User' AND m.message_type = 1 AND m.private = FALSE AND m.account_id = 1
                       AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE AND m.conversation_id NOT IN ${JUNK} AND m.${JAN}
                   ) SELECT COUNT(*) AS conv_dias, COUNT(DISTINCT (ag::text || ':' || dia)) AS ag_dias FROM atv`),
            roda(`SELECT EXTRACT(DOW FROM created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo')::int AS dow,
                     EXTRACT(HOUR FROM created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo')::int AS hora, COUNT(*) AS n
                   FROM conversations WHERE account_id = 1 AND id NOT IN ${JUNK} AND ${JAN} GROUP BY 1, 2`)
        ]);

        const c = (cont && cont[0]) || {}, s = (sla && sla[0]) || {}, f = (fila && fila[0]) || {}, pr = (prod && prod[0]) || {};
        const total = parseInt(c.total) || 0, comResp = parseInt(c.com_resp) || 0;
        const convDias = parseInt(pr.conv_dias) || 0, agDias = parseInt(pr.ag_dias) || 0;
        const nDias = (porDia || []).length || 1;

        res.json({
            success: true, periodo: { ini, fim }, dias: nDias,
            volume: { total, media_dia: total / nDias, por_dia: (porDia || []).map(r => ({ dia: r.dia, n: parseInt(r.n) || 0 })) },
            sla_1a: { mediana_s: s.med != null ? Math.round(s.med) : null, media_s: s.media != null ? Math.round(s.media) : null },
            pct_24h: total ? (parseInt(c.ate24) || 0) / total * 100 : 0,
            pct_1h: total ? (parseInt(c.ate1) || 0) / total * 100 : 0,
            sem_resposta: total - comResp,
            pct_sem_resposta: total ? (total - comResp) / total * 100 : 0,
            sla_entre_s: (entre && entre[0] && entre[0].med != null) ? Math.round(entre[0].med) : null,
            fila: { abertas: parseInt(f.abertas) || 0, sem_resposta: parseInt(f.sem_resp) || 0 },
            produtividade: agDias ? convDias / agDias : 0,
            heatmap: (heat || []).map(r => ({ dow: parseInt(r.dow), hora: parseInt(r.hora), n: parseInt(r.n) || 0 }))
        });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// 🔒 RAIO-X DE DESEMPENHO — acesso exclusivo por e-mail (configuravel via EMAILS_RAIOX)
function ehDonoRaioX(req) {
    const email = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const permitidos = (process.env.EMAILS_RAIOX || 'maurilio.silva@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    return permitidos.includes(email);
}
app.get('/api/raio-x-perf', (req, res) => {
    if (!ehDonoRaioX(req)) return res.status(403).json({ success: false, error: 'Acesso restrito.' });
    const agora = Date.now();
    const cache = Object.keys(cacheMemoria).map(k => ({
        rota: k,
        idade_min: +((agora - cacheMemoria[k].tempo) / 60000).toFixed(1),
        tempo_ms: (tempoRotas[k] != null) ? tempoRotas[k] : null
    })).sort((a, b) => a.rota.localeCompare(b.rota));
    const acesso_min = ultimoAcessoApi ? +((agora - ultimoAcessoApi) / 60000).toFixed(1) : null;
    res.json({
        success: true,
        gerado_em: new Date().toISOString(),
        warmer: {
            token_configurado: !!process.env.WARM_TOKEN,
            ativo: !!(ultimoAcessoApi && (agora - ultimoAcessoApi <= 20 * 60 * 1000)),
            ultimo_acesso_real_min: acesso_min,
            intervalo_min: 15,
            rotas: ROTAS_WARM
        },
        pool: { em_uso: pool.totalCount - pool.idleCount, livres: pool.idleCount, total: pool.totalCount, fila: pool.waitingCount, max: (pool.options && pool.options.max) || 10 },
        freio: { pausado: agora < FREIO.ate, ate: FREIO.ate ? new Date(FREIO.ate).toISOString() : null, acionamentos: FREIO.acionamentos, falhas_seguidas: FREIO.falhas, ultimo_erro: FREIO.ultimo_erro },
        protecao: { consultas_aproveitadas: consultasAproveitadas, dados_guardados_servidos: dadosGuardadosServidos },
        cache: cache
    });
});

const PORT = process.env.PORT || 3003;

// ==========================================
// 📅 TICKETS DIÁRIO (matriz agente x data) — base p/ exports com datas — ADMIN
// ==========================================
app.get('/api/tickets-diario', async (req, res) => {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    if (!adms.includes(emailUser)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
    try {
        let ini, fim;
        if (req.query.since && req.query.until) {
            ini = unixParaYYYYMMDD(req.query.since); fim = unixParaYYYYMMDD(req.query.until);
        } else {
            const agora = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Sao_Paulo" }));
            ini = formatarDataSQL(new Date(agora.getFullYear(), agora.getMonth(), 1));
            fim = formatarDataSQL(agora);
        }
        const result = await pool.query(queryTickets, [ini, fim]);
        const dias = [];
        let d = new Date(ini + 'T12:00:00Z'); const dEnd = new Date(fim + 'T12:00:00Z');
        while (d <= dEnd) { dias.push(d.toISOString().split('T')[0]); d.setUTCDate(d.getUTCDate() + 1); }
        const mapa = {};
        result.rows.forEach(r => {
            const nome = r.agente || 'SEM ATRIBUIR';
            const diaStr = r.dia instanceof Date ? r.dia.toISOString().split('T')[0] : String(r.dia).split('T')[0];
            if (!mapa[nome]) mapa[nome] = { nome, porDia: {}, total: 0 };
            const v = parseInt(r.tickets) || 0;
            mapa[nome].porDia[diaStr] = (mapa[nome].porDia[diaStr] || 0) + v;
            mapa[nome].total += v;
        });
        const agentes = Object.values(mapa).sort((a, b) => b.total - a.total);
        res.json({ success: true, ini, fim, dias, agentes });
    } catch (error) { console.error('[tickets-diario]', error.message); res.status(500).json({ success: false, error: error.message }); }
});


// ==========================================
// 20. ADIAR CASOS (SNOOZE) — ADMIN
// Lê os casos EM ABERTO cuja ÚLTIMA mensagem pública foi do AGENTE (cliente
// ainda não respondeu) e adia via API REST do Chatwoot. Suporta filtro por
// time, por agente (lista) e por faixa de SLA, e adiamento por 1h / 1 dia /
// até a próxima resposta / personalizado. NÃO toca no banco do Chatwoot.
// ==========================================
const CHATWOOT_URL = (process.env.CHATWOOT_URL || 'https://chat.institutoexperience.com').replace(/\/+$/, '');
const CHATWOOT_ACCOUNT_ID = process.env.CHATWOOT_ACCOUNT_ID || '1';
const CHATWOOT_API_TOKEN = process.env.CHATWOOT_API_TOKEN || '';

function ehAdminReq(req) {
    const email = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    return adms.includes(email);
}

const SQL_CASOS_ADIAR = `
    WITH Conv48 AS (
        SELECT DISTINCT tg.taggable_id AS conv_id
        FROM taggings tg
        JOIN tags t2 ON t2.id = tg.tag_id
        WHERE tg.taggable_type = 'Conversation' AND t2.name ILIKE '%time-48h%'
    ),
    OpenConversations AS (
        SELECT
            c.id, c.display_id, c.assignee_id, c.contact_id, c.last_activity_at, c.created_at,
            CASE
                WHEN c.id IN (SELECT conv_id FROM Conv48) THEN '48H'
                WHEN i.name = '[GEX] SMS Support' THEN 'SMS'
                WHEN t.name ILIKE '%reten%' THEN 'RET'
                WHEN t.name ILIKE '%sac%' THEN 'SAC'
                WHEN t.name ILIKE '%back office%' OR t.name ILIKE '%backoffice%' OR t.name ILIKE '%bko%' THEN 'BKO'
                WHEN t.name ILIKE '%sms%' THEN 'SMS'
                ELSE 'OUTROS'
            END AS setor
        FROM conversations c
        LEFT JOIN teams t ON t.id = c.team_id
        LEFT JOIN inboxes i ON i.id = c.inbox_id
        WHERE c.status = 0
          AND c.account_id = 1
          AND (i.name IS NULL OR i.name != 'Atendimento | Brasil')
    )
    SELECT
        u.name AS agente, oc.setor AS setor, oc.id AS conv_id, oc.display_id,
        ct.name AS cliente, oc.last_activity_at, oc.created_at,
        lm.created_at AS last_msg_at, lm.message_type AS last_msg_type, lm.content AS last_msg_content
    FROM OpenConversations oc
    LEFT JOIN users u ON u.id = oc.assignee_id
    LEFT JOIN contacts ct ON ct.id = oc.contact_id
    JOIN LATERAL (
        SELECT m.message_type, m.created_at, m.content
        FROM messages m
        WHERE m.conversation_id = oc.id
          AND m.account_id = 1
          AND m.message_type <> 2
          AND m.private = FALSE
          AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE
        ORDER BY m.created_at DESC
        LIMIT 1
    ) lm ON TRUE
    WHERE lm.message_type <> 0
`;

function limparPreviewMsg(txt) {
    if (!txt) return '(sem texto — anexo ou mensagem automática)';
    let s = String(txt).replace(/\s+/g, ' ').trim();
    return s.length > 160 ? s.slice(0, 160) + '…' : s;
}

function agruparCasosAdiar(rows) {
    const mapa = {};
    const agora = new Date();
    rows.forEach(r => {
        let nomeAgente = (r.agente || '').toUpperCase();
        let siglaSetor = r.setor || 'OUTROS';
        let nome;
        if (!nomeAgente) {
            if (siglaSetor === 'OUTROS') return;
            nome = `SEM ATRIBUIR - ${siglaSetor}`;
        } else {
            const mSig = nomeAgente.match(/[\s\-]+(RET|SAC|BKO|SMS|48H)\b/);
            if (!mSig) return;
            nome = nomeAgente.replace(/[\s\-]+(RET|SAC|BKO|SMS|48H)\b.*$/, '').trim() + ' - ' + mSig[1];
        }
        if (!mapa[nome]) mapa[nome] = { nome, retornos: 0, aguardando: 0, fora_sla: 0, total: 0, detalhes: [] };
        const base = r.last_msg_at ? new Date(r.last_msg_at) : (r.last_activity_at ? new Date(r.last_activity_at) : new Date(r.created_at));
        const diffHoras = (agora - base) / (1000 * 60 * 60);
        let statusLabel, ordem;
        if (diffHoras > 48) { mapa[nome].fora_sla += 1; statusLabel = '\u{1F534} +48h'; ordem = 1; }
        else if (diffHoras >= 24) { mapa[nome].aguardando += 1; statusLabel = '\u{1F7E1} 24-48h'; ordem = 2; }
        else { mapa[nome].retornos += 1; statusLabel = '\u{1F7E2} < 24h'; ordem = 3; }
        mapa[nome].total += 1;
        mapa[nome].detalhes.push({
            id: r.display_id || r.conv_id, display_id: r.display_id,
            cliente: r.cliente || 'Cliente sem nome', status: statusLabel, ordem,
            horas_parado: Math.round(diffHoras),
            ultima_msg_por: (r.last_msg_type === 3 ? 'Agente (automático)' : 'Agente'),
            ultima_msg_preview: limparPreviewMsg(r.last_msg_content)
        });
    });
    return Object.values(mapa).sort((a, b) => b.total - a.total);
}

function detalhePassaFaixa(horas, faixa) {
    if (faixa === 'MENOS24') return horas < 24;
    if (faixa === '24A48') return horas >= 24 && horas <= 48;
    if (faixa === 'MAIS48') return horas > 48;
    return true;
}

function calcularSnoozedUntil(modo, valor, unidade) {
    const nowSec = Math.floor(Date.now() / 1000);
    if (modo === '1h') return nowSec + 3600;
    if (modo === '1d') return nowSec + 86400;
    if (modo === 'custom') {
        const n = parseInt(valor, 10);
        if (!n || n <= 0) return null;
        return nowSec + (unidade === 'dias' ? n * 86400 : n * 3600);
    }
    return null; // 'proxima' ou desconhecido = até a próxima resposta
}

// 🔒 ADIAR CASOS — acesso exclusivo por e-mail (configurável via EMAILS_ADIAR)
function ehDonoAdiar(req) {
    const email = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const permitidos = (process.env.EMAILS_ADIAR || 'maurilio.silva@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    return permitidos.includes(email);
}

app.get('/api/casos-para-adiar', async (req, res) => {
    if (!ehDonoAdiar(req)) return res.status(403).json({ success: false, error: 'Acesso restrito.' });
    try {
        const r = await pool.query(SQL_CASOS_ADIAR);
        const casos = agruparCasosAdiar(r.rows);
        const resumo = { RET: 0, SAC: 0, BKO: 0, SMS: 0, '48H': 0 };
        let totalGeral = 0;
        casos.forEach(a => {
            totalGeral += a.total;
            ['RET', 'SAC', 'BKO', 'SMS', '48H'].forEach(s => { if (a.nome.toUpperCase().includes(`- ${s}`)) resumo[s] += a.total; });
        });
        res.json({ success: true, casos, resumo_setor: resumo, total_geral: totalGeral, token_ok: !!CHATWOOT_API_TOKEN });
    } catch (e) { console.error('[casos-para-adiar]', e.message); res.status(500).json({ success: false, error: e.message }); }
});

async function snoozeConversa(displayId, snoozedUntil) {
    const url = `${CHATWOOT_URL}/api/v1/accounts/${CHATWOOT_ACCOUNT_ID}/conversations/${displayId}/toggle_status`;
    const body = { status: 'snoozed' };
    if (snoozedUntil) body.snoozed_until = snoozedUntil;
    const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'api_access_token': CHATWOOT_API_TOKEN },
        body: JSON.stringify(body)
    });
    if (!resp.ok) {
        let txt = ''; try { txt = await resp.text(); } catch (e) {}
        throw new Error(`HTTP ${resp.status} ${String(txt).slice(0, 120)}`);
    }
    return true;
}

app.post('/api/adiar-casos', express.json(), async (req, res) => {
    if (!ehDonoAdiar(req)) return res.status(403).json({ success: false, error: 'Acesso restrito.' });
    try {
        if (!CHATWOOT_API_TOKEN) return res.status(400).json({ success: false, error: 'CHATWOOT_API_TOKEN nao configurado no .env do servidor.' });
        const b = req.body || {};
        const agentesSel = Array.isArray(b.agentes) ? b.agentes.map(x => String(x).toUpperCase()) : [];
        const setor = (b.setor ? String(b.setor) : 'TODOS').toUpperCase();
        const faixa = (b.faixa ? String(b.faixa) : 'TODAS').toUpperCase();
        const snoozedUntil = calcularSnoozedUntil(b.modo, b.valor, b.unidade);

        const r = await pool.query(SQL_CASOS_ADIAR);
        let casos = agruparCasosAdiar(r.rows);
        if (agentesSel.length > 0) casos = casos.filter(a => agentesSel.includes(a.nome.toUpperCase()));
        else if (setor !== 'TODOS') casos = casos.filter(a => a.nome.toUpperCase().includes(`- ${setor}`));

        const ids = [];
        casos.forEach(a => (a.detalhes || []).forEach(d => {
            if (d.display_id && detalhePassaFaixa(d.horas_parado, faixa)) ids.push(d.display_id);
        }));
        const idsUnicos = [...new Set(ids)];

        const CONC = 6;
        let ok = 0; const erros = [];
        for (let i = 0; i < idsUnicos.length; i += CONC) {
            const slice = idsUnicos.slice(i, i + CONC);
            await Promise.all(slice.map(async id => {
                try { await snoozeConversa(id, snoozedUntil); ok++; }
                catch (e) { erros.push({ id, erro: e.message }); }
            }));
            await new Promise(rs => setTimeout(rs, 150));
        }
        res.json({ success: true, total: idsUnicos.length, ok, falhas: erros.length, erros: erros.slice(0, 50), snoozed_until: snoozedUntil });
    } catch (e) { console.error('[adiar-casos]', e.message); res.status(500).json({ success: false, error: e.message }); }
});

// ==========================================
// 21. RELATÓRIO Q3 — PAINEL EXECUTIVO DE QUALIDADE (ADMIN, SOMENTE LEITURA)
// Lê a aba RELATORIO_Q3_2026 (as 7 seções já montadas) e devolve a matriz
// crua para o painel vivo montar as janelas. NÃO escreve em nada.
// A rota de produtos cruza os tickets sinalizados (BASE_SINALIZACOES) com o
// produto de cada conversa no Chatwoot (custom_attributes), 100% leitura.
// ==========================================
function ehAdminQ3(req) {
    const email = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    return adms.includes(email);
}
function sheetsQ3ReadOnly() {
    let privateKey = (process.env.GOOGLE_PRIVATE_KEY || '').replace(/\\n/g, '\n').replace(/"/g, '').trim();
    const auth = new google.auth.GoogleAuth({
        credentials: { client_email: (process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || '').trim(), private_key: privateKey },
        scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
    });
    return google.sheets({ version: 'v4', auth });
}

// 21.1 — Matriz do relatório Q3 (as seções prontas da planilha)
app.get('/api/q3', async (req, res) => {
    if (!ehAdminQ3(req)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
    try {
        const sheets = sheetsQ3ReadOnly();
        const sheetId = process.env.GOOGLE_SHEET_ID_QUALIDADE ? process.env.GOOGLE_SHEET_ID_QUALIDADE.trim() : '1YVu29a_MiqU73_Za_Daj7nmfMJz-phTec2gxX6VKqwk';
        // valores CRUS (UNFORMATTED) — evita o bug de % já multiplicada e médias vindo como texto
        const resp = await sheets.spreadsheets.values.get({ spreadsheetId: sheetId, range: `'RELATORIO_Q3_2026'!A1:J220`, valueRenderOption: 'UNFORMATTED_VALUE' });
        const valores = resp.data.values || [];
        // mapa analista -> time (melhor esforço, a partir da BASE DE MÉDIA)
        const times = {};
        try {
            const rt = await sheets.spreadsheets.values.get({ spreadsheetId: sheetId, range: `'BASE DE MÉDIA- SETEMBRO'!B5:C1000` });
            const norm = s => String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().trim().replace(/\s+/g, ' ');
            const timeDaCel = c => { const s = String(c || '').toUpperCase(); if (s.includes('SMS')) return 'SMS'; if (s.includes('BKO')) return 'BKO'; if (s.includes('48')) return '48H'; if (s.includes('SAC')) return 'SAC'; if (s.includes('RET')) return 'RET'; return 'OUTROS'; };
            (rt.data.values || []).forEach(r => { const n = norm(r[0]); const c = r[1]; if (n && c) times[n] = timeDaCel(c); });
        } catch (e) { console.log('[q3] times indisponivel:', e.message); }
        res.json({ success: true, valores, times });
    } catch (e) { console.error('[q3]', e.message); res.status(500).json({ success: false, error: e.message }); }
});

// 21.2 — Produtos mais reclamados: tickets sinalizados (QA) x produto no Chatwoot
app.get('/api/q3-produtos', async (req, res) => {
    if (!ehAdminQ3(req)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
    try {
        const sheets = sheetsQ3ReadOnly();
        const sheetId = process.env.GOOGLE_SHEET_ID_QUALIDADE ? process.env.GOOGLE_SHEET_ID_QUALIDADE.trim() : '1YVu29a_MiqU73_Za_Daj7nmfMJz-phTec2gxX6VKqwk';
        const resp = await sheets.spreadsheets.values.get({ spreadsheetId: sheetId, range: `'BASE_SINALIZACOES'!A1:L60000` });
        const rows = resp.data.values || [];
        // Cabeçalho: Semana | Analista | Monitoria | Ticket | Item sinalizado | Peso | Tipo | Data | Quantidade | Obs | Feedback | Mês
        const IDX_TICKET = 3, IDX_ITEM = 4;
        const sinPorTicket = {};   // display_id -> { sinalizacoes, itens:Set }
        for (let i = 3; i < rows.length; i++) {
            const r = rows[i] || [];
            const tkRaw = String(r[IDX_TICKET] || '').trim();
            const m = tkRaw.match(/\d{3,}/);
            if (!m) continue;
            const did = parseInt(m[0], 10);
            if (!sinPorTicket[did]) sinPorTicket[did] = { sinalizacoes: 0, itens: new Set() };
            sinPorTicket[did].sinalizacoes += 1;
            const item = String(r[IDX_ITEM] || '').trim();
            if (item) sinPorTicket[did].itens.add(item);
        }
        const ids = Object.keys(sinPorTicket).map(Number);
        if (!ids.length) return res.json({ success: true, produtos: [], tickets_sinalizados: 0, tickets_com_produto: 0 });

        // produto de cada ticket no Chatwoot (leitura)
        const q = `
            SELECT c.display_id,
                   COALESCE(
                     NULLIF(TRIM(c.custom_attributes->>'produtos'),''), NULLIF(TRIM(c.custom_attributes->>'produto'),''), NULLIF(TRIM(c.custom_attributes->>'Produto'),''),
                     NULLIF(TRIM(ct.custom_attributes->>'produtos'),''), NULLIF(TRIM(ct.custom_attributes->>'produto'),''), NULLIF(TRIM(ct.custom_attributes->>'Produto'),'')
                   ) AS produto
            FROM conversations c
            LEFT JOIN contacts ct ON ct.id = c.contact_id
            WHERE c.account_id = 1 AND c.display_id = ANY($1::int[])`;
        const r = await pool.query(q, [ids]);
        const prodMap = {};
        let comProduto = 0;
        r.rows.forEach(row => {
            const did = row.display_id;
            let prod = (row.produto || '').trim();
            if (!prod) return;
            prod = prod.charAt(0).toUpperCase() + prod.slice(1);
            comProduto += 1;
            const s = sinPorTicket[did] || { sinalizacoes: 1 };
            if (!prodMap[prod]) prodMap[prod] = { produto: prod, tickets: 0, sinalizacoes: 0 };
            prodMap[prod].tickets += 1;
            prodMap[prod].sinalizacoes += s.sinalizacoes;
        });
        const produtos = Object.values(prodMap).sort((a, b) => b.sinalizacoes - a.sinalizacoes);
        res.json({ success: true, produtos, tickets_sinalizados: ids.length, tickets_com_produto: comProduto });
    } catch (e) { console.error('[q3-produtos]', e.message); res.status(500).json({ success: false, error: e.message, produtos: [] }); }
});

app.listen(PORT, () => console.log(`🚀 Servidor rodando na porta ${PORT}`));

// F: warmer — a cada 15min, se houve acesso REAL recente (<=20min), revalida em background as rotas pesadas
// do Postgres (escalonado, 1 por vez). Se ninguem usou o Dash, nao roda (aguarda) — nao toca no Chatwoot.
const ROTAS_WARM = ['/api/resumo-recorrencia', '/api/produtividade']; // /api/time48, Produtos e Menções saíram do aquecedor (01/10/2026): carregam 1x no acesso e depois só pelo 🔄 Atualizar
function aquecerRota(rota) {
    return new Promise((resolve) => {
        const rq = http.get({ host: '127.0.0.1', port: PORT, path: rota + '?fresh=1', headers: { 'x-warm-token': WARM_TOKEN } }, (r) => { r.resume(); r.on('end', resolve); });
        rq.on('error', () => resolve());
        rq.setTimeout(30000, () => { try { rq.destroy(); } catch (e) {} resolve(); });
    });
}
setInterval(async () => {
    if (Date.now() - ultimoAcessoApi > 20 * 60 * 1000) return; // ninguem usando o Dash -> aguarda
    for (const rota of ROTAS_WARM) {
        if (pool.waitingCount > 0 || Date.now() < FREIO.ate) break;   // 🛡️ banco ocupado (fila) ou com freio: pula esta rodada
        await aquecerRota(rota);
        await new Promise(r => setTimeout(r, 800)); // escalona pra nao criar rajada no Postgres
    }
}, 15 * 60 * 1000);

// ==========================================
// 17. 🤖 BOT DO TELEGRAM — avisos 🟡/🔴 por turno, comandos e relatórios (roda dentro do Dash)
// Só liga se a variável TELEGRAM_TOKEN existir. Fala com o Telegram pelo fetch nativo do Node (sem biblioteca nova).
// Casos: a MESMA rota do Status de Casos (/api/distribuicao), chamada por dentro com o token interno (números iguais aos do Dash).
// Guarda vínculos, comandos, envios, cientes, configuração e a foto diária na planilha de log do Adiar Casos (abas tg_*).
// ==========================================
const TG_TOKEN = (process.env.TELEGRAM_TOKEN || '').trim();
const TG_FUSO = 'America/Sao_Paulo';
const TG_URL_CASO = (id) => `https://chat.institutoexperience.com/app/accounts/1/conversations/${encodeURIComponent(id)}`;
const TG_TURNOS = {
    '7':  { ini: 7 * 60,  fim: 16 * 60, rotulo: '7h às 16h' },
    '9':  { ini: 9 * 60,  fim: 18 * 60, rotulo: '9h às 18h' },
    '15': { ini: 15 * 60, fim: 24 * 60, rotulo: '15h às 00h' }
};
const TG_CAB = {
    tg_vinculos: ['chat_id', 'nome_telegram', 'usuario_telegram', 'agente_id', 'agente_chatwoot', 'papel', 'turno', 'status', 'criado_em', 'atualizado_em', 'por'],
    tg_comandos: ['data_hora', 'chat_id', 'nome_telegram', 'agente', 'comando', 'parametros', 'resultado', 'ms'],
    tg_envios:   ['envio_id', 'data_hora', 'tipo', 'chat_id', 'destino', 'papel', 'turno', 'casos', 'entregue', 'erro', 'message_id'],
    tg_cientes:  ['envio_id', 'chat_id', 'destino', 'ciente_em'],
    tg_config:   ['chave', 'valor'],
    tg_fotos:    ['data', 'hora', 'time', 'sem_agente', 'em_aberto', 'retornos', 'aguardando', 'fora_sla', 'total']
};
const TG_CONFIG_PADRAO = {
    avisos: 'sim',              // 🟡 24h e 🔴 48h dentro do turno
    resumo_inicio: 'sim',       // resumo no começo do turno
    so_com_pendencia: 'sim',    // resumo do começo só para quem tem 🔴/🟡
    lembrete_fim: 'sim',        // lembrete 30 min antes do fim do turno
    visao_lider: 'sim',         // visão do turno para o líder ao começar
    relatorio_diario: 'sim',    // Leo e Tati: todo dia
    relatorio_semanal: 'sim',   // Leo e Tati: segunda
    hora_relatorio: '8',
    meta_semana: '400'
};
const TG_TIPOS_CIENTE = ['aviso_24h', 'aviso_48h', 'escalonamento', 'resumo_inicio', 'lembrete_fim', 'visao_lider', 'teste'];
// Equipe por turno (lista do Gabriel, 05/10/2026). LogiCall fica fora do bot. Serve só para SUGERIR o turno ao vincular.
const TG_EQUIPE = [
    ['Giovanna De Oliveira Lira', 'SAC', '7'], ['Mariana Xavier', 'SAC', '7'], ['Maria Eduarda Theodoro Rodrigues', '48H', '7'],
    ['Xaiane Giselen Dias Celestino', 'SAC', '7'], ['Giovana Souza', 'SAC', '7'], ['Rebeca Araujo da Silva', 'SMS', '7'],
    ['Antônia Keuliane Sales Moura', 'SMS', '7'], ['Karla de Assis Santos', 'RET', '7'], ['Ellen Santos Medeiros', 'RET', '7'],
    ['Igor Gustavo Ferreira da Silva', 'RET', '7'], ['Luana Silva Barbosa Sousa', 'RET', '7'], ['Humberto Pereira de Souza', 'RET', '7'],
    ['Mariana Alves Cardoso', 'RET', '7'], ['Rebeca Carmo de Souza', 'RET', '7'], ['Thauane Garcia', '48H', '7'],
    ['Fernanda da Silva Pires Campos', 'BKO', '7'], ['Paula Araujo', 'BKO', '7'],
    ['Susana Garcia de Barros', 'SAC', '9'], ['Rafaela França', 'SAC', '9'], ['Lucas Gomes Azeredo', 'SAC', '9'],
    ['Ariane Isabela Akutsu da Silva', 'SAC', '9'], ['Ana Godinho', 'SMS', '9'], ['Bruno Cordeiro de Lima', 'SMS', '9'],
    ['Lucas Andrade', 'RET', '9'], ['Aline Maria de Oliveira Martins', 'RET', '9'], ['Luiza Vanessa de Oliveira Cavalcante', 'RET', '9'],
    ['Raíssa Coelho de Araújo Mesel', 'RET', '9'], ['Daniel Xavier Martins', 'RET', '9'], ['Thais de Freitas Santos Fadino', 'RET', '9'],
    ['Wanya Santos Silva', 'RET', '9'], ['Veronica Paiva de Oliveira', 'RET', '9'], ['Graziela Donini', 'RET', '9'],
    ['Willian Felipe Barros Dos Santos', 'RET', '9'], ['Patrícia Figueredo de Jesus Maia', 'RET', '9'], ['Lavínia Maia Batista Boaventura', 'RET', '9'],
    ['Alexandre Alves Gonçalves Filho', '48H', '9'], ['Daryson Matheus Nascimento', '48H', '9'], ['Giovana Ferreira Feitosa', 'BKO', '9'],
    ['Maria Dolores Pereira de Moura', 'BKO', '9'], ['Barbara Ferreira', 'RET', '9'],
    ['Maryana Ribeiro do Prado Peres', 'SAC', '15'], ['Bianca Silva Da Cruz', 'SAC', '15'], ['Agatha Ribeiro dos Santos Cezar', 'RET', '15'],
    ['Keroline Valeria Alves', 'RET', '15'], ['Gabriela Caroline Andrade da Penha', '48H', '15'], ['Bruno Régis da Silva', '48H', '15'],
    ['Simone Maria da Silva', 'RET', '15'], ['Dayane', 'RET', '15'], ['Rayssa', 'RET', '15'], ['José Carlos', 'RET', '15'],
    ['Juan', 'RET', '15'], ['Henrique', 'RET', '15'], ['Tharyck', 'RET', '15'], ['Jéssica', 'SAC', '15'],
    ['Miriam', 'SAC', '15'], ['Thaylle', 'SAC', '15'], ['Ana Paula', 'SAC', '15']
];
// Líderes acompanham o próprio turno; supervisor e gerente recebem só os relatórios diário e semanal
const TG_GESTORES = [
    ['Camila Moura', 'lider', '7'], ['Flavia Lira', 'lider', '9'], ['Adevânia Silva', 'lider', '15'],
    ['Leonardo Alves', 'diretoria', ''], ['Tatiana Carmo', 'diretoria', '']
];
const TG_COMANDOS = [
    { cmd: 'casos',     quem: 'agente', desc: 'Seus casos por status (🔴 🟡 🟢 🔵), com o link dos 🔴 e 🟡', fonte: 'Status de Casos (mesma regra do Dash)' },
    { cmd: 'sla',       quem: 'agente', desc: 'Só os casos 🟡 e 🔴, do mais antigo para o mais novo', fonte: 'Status de Casos' },
    { cmd: 'eu',        quem: 'agente', desc: 'Suas mensagens da semana × meta, dia a dia', fonte: 'Mensagens enviadas (mesma regra do Tickets Atual do Dash)' },
    { cmd: 'hoje',      quem: 'agente', desc: 'Seu dia: mensagens de hoje + casos por status', fonte: 'Tickets Atual + Status de Casos' },
    { cmd: 'time',      quem: 'gestor', desc: 'O time por status e quem tem 🔴 (ex.: /time RET). Sem sigla: o seu turno', fonte: 'Status de Casos' },
    { cmd: 'fila',      quem: 'gestor', desc: 'Casos sem agente, por time', fonte: 'Status de Casos' },
    { cmd: 'relatorio', quem: 'gestor', desc: 'Relatório de Casos de hoje (mesmo formato do WhatsApp)', fonte: 'Status de Casos + Time 48H' },
    { cmd: 'ajuda',     quem: 'todos',  desc: 'Lista dos comandos', fonte: '—' },
    { cmd: 'start',     quem: 'todos',  desc: 'Pede o vínculo com o bot (aparece no Dash para aprovar)', fonte: '—' }
];
const TG_SIGLAS = ['SAC', 'RET', 'BKO', 'SMS', '48H'];

const tgBot = {
    ligado: false, usuario: '', nome: '', offset: 0, ultimoPoll: 0, ultimoErro: '', erroEm: 0, erroSeguido: 0, iniciadoEm: Date.now(),
    planilhaOk: false, carregado: false, abasOk: false,
    vinculos: [], config: Object.assign({}, TG_CONFIG_PADRAO), comandos: [], envios: [], cientes: [], fotos: [],
    avisados: new Map(),   // `${chat}|${caso}|${faixa}` -> ms (caso já avisado nessa faixa)
    marcos: new Set(),     // `${tipo}|${chat}|${data}` -> envio agendado do dia já feito
    fila: { tg_comandos: [], tg_envios: [], tg_cientes: [], tg_fotos: [] },
    snap: null, snapEm: 0, snapPromessa: null, ultCmd: {}, ultimaRodada: 0, rodando: false, gravando: false, usuariosCw: null, usuariosCwEm: 0
};

// ---------- utilidades ----------
const tgEsc = (s) => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const tgSemAcento = (s) => String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toUpperCase();
const tgEsperar = (ms) => new Promise(r => setTimeout(r, ms));
function tgAgoraBR(d) {
    const p = {};
    new Intl.DateTimeFormat('en-GB', { timeZone: TG_FUSO, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', weekday: 'short', hourCycle: 'h23' })
        .formatToParts(d || new Date()).forEach(x => { p[x.type] = x.value; });
    const hora = parseInt(p.hour, 10) % 24, min = parseInt(p.minute, 10);
    const dows = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
    const hh = String(hora).padStart(2, '0');
    return { data: `${p.year}-${p.month}-${p.day}`, hora, min, minutos: hora * 60 + min, dow: dows[p.weekday], texto: `${p.year}-${p.month}-${p.day} ${hh}:${p.minute}:${p.second}`, hhmm: `${hh}:${p.minute}` };
}
function tgSomarDias(dataStr, n) { const [a, m, d] = dataStr.split('-').map(Number); const x = new Date(Date.UTC(a, m - 1, d + n)); return x.toISOString().slice(0, 10); }
const tgUnixIni = (dataStr) => { const [a, m, d] = dataStr.split('-').map(Number); return Date.UTC(a, m - 1, d, 3, 0, 0) / 1000; };   // 00:00 de Brasília
const tgUnixFim = (dataStr) => tgUnixIni(dataStr) + 86399;                                                                          // 23:59:59 de Brasília
const tgDM = (dataStr) => { const p = String(dataStr || '').slice(0, 10).split('-'); return p.length === 3 ? `${p[2]}/${p[1]}` : String(dataStr || ''); };
const tgMsBR = (txt) => { const t = String(txt || ''); const m = t.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/); return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4] + 3, +m[5], +(m[6] || 0)) : NaN; };
function tgNoTurno(turno, a) { const t = TG_TURNOS[String(turno)]; return !!t && a.minutos >= t.ini && a.minutos < t.fim; }
function tgFaixa(status) { const s = String(status || ''); return s.includes('Fora do SLA') ? '48' : (s.includes('Aguardando') ? '24' : ''); }
function tgChaveAgente(nome) {   // mesma regra de nome do Status de Casos: "NOME - SIGLA" em maiúsculas
    const n = String(nome || '').toUpperCase();
    const m = n.match(/[\s\-]+(RET|SAC|BKO|SMS|48H)\b/);
    if (!m) return n.trim();
    return n.replace(/[\s\-]+(RET|SAC|BKO|SMS|48H)\b.*$/, '').trim() + ' - ' + m[1];
}
const tgSigla = (chave) => { const m = String(chave || '').match(/ - (RET|SAC|BKO|SMS|48H)$/); return m ? m[1] : ''; };
const tgNomeBonito = (chave) => String(chave || '').replace(/ - (RET|SAC|BKO|SMS|48H)$/, '').toLowerCase().replace(/(^|\s)\S/g, x => x.toUpperCase());
const tgPrimeiroNome = (v) => String((v && (v.agente_chatwoot || v.nome_telegram)) || '').split(/[\s\-]+/)[0] || '';
function tgEhAdmin(req) {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    const donosTg = (process.env.EMAILS_TELEGRAM || 'maurilio.silva@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());   // 🔒 painel do bot: só o(s) dono(s) (07/10/2026)
    return (adms.includes(emailUser) && donosTg.includes(emailUser)) ? emailUser : '';
}
function tgGetInterno(caminho, timeoutMs) {   // chama uma rota do próprio Dash (como o aquecedor): mesma lógica, mesmos números
    return new Promise((resolve) => {
        const rq = http.get({ host: '127.0.0.1', port: PORT, path: caminho + (caminho.includes('?') ? '&' : '?') + 'fresh=1', headers: { 'x-warm-token': WARM_TOKEN } }, (r) => {
            let b = ''; r.setEncoding('utf8'); r.on('data', c => { b += c; });
            r.on('end', () => { try { resolve(JSON.parse(b)); } catch (e) { resolve(null); } });
        });
        rq.on('error', () => resolve(null));
        rq.setTimeout(timeoutMs || 60000, () => { try { rq.destroy(); } catch (e) {} resolve(null); });
    });
}

// ---------- planilha (abas tg_* na planilha de log) ----------
function tgSheets() {
    if (!process.env.GOOGLE_PRIVATE_KEY || !process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL) return null;
    try { return getSheetsRW(); } catch (e) { return null; }
}
async function tgGarantirAbas(sheets) {
    if (tgBot.abasOk) return true;
    const meta = await sheets.spreadsheets.get({ spreadsheetId: SNOOZE_SHEET_ID, fields: 'sheets.properties.title' });
    const existentes = new Set(((meta.data && meta.data.sheets) || []).map(s => s.properties.title));
    const faltam = Object.keys(TG_CAB).filter(a => !existentes.has(a));
    if (faltam.length) {
        await sheets.spreadsheets.batchUpdate({ spreadsheetId: SNOOZE_SHEET_ID, requestBody: { requests: faltam.map(t => ({ addSheet: { properties: { title: t } } })) } });
    }
    for (const aba of Object.keys(TG_CAB)) {
        const r = await sheets.spreadsheets.values.get({ spreadsheetId: SNOOZE_SHEET_ID, range: `${aba}!A1:K1` });
        if (!r.data.values || !r.data.values.length) {
            await sheets.spreadsheets.values.update({ spreadsheetId: SNOOZE_SHEET_ID, range: `${aba}!A1`, valueInputOption: 'RAW', requestBody: { values: [TG_CAB[aba]] } });
        }
    }
    tgBot.abasOk = true;
    return true;
}
async function tgLerAba(sheets, aba) {
    const r = await sheets.spreadsheets.values.get({ spreadsheetId: SNOOZE_SHEET_ID, range: `${aba}!A2:K` });
    const cab = TG_CAB[aba];
    return (r.data.values || []).filter(l => l && l.some(v => v !== '' && v != null)).map(l => { const o = {}; cab.forEach((k, i) => { o[k] = l[i] != null ? String(l[i]) : ''; }); return o; });
}
async function tgReescreverAba(aba, linhas) {   // vínculos e configuração: poucas linhas, regrava a aba inteira
    const sheets = tgSheets();
    if (!sheets) return false;
    try {
        await tgGarantirAbas(sheets);
        await sheets.spreadsheets.values.clear({ spreadsheetId: SNOOZE_SHEET_ID, range: `${aba}!A2:K` });
        if (linhas.length) {
            await sheets.spreadsheets.values.update({ spreadsheetId: SNOOZE_SHEET_ID, range: `${aba}!A2`, valueInputOption: 'RAW', requestBody: { values: linhas.map(o => TG_CAB[aba].map(k => o[k] != null ? String(o[k]) : '')) } });
        }
        tgBot.planilhaOk = true;
        return true;
    } catch (e) { console.error(`[telegram] falha ao gravar ${aba}:`, e.message); tgBot.planilhaOk = false; return false; }
}
const tgSalvarVinculos = () => tgReescreverAba('tg_vinculos', tgBot.vinculos);
const tgSalvarConfig = () => tgReescreverAba('tg_config', Object.keys(tgBot.config).map(k => ({ chave: k, valor: tgBot.config[k] })));
function tgEnfileirar(aba, obj) { tgBot.fila[aba].push(TG_CAB[aba].map(k => obj[k] != null ? String(obj[k]) : '')); }
async function tgGravarFila() {   // logs vão em lote (o Google limita gravações por minuto)
    if (tgBot.gravando) return;
    const temAlgo = Object.keys(tgBot.fila).some(a => tgBot.fila[a].length);
    if (!temAlgo) return;
    const sheets = tgSheets();
    if (!sheets) { Object.keys(tgBot.fila).forEach(a => { if (tgBot.fila[a].length > 5000) tgBot.fila[a].splice(0, tgBot.fila[a].length - 5000); }); return; }
    tgBot.gravando = true;
    try {
        await tgGarantirAbas(sheets);
        for (const aba of Object.keys(tgBot.fila)) {
            const lote = tgBot.fila[aba].slice(0, 500);
            if (!lote.length) continue;
            await sheets.spreadsheets.values.append({ spreadsheetId: SNOOZE_SHEET_ID, range: `${aba}!A:K`, valueInputOption: 'RAW', insertDataOption: 'INSERT_ROWS', requestBody: { values: lote } });
            tgBot.fila[aba].splice(0, lote.length);
        }
        tgBot.planilhaOk = true;
    } catch (e) { console.error('[telegram] falha ao gravar o log na planilha (tenta de novo em 30s):', e.message); tgBot.planilhaOk = false; }
    finally { tgBot.gravando = false; }
}
async function tgCarregarPlanilha() {
    const sheets = tgSheets();
    if (!sheets) { console.warn('[telegram] sem credenciais do Google: vínculos e logs ficam só na memória até reiniciar'); tgBot.carregado = true; return; }
    try {
        await tgGarantirAbas(sheets);
        const [vinc, conf, envios, cientes, comandos, fotos] = await Promise.all(['tg_vinculos', 'tg_config', 'tg_envios', 'tg_cientes', 'tg_comandos', 'tg_fotos'].map(a => tgLerAba(sheets, a)));
        tgBot.vinculos = vinc.filter(v => v.chat_id);
        conf.forEach(c => { if (c.chave) tgBot.config[c.chave] = c.valor; });
        const limite = Date.now() - 120 * 24 * 3600 * 1000;   // memória: últimos 120 dias (a planilha guarda tudo)
        tgBot.envios = envios.filter(e => (tgMsBR(e.data_hora) || 0) >= limite);
        tgBot.cientes = cientes.filter(c => (tgMsBR(c.ciente_em) || 0) >= limite);
        tgBot.comandos = comandos.filter(c => (tgMsBR(c.data_hora) || 0) >= limite);
        tgBot.fotos = fotos.filter(f => (tgMsBR(`${f.data} ${f.hora || '00:00'}`) || 0) >= limite);
        // Reconstrói o que já foi enviado (sem repetir aviso nem resumo depois de reiniciar)
        const tres = Date.now() - 3 * 24 * 3600 * 1000;
        tgBot.envios.forEach(e => {
            const ms = tgMsBR(e.data_hora) || 0;
            if (e.entregue === 'sim' && e.tipo && e.chat_id) tgBot.marcos.add(`${e.tipo}|${e.chat_id}|${String(e.data_hora).slice(0, 10)}`);   // envio agendado do dia já feito
            if (ms >= tres && e.entregue === 'sim' && ['aviso_24h', 'aviso_48h', 'resumo_inicio', 'lembrete_fim'].includes(e.tipo)) {
                String(e.casos || '').split(/\s+/).filter(Boolean).forEach(c => { const [id, fx] = c.split(':'); if (id && fx) tgBot.avisados.set(`${e.chat_id}|${id}|${fx}`, ms); });
            }
        });
        tgBot.fotos.forEach(f => tgBot.marcos.add(`foto|-|${f.data}`));
        tgBot.planilhaOk = true;
        console.log(`[telegram] planilha carregada: ${tgBot.vinculos.length} vínculos, ${tgBot.envios.length} envios, ${tgBot.comandos.length} comandos`);
    } catch (e) { console.error('[telegram] não consegui ler a planilha de log:', e.message); tgBot.planilhaOk = false; }
    tgBot.carregado = true;
}

// ---------- Telegram ----------
async function tgApi(metodo, corpo, timeoutMs) {
    if (!TG_TOKEN) return { ok: false, description: 'TELEGRAM_TOKEN ausente' };
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs || 15000);
    try {
        const r = await fetch(`https://api.telegram.org/bot${TG_TOKEN}/${metodo}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(corpo || {}), signal: ctl.signal });
        return await r.json().catch(() => ({ ok: false, error_code: r.status, description: `HTTP ${r.status}` }));
    } catch (e) { return { ok: false, description: e.name === 'AbortError' ? 'tempo esgotado' : e.message }; }
    finally { clearTimeout(t); }
}
const tgIdEnvio = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
// Envio "proativo" (aviso, resumo, relatório, teste): vai para a aba tg_envios — é o que a sub-aba Entregas & Leitura mostra
async function tgEnviar(destino, texto, meta) {
    meta = meta || {};
    const envioId = tgIdEnvio();
    const corpo = { chat_id: destino.chat_id, text: String(texto).slice(0, 4090), parse_mode: 'HTML', disable_web_page_preview: true };
    if (TG_TIPOS_CIENTE.includes(meta.tipo)) corpo.reply_markup = { inline_keyboard: [[{ text: '✅ Ciente', callback_data: `ok:${envioId}` }]] };
    const r = await tgApi('sendMessage', corpo);
    const linha = {
        envio_id: envioId, data_hora: tgAgoraBR().texto, tipo: meta.tipo || 'outro', chat_id: String(destino.chat_id),
        destino: destino.agente_chatwoot || destino.nome_telegram || '', papel: destino.papel || '', turno: destino.turno || '',
        casos: (meta.casos || []).join(' '), entregue: r.ok ? 'sim' : 'não', erro: r.ok ? '' : String(r.description || 'erro'),
        message_id: (r.ok && r.result) ? String(r.result.message_id) : ''
    };
    tgBot.envios.push(linha); tgEnfileirar('tg_envios', linha);
    if (r.ok && meta.tipo) tgBot.marcos.add(`${meta.tipo}|${destino.chat_id}|${linha.data_hora.slice(0, 10)}`);
    return r;
}
async function tgResponder(chatId, texto) { return tgApi('sendMessage', { chat_id: chatId, text: String(texto).slice(0, 4090), parse_mode: 'HTML', disable_web_page_preview: true }); }

// ---------- dados: Status de Casos (mesma rota do Dash) ----------
async function tgSnapshot(maxIdadeMs) {
    const idadeSnap = Date.now() - tgBot.snapEm;
    if (tgBot.snap && idadeSnap >= 0 && idadeSnap < (maxIdadeMs || 120000)) return tgBot.snap;
    if (tgBot.snapPromessa) return tgBot.snapPromessa;
    tgBot.snapPromessa = (async () => {
        const d = await tgGetInterno('/api/distribuicao', 90000);
        if (d && d.success && Array.isArray(d.casos)) { tgBot.snap = d; tgBot.snapEm = Date.now(); }
        const idade = Date.now() - tgBot.snapEm;
        return tgBot.snap && idade >= 0 && idade < 30 * 60 * 1000 ? tgBot.snap : null;
    })();
    try { return await tgBot.snapPromessa; } finally { tgBot.snapPromessa = null; }
}
function tgEntradaDoAgente(snap, v) {
    if (!snap || !v || !v.agente_chatwoot) return null;
    const chave = tgChaveAgente(v.agente_chatwoot);
    return (snap.casos || []).find(c => c.nome === chave) || { nome: chave, em_aberto: 0, retornos: 0, aguardando: 0, fora_sla: 0, total: 0, detalhes: [] };
}
const tgOrdenaHoras = (a, b) => (b.horas_parado || 0) - (a.horas_parado || 0);
function tgListaCasos(detalhes, faixa, limite) {
    const l = (detalhes || []).filter(d => tgFaixa(d.status) === faixa).sort(tgOrdenaHoras);
    const linhas = l.slice(0, limite || 20).map(d => `• <a href="${TG_URL_CASO(d.id)}">#${tgEsc(d.id)}</a> — ${d.horas_parado}h esperando`);
    if (l.length > (limite || 20)) linhas.push(`<i>… e mais ${l.length - (limite || 20)}</i>`);
    return linhas.join('\n');
}
const tgContagem = (e) => `🔴 <b>${e.fora_sla || 0}</b> · 🟡 <b>${e.aguardando || 0}</b> · 🟢 <b>${e.retornos || 0}</b> · 🔵 <b>${e.em_aberto || 0}</b>`;
const tgCasosFaixa = (e, faixa) => ((e && e.detalhes) || []).filter(d => tgFaixa(d.status) === faixa);

// ---------- mensagens por agente (mesma regra da Produtividade) ----------
async function tgMensagensPorDia(v, ini, fim) {
    const params = [ini, fim];
    let filtro;
    if (v.agente_id) { params.push(parseInt(v.agente_id, 10)); filtro = 'm.sender_id = $3'; }
    else { params.push(String(v.agente_chatwoot || '')); filtro = 'UPPER(u.name) = UPPER($3)'; }
    const r = await pool.query(`
        SELECT TO_CHAR(m.created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo', 'YYYY-MM-DD') AS dia, COUNT(*)::int AS msgs
        FROM messages m
        INNER JOIN users u ON u.id = m.sender_id
        WHERE m.account_id = 1
          AND m.sender_type = 'User'
          AND m.message_type = 1
          AND m.private = FALSE
          AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE
          AND m.content IS NOT NULL   -- mesma regra do Tickets Atual do Dash (mensagem sem texto, como anexo sozinho, não conta)
          AND m.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
          AND m.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
          AND ${filtro}
        GROUP BY 1 ORDER BY 1`, params);
    const porDia = {}; r.rows.forEach(x => { porDia[x.dia] = x.msgs; });
    return porDia;
}
async function tgMensagensPorAgente(ini, fim) {   // semana: mensagens por agente (para o relatório semanal)
    const r = await pool.query(`
        SELECT u.name AS agente, COUNT(*)::int AS msgs
        FROM messages m
        INNER JOIN users u ON u.id = m.sender_id
        WHERE m.account_id = 1
          AND m.sender_type = 'User'
          AND m.message_type = 1
          AND m.private = FALSE
          AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE
          AND m.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
          AND m.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
        GROUP BY u.name`, [ini, fim]);
    return r.rows;
}
async function tgUsuariosChatwoot() {
    const idadeUs = Date.now() - tgBot.usuariosCwEm;
    if (tgBot.usuariosCw && idadeUs >= 0 && idadeUs < 10 * 60 * 1000) return tgBot.usuariosCw;
    const r = await pool.query(`SELECT id, name FROM users ORDER BY name`);
    tgBot.usuariosCw = r.rows.map(x => ({ id: String(x.id), name: x.name }));
    tgBot.usuariosCwEm = Date.now();
    return tgBot.usuariosCw;
}

// ---------- sugestões ao vincular (o admin confirma no Dash) ----------
const tgTokens = (s) => tgSemAcento(String(s || '').replace(/ - (RET|SAC|BKO|SMS|48H|LD)\b.*$/i, '')).split(/[^A-Z]+/).filter(t => t.length > 1 && !['DA', 'DE', 'DO', 'DOS', 'DAS', 'E'].includes(t));
function tgSugerirTurno(nomeChatwoot) {
    const tk = tgTokens(nomeChatwoot); if (!tk.length) return null;
    const sigla = (String(nomeChatwoot || '').toUpperCase().match(/ - (RET|SAC|BKO|SMS|48H)\b/) || [])[1] || '';
    for (const [nome, papel, turno] of TG_GESTORES) { const g = tgTokens(nome); if (g[0] === tk[0] && tk.slice(1).every(t => g.includes(t))) return { papel, turno, origem: nome }; }
    const cand = TG_EQUIPE.filter(([nome]) => { const e = tgTokens(nome); return e[0] === tk[0] && tk.slice(1).every(t => e.includes(t)); });
    const mesmaSigla = cand.filter(c => c[1] === sigla);
    const escolha = (mesmaSigla.length === 1 ? mesmaSigla[0] : (cand.length === 1 ? cand[0] : null));
    return escolha ? { papel: 'agente', turno: escolha[2], origem: escolha[0] } : null;
}
function tgSugerirAgente(nomeTelegram, usuarios) {
    const tk = tgTokens(nomeTelegram); if (!tk.length) return null;
    let melhor = null, pontos = 0, empate = false;
    (usuarios || []).forEach(u => {
        const ut = tgTokens(u.name); if (ut[0] !== tk[0]) return;
        const p = 1 + tk.slice(1).filter(t => ut.includes(t)).length;
        if (p > pontos) { melhor = u; pontos = p; empate = false; } else if (p === pontos) empate = true;
    });
    return (melhor && !empate) ? melhor : null;
}

// ---------- relatórios ----------
function tgTempo(min) { min = Number(min); if (!min || isNaN(min)) return '-'; const t = Math.round(min); if (t < 60) return t + ' min'; return `${Math.floor(t / 60)}h ${t % 60}m`; }   // arredonda antes de separar (evita "4h 60m")
const tgPct = (a, b) => b ? (a / b * 100).toFixed(1).replace('.', ',') + '%' : '0%';
function tgResumoTimes(snap) {   // mesma conta do Relatório de Casos: por time, sem agente / com agente / fora do SLA
    const r = {}; TG_SIGLAS.forEach(s => { r[s] = { sem: 0, com: 0, fora: 0, em_aberto: 0, retornos: 0, aguardando: 0, total: 0, agentes: [] }; });
    (snap.casos || []).forEach(e => {
        const s = tgSigla(e.nome); if (!r[s]) return;
        const semAg = e.nome.startsWith('SEM ATRIBUIR');
        if (semAg) r[s].sem += e.total || 0; else { r[s].com += e.total || 0; r[s].agentes.push(e); }
        r[s].fora += e.fora_sla || 0; r[s].em_aberto += e.em_aberto || 0; r[s].retornos += e.retornos || 0; r[s].aguardando += e.aguardando || 0; r[s].total += e.total || 0;
    });
    return r;
}
async function tgDesempenho48(ini, fim) {
    const d = await tgGetInterno(`/api/time48-atendimento?since=${tgUnixIni(ini)}&until=${tgUnixFim(fim)}&so_time=1`, 120000);
    if (!d || !d.success) return null;
    let tks = 0, rets = 0, msgs = 0, tmcW = 0, tmrW = 0;
    (d.dados || []).forEach(x => { const t = parseInt(x.tickets) || 0; tks += t; rets += parseInt(x.retornos) || 0; msgs += parseInt(x.mensagens) || 0; tmcW += (parseFloat(x.tmc_medio_minutos) || 0) * t; tmrW += (parseFloat(x.tmr_medio_minutos) || 0) * t; });
    const r = d.resumo || {};   // tickets e retornos sem repetir ticket, como nos cards da Visão Geral do Dash
    return { tickets: r.tickets != null ? r.tickets : tks, retornos: r.retornos != null ? r.retornos : rets, mensagens: r.mensagens != null ? r.mensagens : msgs, tmc: tks ? tmcW / tks : 0, tmr: tks ? tmrW / tks : 0 };
}
function tgResumoBot(ini, fim) {   // como o bot rodou no período: avisos, entregas e ✅ Ciente (por turno)
    const dentro = (txt) => { const d = String(txt || '').slice(0, 10); return d >= ini && d <= fim; };
    const env = tgBot.envios.filter(e => dentro(e.data_hora));
    const cienteDe = {}; tgBot.cientes.forEach(c => { if (!cienteDe[c.envio_id]) cienteDe[c.envio_id] = c; });
    const comBotao = env.filter(e => TG_TIPOS_CIENTE.includes(e.tipo) && e.tipo !== 'teste' && e.entregue === 'sim');
    const cientes = comBotao.filter(e => cienteDe[e.envio_id]);
    const tempos = cientes.map(e => (tgMsBR(cienteDe[e.envio_id].ciente_em) - tgMsBR(e.data_hora)) / 60000).filter(x => x >= 0);
    const porTurno = {};
    Object.keys(TG_TURNOS).forEach(t => {
        const cb = comBotao.filter(e => e.turno === t), ci = cb.filter(e => cienteDe[e.envio_id]);
        porTurno[t] = { avisos48: env.filter(e => e.tipo === 'aviso_48h' && e.turno === t).reduce((s, e) => s + String(e.casos || '').split(/\s+/).filter(Boolean).length, 0), comBotao: cb.length, cientes: ci.length };
    });
    return {
        casos48: env.filter(e => e.tipo === 'aviso_48h').reduce((s, e) => s + String(e.casos || '').split(/\s+/).filter(Boolean).length, 0),
        casos24: env.filter(e => e.tipo === 'aviso_24h').reduce((s, e) => s + String(e.casos || '').split(/\s+/).filter(Boolean).length, 0),
        escalonamentos: env.filter(e => e.tipo === 'escalonamento').length,
        falhas: env.filter(e => e.entregue !== 'sim').length,
        comBotao: comBotao.length, cientes: cientes.length,
        tempoMedio: tempos.length ? tempos.reduce((a, b) => a + b, 0) / tempos.length : 0,
        porTurno
    };
}
async function tgRelatorioCasos(ini, fim, titulo, comBot) {
    const snap = await tgSnapshot(60000);
    if (!snap) return '⚠️ Não consegui ler o Status de Casos agora. Tente de novo em alguns minutos.';
    const t = tgResumoTimes(snap), h = t['48H'];
    const lin = (k) => `SAC: ${t.SAC[k]} | RET: ${t.RET[k]} | SMS: ${t.SMS[k]} | 48H: ${t['48H'][k]}`;
    const ag48 = h.agentes.slice().sort((a, b) => (b.total || 0) - (a.total || 0)).slice(0, 12).map(e => `• ${tgEsc(tgNomeBonito(e.nome))}: ${e.total}`).join('\n');
    const d48 = await tgDesempenho48(ini, fim);
    let txt = `📊 <b>${tgEsc(titulo)}</b>\n\n<b>Sem agente</b>\n${lin('sem')}\n\n<b>Com agente</b>\n${lin('com')}\n\n<b>Fora do SLA de até 48H</b>\nSAC: ${t.SAC.fora} | RET: ${t.RET.fora} | SMS: ${t.SMS.fora} | Time 48H: ${h.fora}\n\n`;
    txt += `⏳ <b>TIME 48H</b>\n\n<b>Status de Casos:</b> ${h.total}\nSem agente: ${h.sem} | Com agente: ${h.com}\nEm aberto: ${h.em_aberto} | Até 24h: ${h.retornos} | 24–48h: ${h.aguardando} | Fora do SLA: ${h.fora}\n\n<b>Por agente</b>\n${ag48 || '• —'}\n\n`;
    const per = ini === fim ? tgDM(ini) : `${tgDM(ini)} a ${tgDM(fim)}`;
    if (d48) txt += `📈 <b>DESEMPENHO DO TIME 48H — tickets atendidos ${ini === fim ? 'em' : 'de'} ${per}</b>\n\nTickets atendidos: <b>${d48.tickets}</b>\nRetornos (cliente voltou após a resposta): <b>${d48.retornos} (${tgPct(d48.retornos, d48.tickets)})</b>\nMensagens enviadas pelos agentes: <b>${d48.mensagens}</b>\nTMC (1º contato do agente): <b>${tgTempo(d48.tmc)}</b>\nTMR (tempo médio de resposta): <b>${tgTempo(d48.tmr)}</b>`;
    else txt += `📈 <i>Desempenho do Time 48H indisponível agora.</i>`;
    if (comBot) {
        const b = tgResumoBot(ini, fim);
        const pt = Object.keys(TG_TURNOS).map(k => `${TG_TURNOS[k].rotulo}: 🔴 ${b.porTurno[k].avisos48} · ✅ ${tgPct(b.porTurno[k].cientes, b.porTurno[k].comBotao)}`).join('\n');
        txt += `\n\n🤖 <b>BOT (${per})</b>\n🔴 casos avisados: <b>${b.casos48}</b> · 🟡 <b>${b.casos24}</b> · escalonados ao líder: <b>${b.escalonamentos}</b>\n✅ Ciente: <b>${tgPct(b.cientes, b.comBotao)}</b> · tempo médio até confirmar: <b>${tgTempo(b.tempoMedio)}</b>${b.falhas ? `\n⚠️ Mensagens que não chegaram: <b>${b.falhas}</b>` : ''}\n${pt}`;
    }
    return txt;
}
async function tgRelatorioSemanal(seg) {   // seg = segunda da semana que fechou
    const dom = tgSomarDias(seg, 6), segAnt = tgSomarDias(seg, -7), domAnt = tgSomarDias(seg, -1);
    const [atual, ant] = await Promise.all([tgMensagensPorAgente(seg, dom), tgMensagensPorAgente(segAnt, domAnt)]);
    const porTime = (rows) => { const o = {}; TG_SIGLAS.forEach(s => { o[s] = 0; }); rows.forEach(r => { const s = tgSigla(tgChaveAgente(r.agente)); if (s) o[s] += r.msgs; }); return o; };
    const pa = porTime(atual), pb = porTime(ant);
    const delta = (a, b) => b ? `${a >= b ? '▲' : '▼'} ${Math.abs((a - b) / b * 100).toFixed(0)}%` : '—';
    const top = atual.filter(r => tgSigla(tgChaveAgente(r.agente))).sort((a, b) => b.msgs - a.msgs).slice(0, 5).map((r, i) => `${['🥇', '🥈', '🥉', '4.', '5.'][i]} ${tgEsc(tgNomeBonito(tgChaveAgente(r.agente)))}: ${r.msgs}`).join('\n');
    const [d48, d48a] = await Promise.all([tgDesempenho48(seg, dom), tgDesempenho48(segAnt, domAnt)]);
    const b = tgResumoBot(seg, dom), ba = tgResumoBot(segAnt, domAnt);
    const fotoMedia = (ini, fim) => { const o = {}; TG_SIGLAS.forEach(s => { const l = tgBot.fotos.filter(f => f.time === s && f.data >= ini && f.data <= fim); o[s] = l.length ? (l.reduce((x, f) => x + (parseInt(f.fora_sla) || 0), 0) / l.length) : null; }); return o; };
    const fa = fotoMedia(seg, dom), fb = fotoMedia(segAnt, domAnt);
    let txt = `🗓️ <b>RELATÓRIO SEMANAL — ${tgDM(seg)} a ${tgDM(dom)}</b>\n<i>comparado com ${tgDM(segAnt)} a ${tgDM(domAnt)}</i>\n\n💬 <b>Mensagens enviadas por time</b>\n`;
    txt += TG_SIGLAS.map(s => `${s}: <b>${pa[s]}</b> (${delta(pa[s], pb[s])})`).join('\n');
    txt += `\n\n🏆 <b>Quem mais enviou</b>\n${top || '—'}\n\n`;
    if (d48) txt += `⏳ <b>Time 48H</b>\nTickets: <b>${d48.tickets}</b> (${d48a ? delta(d48.tickets, d48a.tickets) : '—'}) · Retornos: <b>${tgPct(d48.retornos, d48.tickets)}</b>\nTMC: <b>${tgTempo(d48.tmc)}</b> · TMR: <b>${tgTempo(d48.tmr)}</b>\n\n`;
    txt += `🤖 <b>Bot</b>\n🔴 casos avisados: <b>${b.casos48}</b> (${delta(b.casos48, ba.casos48)}) · escalonados: <b>${b.escalonamentos}</b>\n✅ Ciente: <b>${tgPct(b.cientes, b.comBotao)}</b> (antes ${tgPct(ba.cientes, ba.comBotao)}) · tempo médio: <b>${tgTempo(b.tempoMedio)}</b>\n`;
    txt += Object.keys(TG_TURNOS).map(k => `${TG_TURNOS[k].rotulo}: 🔴 ${b.porTurno[k].avisos48} · ✅ ${tgPct(b.porTurno[k].cientes, b.porTurno[k].comBotao)}`).join('\n');
    if (TG_SIGLAS.some(s => fa[s] != null)) txt += `\n\n📷 <b>Média diária fora do SLA (foto das 23h50)</b>\n` + TG_SIGLAS.map(s => `${s}: <b>${fa[s] == null ? '—' : fa[s].toFixed(1).replace('.', ',')}</b>${fb[s] == null || fa[s] == null ? '' : ` (antes ${fb[s].toFixed(1).replace('.', ',')})`}`).join('\n');
    return txt;
}

// ---------- comandos ----------
function tgAjuda(v) {
    const gestor = v && (v.papel === 'lider' || v.papel === 'diretoria');
    const l = TG_COMANDOS.filter(c => c.cmd !== 'start' && (gestor ? c.quem !== 'agente' : c.quem !== 'gestor'));
    return `🤖 <b>Comandos</b>\n\n${l.map(c => `/${c.cmd} — ${tgEsc(c.desc)}`).join('\n')}\n\n<i>Os números são os mesmos do Status de Casos do Dash.</i>`;
}
async function tgCmdCasos(v, soSla) {
    const snap = await tgSnapshot(120000);
    if (!snap) return '⚠️ Não consegui ler o Status de Casos agora. Tente de novo em alguns minutos.';
    const e = tgEntradaDoAgente(snap, v);
    const c48 = tgListaCasos(e.detalhes, '48', 20), c24 = tgListaCasos(e.detalhes, '24', 20);
    let txt = soSla ? `⏱️ <b>Seus casos no limite do SLA</b>\n` : `📋 <b>Seus casos — ${tgEsc(tgNomeBonito(e.nome))}</b>\n${tgContagem(e)}\n`;
    if (!c48 && !c24) txt += `\n✅ Nenhum caso 🟡 ou 🔴 agora.`;
    if (c48) txt += `\n🔴 <b>Fora do SLA (mais de 48h)</b>\n${c48}\n`;
    if (c24) txt += `\n🟡 <b>Aguardando (24h a 48h)</b>\n${c24}\n`;
    return txt + `\n<i>Atualizado às ${tgAgoraBR(new Date(tgBot.snapEm)).hhmm}</i>`;
}
async function tgCmdEu(v) {
    const a = tgAgoraBR(), seg = tgSomarDias(a.data, -((a.dow + 6) % 7)), dom = tgSomarDias(seg, 6);
    const porDia = await tgMensagensPorDia(v, seg, dom);
    const meta = 400;   // mesma meta semanal do Tickets Atual do Dash (o campo saiu do painel em 07/10/2026)
    let total = 0;
    const nomes = ['Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb', 'Dom'];
    const linhas = nomes.map((n, i) => { const d = tgSomarDias(seg, i), q = porDia[d] || 0; total += q; return `${n} ${tgDM(d)}: <b>${q}</b> ${q ? '▓'.repeat(Math.min(10, Math.max(1, Math.round(q / 8)))) : (d > a.data ? '' : '—')}`; });
    const pct = Math.round(total / meta * 100);
    const st = pct >= 100 ? '🏆 Meta batida!' : pct >= 75 ? '🟢 Quase lá!' : pct >= 50 ? '🟡 Metade do caminho' : '🔴 Precisa acelerar';
    return `📊 <b>Sua semana — ${tgDM(seg)} a ${tgDM(dom)}</b>\n\n${linhas.join('\n')}\n\n📦 Total: <b>${total}</b> · 🎯 Meta: ${meta} · Falta: <b>${Math.max(0, meta - total)}</b>\n📈 ${pct}% — ${st}`;
}
async function tgCmdHoje(v) {
    const a = tgAgoraBR();
    const [porDia, snap] = await Promise.all([tgMensagensPorDia(v, a.data, a.data), tgSnapshot(120000)]);
    const e = snap ? tgEntradaDoAgente(snap, v) : null;
    return `☀️ <b>Seu dia — ${tgDM(a.data)}</b>\n\n💬 Mensagens enviadas hoje: <b>${porDia[a.data] || 0}</b>\n${e ? `📋 Casos agora: ${tgContagem(e)}` : '📋 Status de Casos indisponível agora'}\n\n<i>Detalhes: /casos</i>`;
}
async function tgCmdTime(v, arg) {
    const snap = await tgSnapshot(120000);
    if (!snap) return '⚠️ Não consegui ler o Status de Casos agora.';
    const sig = String(arg || '').toUpperCase().trim();
    let entradas, titulo;
    if (TG_SIGLAS.includes(sig)) { entradas = (snap.casos || []).filter(e => tgSigla(e.nome) === sig && !e.nome.startsWith('SEM ATRIBUIR')); titulo = `Time ${sig}`; }
    else if (v.papel === 'lider' && TG_TURNOS[v.turno]) {
        const chaves = new Set(tgBot.vinculos.filter(x => x.status === 'ativo' && x.papel === 'agente' && x.turno === v.turno).map(x => tgChaveAgente(x.agente_chatwoot)));
        entradas = (snap.casos || []).filter(e => chaves.has(e.nome)); titulo = `Seu turno (${TG_TURNOS[v.turno].rotulo})`;
    } else {
        const t = tgResumoTimes(snap);
        return `👥 <b>Times agora</b>\n\n${TG_SIGLAS.map(s => `<b>${s}</b>: 🔴 ${t[s].fora} · 🟡 ${t[s].aguardando} · 🟢 ${t[s].retornos} · 🔵 ${t[s].em_aberto} · sem agente ${t[s].sem}`).join('\n')}\n\n<i>Detalhe de um time: /time RET (ou SAC, BKO, SMS, 48H)</i>`;
    }
    entradas = entradas.slice().sort((a, b) => (b.fora_sla - a.fora_sla) || (b.aguardando - a.aguardando) || (b.total - a.total));
    const tot = entradas.reduce((o, e) => { o.fora_sla += e.fora_sla || 0; o.aguardando += e.aguardando || 0; o.retornos += e.retornos || 0; o.em_aberto += e.em_aberto || 0; return o; }, { fora_sla: 0, aguardando: 0, retornos: 0, em_aberto: 0 });
    const linhas = entradas.slice(0, 40).map(e => `• ${tgEsc(tgNomeBonito(e.nome))}: 🔴 ${e.fora_sla} · 🟡 ${e.aguardando} · 🟢 ${e.retornos} · 🔵 ${e.em_aberto}`);
    return `👥 <b>${tgEsc(titulo)} — agora</b>\n${tgContagem(tot)}\n\n${linhas.join('\n') || '—'}`;
}
async function tgCmdFila() {
    const snap = await tgSnapshot(120000);
    if (!snap) return '⚠️ Não consegui ler o Status de Casos agora.';
    const sem = (snap.casos || []).filter(e => e.nome.startsWith('SEM ATRIBUIR'));
    if (!sem.length) return '✅ Nenhum caso sem agente agora.';
    return `📥 <b>Casos sem agente — agora</b>\n\n${sem.map(e => `<b>${tgSigla(e.nome)}</b>: ${e.total} · 🔴 ${e.fora_sla} · 🟡 ${e.aguardando} · 🟢 ${e.retornos} · 🔵 ${e.em_aberto}`).join('\n')}`;
}

// ---------- mensagens recebidas ----------
function tgLogComando(o) { tgBot.comandos.push(o); tgEnfileirar('tg_comandos', o); }
async function tgTratarUpdate(u) {
    if (u.callback_query) return tgTratarBotao(u.callback_query);
    const m = u.message;
    if (!m || !m.chat || m.chat.type !== 'private') return;   // só conversa no privado
    const chatId = String(m.chat.id);
    const nomeTg = [m.from && m.from.first_name, m.from && m.from.last_name].filter(Boolean).join(' ').trim() || 'Sem nome';
    const texto = String(m.text || '').trim();
    const cm = texto.match(/^\/([a-zA-Z_]+)(?:@\w+)?(?:\s+([\s\S]*))?$/);
    const cmd = cm ? cm[1].toLowerCase() : '', arg = cm ? String(cm[2] || '').trim() : '';
    let v = tgBot.vinculos.find(x => x.chat_id === chatId);
    const inicio = Date.now();
    const log = (resultado) => tgLogComando({ data_hora: tgAgoraBR().texto, chat_id: chatId, nome_telegram: nomeTg, agente: v ? (v.agente_chatwoot || '') : '', comando: cmd ? '/' + cmd : '(mensagem)', parametros: arg.slice(0, 80), resultado, ms: Date.now() - inicio });
    if (!v) {   // pedido de vínculo: /start ou qualquer mensagem de quem ainda não está na lista
        if (tgBot.vinculos.filter(x => x.status === 'pendente').length >= 200) return;
        const agora = tgAgoraBR().texto;
        v = { chat_id: chatId, nome_telegram: nomeTg, usuario_telegram: (m.from && m.from.username) || '', agente_id: '', agente_chatwoot: '', papel: '', turno: '', status: 'pendente', criado_em: agora, atualizado_em: agora, por: '' };
        tgBot.vinculos.push(v); tgSalvarVinculos();
        await tgResponder(chatId, `👋 Olá, <b>${tgEsc((m.from && m.from.first_name) || nomeTg)}</b>!\n\nSeu pedido de vínculo foi registrado. Assim que for liberado no Dash, você recebe uma mensagem aqui.`);
        log('pedido de vínculo'); return;
    }
    if (v.status === 'pendente') { await tgResponder(chatId, '⏳ Seu pedido de vínculo ainda está aguardando liberação no Dash.'); log('aguardando liberação'); return; }
    if (v.status === 'recusado') { await tgResponder(chatId, '🚫 Seu acesso a este bot não foi liberado. Fale com o seu líder.'); log('acesso recusado'); return; }
    if (!cmd) { await tgResponder(chatId, 'Use /ajuda para ver os comandos.'); log('ajuda sugerida'); return; }
    const rl = `${chatId}:${cmd}:${arg}`;   // mesmo comando repetido em 5s (toque duplo) não roda 2x
    const desdeCmd = Date.now() - (tgBot.ultCmd[rl] || 0);
    if (tgBot.ultCmd[rl] && desdeCmd >= 0 && desdeCmd < 5000) { log('aguarde (repetido)'); return; }
    tgBot.ultCmd[rl] = Date.now();
    const gestor = v.papel === 'lider' || v.papel === 'diretoria';
    const temAgente = !!v.agente_chatwoot && v.papel === 'agente';
    try {
        let resp, resultado = 'ok';
        if (['time', 'fila', 'relatorio'].includes(cmd) && !gestor) { resp = '🔒 Esse comando é só para líderes.'; resultado = 'sem permissão'; }
        else if (['casos', 'sla', 'eu', 'hoje'].includes(cmd) && !temAgente) { resp = gestor ? 'ℹ️ Seu vínculo é de gestor. Use /time, /fila ou /relatorio.' : 'ℹ️ Seu vínculo ainda não tem agente do Chatwoot. Fale com o seu líder.'; resultado = 'sem agente'; }
        else switch (cmd) {
            case 'start': resp = `✅ Você já está vinculado${v.agente_chatwoot ? ` como <b>${tgEsc(v.agente_chatwoot)}</b>` : ''}.\n\n${tgAjuda(v)}`; break;
            case 'ajuda': case 'help': resp = tgAjuda(v); break;
            case 'casos': resp = await tgCmdCasos(v, false); break;
            case 'sla': resp = await tgCmdCasos(v, true); break;
            case 'eu': resp = await tgCmdEu(v); break;
            case 'hoje': resp = await tgCmdHoje(v); break;
            case 'time': resp = await tgCmdTime(v, arg); break;
            case 'fila': resp = await tgCmdFila(); break;
            case 'relatorio': { const a = tgAgoraBR(); resp = await tgRelatorioCasos(a.data, a.data, `RELATÓRIO DE CASOS — ${tgDM(a.data)}`, false); break; }
            default: resp = 'Não conheço esse comando. Use /ajuda.'; resultado = 'desconhecido';
        }
        const r = await tgResponder(chatId, resp);
        log(r.ok ? resultado : `falhou: ${String(r.description || '').slice(0, 60)}`);
    } catch (e) {
        await tgResponder(chatId, '⚠️ Deu erro ao buscar os dados. Tente de novo em alguns minutos.');
        log(`erro: ${String(e.message).slice(0, 80)}`);
    }
}
async function tgTratarBotao(cq) {
    const dado = String(cq.data || '');
    if (!dado.startsWith('ok:')) return tgApi('answerCallbackQuery', { callback_query_id: cq.id });
    const envioId = dado.slice(3);
    const chatId = String((cq.message && cq.message.chat && cq.message.chat.id) || (cq.from && cq.from.id) || '');
    const agora = tgAgoraBR();
    let c = tgBot.cientes.find(x => x.envio_id === envioId);
    if (!c) {
        const env = tgBot.envios.find(e => e.envio_id === envioId);
        c = { envio_id: envioId, chat_id: chatId, destino: env ? env.destino : '', ciente_em: agora.texto };
        tgBot.cientes.push(c); tgEnfileirar('tg_cientes', c);
    }
    await tgApi('answerCallbackQuery', { callback_query_id: cq.id, text: '✅ Registrado. Obrigado!' });
    if (cq.message) await tgApi('editMessageReplyMarkup', { chat_id: cq.message.chat.id, message_id: cq.message.message_id, reply_markup: { inline_keyboard: [[{ text: `✅ Ciente às ${String(c.ciente_em).slice(11, 16)}`, callback_data: 'noop' }]] } });
}

// ---------- disparos automáticos (por turno) ----------
const tgCasosTexto = (lista) => lista.slice(0, 20).map(d => `• <a href="${TG_URL_CASO(d.id)}">#${tgEsc(d.id)}</a> — ${d.horas_parado}h esperando`).join('\n') + (lista.length > 20 ? `\n<i>… e mais ${lista.length - 20}</i>` : '');
const tgFalhaDefinitiva = (r) => !!r && (r.error_code === 403 || r.error_code === 400);   // bloqueou o bot / chat não existe: não adianta tentar de novo
async function tgResumoInicio(v, a) {
    tgBot.marcos.add(`resumo_inicio|${v.chat_id}|${a.data}`);
    const snap = await tgSnapshot(120000); if (!snap) return;
    const e = tgEntradaDoAgente(snap, v), c48 = tgCasosFaixa(e, '48'), c24 = tgCasosFaixa(e, '24');
    if (tgBot.config.so_com_pendencia === 'sim' && !c48.length && !c24.length) return;
    let txt = `☀️ <b>Bom turno, ${tgEsc(tgPrimeiroNome(v))}!</b> (${TG_TURNOS[v.turno].rotulo})\n\nVocê começa com:\n${tgContagem(e)}\n`;
    if (c48.length) txt += `\n🔴 <b>Fora do SLA (mais de 48h)</b>\n${tgListaCasos(e.detalhes, '48', 20)}\n`;
    if (c24.length) txt += `\n🟡 <b>Aguardando (24h a 48h)</b>\n${tgListaCasos(e.detalhes, '24', 20)}\n`;
    if (!c48.length && !c24.length) txt += `\n✅ Nenhum caso 🟡 ou 🔴. Bom trabalho!`;
    const casos = [...c48.map(d => `${d.id}:48`), ...c24.map(d => `${d.id}:24`)];
    const r = await tgEnviar(v, txt, { tipo: 'resumo_inicio', casos });
    if (r.ok || tgFalhaDefinitiva(r)) casos.forEach(k => { const [id, fx] = k.split(':'); tgBot.avisados.set(`${v.chat_id}|${id}|${fx}`, Date.now()); });
}
async function tgLembreteFim(v, a) {
    tgBot.marcos.add(`lembrete_fim|${v.chat_id}|${a.data}`);
    const snap = await tgSnapshot(120000); if (!snap) return;
    const e = tgEntradaDoAgente(snap, v), c48 = tgCasosFaixa(e, '48'), c24 = tgCasosFaixa(e, '24');
    if (!c48.length && !c24.length) return;
    let txt = `⏰ <b>Faltam 30 min para o fim do seu turno</b>\n\nAinda estão pendentes:\n`;
    if (c48.length) txt += `\n🔴 <b>Fora do SLA</b>\n${tgListaCasos(e.detalhes, '48', 15)}\n`;
    if (c24.length) txt += `\n🟡 <b>Aguardando</b>\n${tgListaCasos(e.detalhes, '24', 15)}\n`;
    await tgEnviar(v, txt + `\n<i>Tente deixar os 🔴 respondidos antes de sair.</i>`, { tipo: 'lembrete_fim', casos: [...c48.map(d => `${d.id}:48`), ...c24.map(d => `${d.id}:24`)] });
}
async function tgVisaoLider(v, a) {
    tgBot.marcos.add(`visao_lider|${v.chat_id}|${a.data}`);
    const snap = await tgSnapshot(120000); if (!snap) return;
    const doTurno = tgBot.vinculos.filter(x => (x.status === 'ativo' || x.status === 'pausado') && x.papel === 'agente' && x.turno === v.turno && x.agente_chatwoot);
    const entradas = doTurno.map(x => tgEntradaDoAgente(snap, x));
    const tot = entradas.reduce((o, e) => { o.fora_sla += e.fora_sla || 0; o.aguardando += e.aguardando || 0; o.retornos += e.retornos || 0; o.em_aberto += e.em_aberto || 0; return o; }, { fora_sla: 0, aguardando: 0, retornos: 0, em_aberto: 0 });
    const vermelhos = [];
    entradas.forEach(e => tgCasosFaixa(e, '48').forEach(d => vermelhos.push(Object.assign({}, d, { agente: tgNomeBonito(e.nome) }))));
    vermelhos.sort(tgOrdenaHoras);
    const naLista = TG_EQUIPE.filter(x => x[2] === v.turno).length;
    let txt = `👋 <b>Bom turno, ${tgEsc(tgPrimeiroNome(v))}!</b>\nVisão do turno ${TG_TURNOS[v.turno].rotulo}\n\n${tgContagem(tot)}\n👥 Agentes do turno no bot: <b>${doTurno.length}</b> de ${naLista}\n`;
    if (vermelhos.length) txt += `\n🔴 <b>Fora do SLA agora</b> (inclui os que viraram 🔴 fora do horário)\n` + vermelhos.slice(0, 25).map(d => `• <a href="${TG_URL_CASO(d.id)}">#${tgEsc(d.id)}</a> — ${tgEsc(d.agente)} — ${d.horas_parado}h (🔴 há ${Math.max(0, d.horas_parado - 48)}h)`).join('\n') + (vermelhos.length > 25 ? `\n<i>… e mais ${vermelhos.length - 25}</i>` : '') + '\n';
    const comPend = entradas.filter(e => (e.fora_sla || 0) + (e.aguardando || 0) > 0).sort((x, y) => (y.fora_sla - x.fora_sla) || (y.aguardando - x.aguardando));
    txt += comPend.length ? `\n<b>Por agente</b>\n${comPend.slice(0, 30).map(e => `• ${tgEsc(tgNomeBonito(e.nome))}: 🔴 ${e.fora_sla} · 🟡 ${e.aguardando}`).join('\n')}` : `\n✅ Nenhum agente do turno com 🔴 ou 🟡.`;
    await tgEnviar(v, txt, { tipo: 'visao_lider', casos: vermelhos.map(d => `${d.id}:48`) });
}
async function tgFotoDiaria(a) {
    tgBot.marcos.add(`foto|-|${a.data}`);
    const snap = await tgSnapshot(60000); if (!snap) return;
    const t = tgResumoTimes(snap);
    TG_SIGLAS.forEach(s => { const o = { data: a.data, hora: a.hhmm, time: s, sem_agente: t[s].sem, em_aberto: t[s].em_aberto, retornos: t[s].retornos, aguardando: t[s].aguardando, fora_sla: t[s].fora, total: t[s].total }; tgBot.fotos.push(o); tgEnfileirar('tg_fotos', o); });
}
async function tgAgendados(a) {
    const c = tgBot.config;
    const ativos = tgBot.vinculos.filter(v => v.status === 'ativo');
    const janela = (ini) => a.minutos >= ini && a.minutos < ini + 15;
    for (const v of ativos) {
        const t = TG_TURNOS[v.turno]; if (!t) continue;
        if (v.papel === 'agente' && v.agente_chatwoot) {
            if (c.resumo_inicio === 'sim' && janela(t.ini) && !tgBot.marcos.has(`resumo_inicio|${v.chat_id}|${a.data}`)) await tgResumoInicio(v, a);
            if (c.lembrete_fim === 'sim' && janela(t.fim - 30) && !tgBot.marcos.has(`lembrete_fim|${v.chat_id}|${a.data}`)) await tgLembreteFim(v, a);
        }
        if (v.papel === 'lider' && c.visao_lider === 'sim' && janela(t.ini) && !tgBot.marcos.has(`visao_lider|${v.chat_id}|${a.data}`)) await tgVisaoLider(v, a);
    }
    const h = 8;   // relatórios para a gestão sempre às 8h (o campo saiu do painel em 07/10/2026)
    if (!isNaN(h) && janela(h * 60)) {
        const dir = ativos.filter(x => x.papel === 'diretoria');
        const faltaDia = c.relatorio_diario === 'sim' ? dir.filter(v => !tgBot.marcos.has(`relatorio_diario|${v.chat_id}|${a.data}`)) : [];
        const faltaSem = (c.relatorio_semanal === 'sim' && a.dow === 1) ? dir.filter(v => !tgBot.marcos.has(`relatorio_semanal|${v.chat_id}|${a.data}`)) : [];
        if (faltaDia.length) { const ontem = tgSomarDias(a.data, -1); const txt = await tgRelatorioCasos(ontem, ontem, `RELATÓRIO DIÁRIO — ${tgDM(a.data)} (fechamento de ${tgDM(ontem)})`, true); for (const v of faltaDia) await tgEnviar(v, txt, { tipo: 'relatorio_diario' }); }
        if (faltaSem.length) { const txt = await tgRelatorioSemanal(tgSomarDias(a.data, -7)); for (const v of faltaSem) await tgEnviar(v, txt, { tipo: 'relatorio_semanal' }); }
    }
    if (a.minutos >= 23 * 60 + 50 && !tgBot.marcos.has(`foto|-|${a.data}`)) await tgFotoDiaria(a);
}
async function tgRodadaAvisos(a) {
    if (tgBot.config.avisos !== 'sim') return;
    if (Date.now() < FREIO.ate) return;   // banco com freio: não avisa com dado velho
    const ativos = tgBot.vinculos.filter(v => v.status === 'ativo' && v.papel === 'agente' && v.agente_chatwoot && TG_TURNOS[v.turno]);
    if (!ativos.length) return;
    const snap = await tgSnapshot(60000); if (!snap) return;
    const lideres = tgBot.vinculos.filter(v => v.status === 'ativo' && v.papel === 'lider' && TG_TURNOS[v.turno]);
    const presentes = new Set();
    for (const v of ativos) {
        const e = tgEntradaDoAgente(snap, v);
        (e.detalhes || []).forEach(d => { const fx = tgFaixa(d.status); if (fx) presentes.add(`${v.chat_id}|${d.id}|${fx}`); });
        if (!tgNoTurno(v.turno, a)) continue;   // fora do turno: o caso entra no resumo do começo do próximo turno
        if (tgBot.config.resumo_inicio === 'sim' && a.minutos < TG_TURNOS[v.turno].ini + 15 && !tgBot.marcos.has(`resumo_inicio|${v.chat_id}|${a.data}`)) continue;
        const n48 = tgCasosFaixa(e, '48').filter(d => !tgBot.avisados.has(`${v.chat_id}|${d.id}|48`)).sort(tgOrdenaHoras);
        const n24 = tgCasosFaixa(e, '24').filter(d => !tgBot.avisados.has(`${v.chat_id}|${d.id}|24`)).sort(tgOrdenaHoras);
        if (n48.length) {
            const lista = tgCasosTexto(n48);
            const r = await tgEnviar(v, `🔴 <b>${n48.length > 1 ? `${n48.length} casos fora` : 'Caso fora'} do SLA (mais de 48h)</b>\n\n${lista}\n\n<i>O cliente está esperando a sua resposta.</i>`, { tipo: 'aviso_48h', casos: n48.map(d => `${d.id}:48`) });
            if (r.ok || tgFalhaDefinitiva(r)) n48.forEach(d => tgBot.avisados.set(`${v.chat_id}|${d.id}|48`, Date.now()));
            for (const l of lideres.filter(x => x.turno === v.turno && tgNoTurno(x.turno, a))) {   // escalonamento: líder do MESMO turno, só no horário dele
                await tgEnviar(l, `🔴 <b>Escalonamento — ${tgEsc(tgNomeBonito(e.nome))}</b>\n${n48.length > 1 ? `${n48.length} casos passaram` : '1 caso passou'} de 48h:\n\n${lista}`, { tipo: 'escalonamento', casos: n48.map(d => `${d.id}:48`) });
            }
        }
        if (n24.length) {
            const r = await tgEnviar(v, `🟡 <b>${n24.length > 1 ? `${n24.length} casos chegando` : 'Caso chegando'} no limite (mais de 24h esperando)</b>\n\n${tgCasosTexto(n24)}\n\n<i>Responda antes de passar de 48h.</i>`, { tipo: 'aviso_24h', casos: n24.map(d => `${d.id}:24`) });
            if (r.ok || tgFalhaDefinitiva(r)) n24.forEach(d => tgBot.avisados.set(`${v.chat_id}|${d.id}|24`, Date.now()));
        }
    }
    for (const k of Array.from(tgBot.avisados.keys())) if (!presentes.has(k)) tgBot.avisados.delete(k);   // saiu da faixa: se voltar, avisa de novo
}
async function tgTick() {
    if (!tgBot.ligado || !tgBot.carregado || tgBot.rodando) return;
    tgBot.rodando = true;
    try {
        const a = tgAgoraBR();
        await tgAgendados(a);
        const desdeRodada = Date.now() - tgBot.ultimaRodada;   // relógio que voltou (ajuste de hora) também libera a rodada
        if ((desdeRodada < 0 || desdeRodada >= 5 * 60 * 1000) && a.minutos >= 7 * 60) { tgBot.ultimaRodada = Date.now(); await tgRodadaAvisos(a); }
        if (tgBot.fila.tg_envios.length) await tgGravarFila();   // envio feito já vai para a planilha (no deploy, a cópia nova não repete)
    } catch (e) { console.error('[telegram] rotina de disparos:', e.message); }
    finally { tgBot.rodando = false; }
}
async function tgLoop() {   // polling: o Dash fica acordado pelo UptimeRobot
    while (tgBot.ligado) {
        const r = await tgApi('getUpdates', { offset: tgBot.offset, timeout: 25, allowed_updates: ['message', 'callback_query'] }, 35000);
        tgBot.ultimoPoll = Date.now();
        if (r && r.ok) {
            tgBot.erroSeguido = 0;
            for (const u of (r.result || [])) {
                tgBot.offset = Math.max(tgBot.offset, u.update_id + 1);
                try { await tgTratarUpdate(u); } catch (e) { console.error('[telegram] erro ao tratar mensagem:', e.message); }
            }
        } else {
            tgBot.ultimoErro = (r && r.description) || 'erro'; tgBot.erroEm = Date.now(); tgBot.erroSeguido += 1;
            if (r && r.error_code === 401) { console.error('[telegram] token recusado pelo Telegram: bot desligado'); tgBot.ligado = false; break; }
            await tgEsperar(r && r.error_code === 409 ? 10000 : Math.min(60000, 3000 * tgBot.erroSeguido));   // 409: outra cópia rodando (ex.: deploy)
        }
    }
}
async function tgComandosGestor(v) {
    return tgApi('setMyCommands', { scope: { type: 'chat', chat_id: Number(v.chat_id) }, commands: TG_COMANDOS.filter(c => c.cmd !== 'start' && c.quem !== 'agente').map(c => ({ command: c.cmd, description: c.desc.slice(0, 250) })) });
}
async function tgMenuPadrao(v) {   // agente ou removido: tira o menu de gestão daquele chat (volta o menu padrão de agente)
    return tgApi('deleteMyCommands', { scope: { type: 'chat', chat_id: Number(v.chat_id) } });
}
async function tgIniciar() {
    await tgCarregarPlanilha();
    setInterval(() => { tgGravarFila(); }, 30 * 1000);
    if (!TG_TOKEN) { console.warn('[telegram] TELEGRAM_TOKEN ausente: bot desligado (a aba 🤖 Bot Telegram mostra o aviso)'); return; }
    const me = await tgApi('getMe', {});
    if (me && me.ok) { tgBot.usuario = me.result.username || ''; tgBot.nome = me.result.first_name || ''; }
    else { tgBot.ultimoErro = (me && me.description) || 'getMe falhou'; tgBot.erroEm = Date.now(); console.error('[telegram] não consegui falar com o Telegram:', tgBot.ultimoErro); if (me && me.error_code === 401) return; }
    await tgApi('deleteWebhook', { drop_pending_updates: false });   // garante o modo polling
    await tgApi('setMyCommands', { commands: TG_COMANDOS.filter(c => c.quem !== 'gestor' && c.cmd !== 'start').map(c => ({ command: c.cmd, description: c.desc.slice(0, 250) })) });
    for (const v of tgBot.vinculos.filter(x => x.status === 'ativo' && (x.papel === 'lider' || x.papel === 'diretoria'))) await tgComandosGestor(v);
    tgBot.ligado = true;
    tgLoop();
    setInterval(tgTick, 60 * 1000);
    console.log(`[telegram] bot @${tgBot.usuario || '?'} ligado (polling)`);
}

// ---------- rotas da aba 🤖 Bot Telegram (só admin) ----------
function tgPeriodo(req, diasPadrao) {
    const a = tgAgoraBR();
    const ini = req.query.since ? unixParaYYYYMMDD(req.query.since) : tgSomarDias(a.data, -(diasPadrao - 1));
    const fim = req.query.until ? unixParaYYYYMMDD(req.query.until) : a.data;
    return { ini, fim, dentro: (t) => { const d = String(t || '').slice(0, 10); return d >= ini && d <= fim; } };
}
function tgUltimaInteracao() {
    const u = {};
    tgBot.comandos.forEach(c => { if (!u[c.chat_id] || c.data_hora > u[c.chat_id]) u[c.chat_id] = c.data_hora; });
    tgBot.cientes.forEach(c => { if (!u[c.chat_id] || c.ciente_em > u[c.chat_id]) u[c.chat_id] = c.ciente_em; });
    return u;
}
app.get('/api/telegram/painel', async (req, res) => {
    if (!tgEhAdmin(req)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
    try {
        let usuarios = [];
        try { usuarios = await tgUsuariosChatwoot(); } catch (e) { usuarios = []; }
        const ultInt = tgUltimaInteracao();
        const ultEnv = {}; tgBot.envios.forEach(e => { if (!ultEnv[e.chat_id] || e.data_hora >= ultEnv[e.chat_id].data_hora) ultEnv[e.chat_id] = e; });
        const vinculos = tgBot.vinculos.map(v => {
            const o = Object.assign({}, v, { ultima_interacao: ultInt[v.chat_id] || '', ultimo_envio: ultEnv[v.chat_id] ? { data_hora: ultEnv[v.chat_id].data_hora, tipo: ultEnv[v.chat_id].tipo, entregue: ultEnv[v.chat_id].entregue, erro: ultEnv[v.chat_id].erro } : null });
            if (v.status === 'pendente') { const ag = tgSugerirAgente(v.nome_telegram, usuarios); o.sugestao = ag ? Object.assign({ agente_id: ag.id, agente_chatwoot: ag.name }, tgSugerirTurno(ag.name) || {}) : null; }
            return o;
        });
        const sete = tgSomarDias(tgAgoraBR().data, -6);
        const usos = {}; tgBot.comandos.filter(c => String(c.data_hora).slice(0, 10) >= sete).forEach(c => { usos[c.comando] = (usos[c.comando] || 0) + 1; });
        const porTurno = {};
        Object.keys(TG_TURNOS).forEach(t => { porTurno[t] = { rotulo: TG_TURNOS[t].rotulo, equipe: TG_EQUIPE.filter(x => x[2] === t).length, vinculados: tgBot.vinculos.filter(v => v.status === 'ativo' && v.papel === 'agente' && v.turno === t).length, lider: (tgBot.vinculos.find(v => v.status === 'ativo' && v.papel === 'lider' && v.turno === t) || {}).agente_chatwoot || '' }; });
        res.json({
            success: true,
            bot: { configurado: !!TG_TOKEN, ligado: tgBot.ligado, usuario: tgBot.usuario, nome: tgBot.nome, ultimo_poll: tgBot.ultimoPoll, ultimo_erro: tgBot.ultimoErro, erro_em: tgBot.erroEm, planilha_ok: tgBot.planilhaOk, planilha_configurada: !!tgSheets(), iniciado_em: tgBot.iniciadoEm, agora: tgAgoraBR().texto, fila_planilha: Object.values(tgBot.fila).reduce((s, l) => s + l.length, 0) },
            config: tgBot.config, turnos: TG_TURNOS, por_turno: porTurno, gestores: TG_GESTORES,
            comandos: TG_COMANDOS.map(c => Object.assign({}, c, { usos_7d: usos['/' + c.cmd] || 0 })),
            vinculos, agentes: usuarios.map(u => ({ id: u.id, name: u.name, sugestao: tgSugerirTurno(u.name) }))
        });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.get('/api/telegram/entregas', (req, res) => {
    if (!tgEhAdmin(req)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
    try {
        const p = tgPeriodo(req, 7);
        const env = tgBot.envios.filter(e => p.dentro(e.data_hora));
        const cienteDe = {}; tgBot.cientes.forEach(c => { if (!cienteDe[c.envio_id]) cienteDe[c.envio_id] = c; });
        const ultInt = tgUltimaInteracao();
        const porDest = {}, porDia = {}, porTipo = {};
        const novo = (k, d) => ({ chat_id: k, destino: d.destino || '', papel: d.papel || '', turno: d.turno || '', envios: 0, entregues: 0, falhas: 0, ultimo_erro: '', com_botao: 0, cientes: 0, _t: [], ultimo_envio: '' });
        env.forEach(e => {
            const o = porDest[e.chat_id] || (porDest[e.chat_id] = novo(e.chat_id, e));
            o.envios++; porTipo[e.tipo] = (porTipo[e.tipo] || 0) + 1;
            const dia = String(e.data_hora).slice(0, 10); const pd = porDia[dia] || (porDia[dia] = { dia, envios: 0, entregues: 0, cientes: 0 }); pd.envios++;
            if (e.entregue === 'sim') { o.entregues++; pd.entregues++; } else { o.falhas++; o.ultimo_erro = e.erro; }
            if (TG_TIPOS_CIENTE.includes(e.tipo) && e.entregue === 'sim') {
                o.com_botao++;
                const c = cienteDe[e.envio_id];
                if (c) { o.cientes++; pd.cientes++; const m = (tgMsBR(c.ciente_em) - tgMsBR(e.data_hora)) / 60000; if (m >= 0) o._t.push(m); }
            }
            if (e.data_hora > o.ultimo_envio) o.ultimo_envio = e.data_hora;
        });
        tgBot.vinculos.filter(v => v.status === 'ativo' || v.status === 'pausado').forEach(v => { if (!porDest[v.chat_id]) porDest[v.chat_id] = novo(v.chat_id, { destino: v.agente_chatwoot || v.nome_telegram, papel: v.papel, turno: v.turno }); });
        const vinc = {}; tgBot.vinculos.forEach(v => { vinc[v.chat_id] = v; });
        const lista = Object.values(porDest).map(o => {
            const v = vinc[o.chat_id] || {};
            const tempo = o._t.length ? o._t.reduce((a, b) => a + b, 0) / o._t.length : null;
            const r = Object.assign({}, o, { destino: v.agente_chatwoot || o.destino, papel: v.papel || o.papel, turno: v.turno || o.turno, status: v.status || '', taxa_ciente: o.com_botao ? o.cientes / o.com_botao : null, tempo_medio_min: tempo, ultima_interacao: ultInt[o.chat_id] || '', bloqueado: /blocked|forbidden|deactivated|chat not found/i.test(o.ultimo_erro) });
            delete r._t; return r;
        }).sort((x, y) => (y.envios - x.envios) || String(x.destino).localeCompare(String(y.destino)));
        const tot = lista.reduce((s, o) => { s.envios += o.envios; s.entregues += o.entregues; s.falhas += o.falhas; s.com_botao += o.com_botao; s.cientes += o.cientes; return s; }, { envios: 0, entregues: 0, falhas: 0, com_botao: 0, cientes: 0 });
        const tempos = []; env.forEach(e => { const c = cienteDe[e.envio_id]; if (c && TG_TIPOS_CIENTE.includes(e.tipo) && e.entregue === 'sim') { const m = (tgMsBR(c.ciente_em) - tgMsBR(e.data_hora)) / 60000; if (m >= 0) tempos.push(m); } });
        const dias = []; for (let d = p.ini; d <= p.fim && dias.length < 62; d = tgSomarDias(d, 1)) dias.push(porDia[d] || { dia: d, envios: 0, entregues: 0, cientes: 0 });
        res.json({
            success: true, periodo: { inicio: p.ini, fim: p.fim },
            kpis: Object.assign(tot, { taxa_entrega: tot.envios ? tot.entregues / tot.envios : null, taxa_ciente: tot.com_botao ? tot.cientes / tot.com_botao : null, tempo_medio_min: tempos.length ? tempos.reduce((a, b) => a + b, 0) / tempos.length : null, bloqueados: lista.filter(o => o.bloqueado).length }),
            por_destino: lista, por_dia: dias, por_tipo: porTipo,
            envios: env.slice().sort((x, y) => String(y.data_hora).localeCompare(String(x.data_hora))).slice(0, 400).map(e => Object.assign({}, e, { ciente_em: cienteDe[e.envio_id] ? cienteDe[e.envio_id].ciente_em : '' }))
        });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.get('/api/telegram/comandos', (req, res) => {
    if (!tgEhAdmin(req)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
    try {
        const p = tgPeriodo(req, 7);
        const linhas = tgBot.comandos.filter(c => p.dentro(c.data_hora)).sort((x, y) => String(y.data_hora).localeCompare(String(x.data_hora)));
        const porDia = {}, porCmd = {}, porAg = {};
        linhas.forEach(c => { const d = String(c.data_hora).slice(0, 10); porDia[d] = (porDia[d] || 0) + 1; porCmd[c.comando] = (porCmd[c.comando] || 0) + 1; const ag = c.agente || c.nome_telegram || c.chat_id; porAg[ag] = (porAg[ag] || 0) + 1; });
        const dias = []; for (let d = p.ini; d <= p.fim && dias.length < 62; d = tgSomarDias(d, 1)) dias.push({ dia: d, total: porDia[d] || 0 });
        const ordena = (o) => Object.keys(o).map(k => ({ nome: k, total: o[k] })).sort((a, b) => b.total - a.total);
        res.json({ success: true, periodo: { inicio: p.ini, fim: p.fim }, total: linhas.length, por_dia: dias, por_comando: ordena(porCmd), por_agente: ordena(porAg), linhas: linhas.slice(0, 3000) });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
// Ações (POST): a resposta usa "ok" (sem "success") para o cache das rotas nunca guardar uma ação
app.post('/api/telegram/vinculo', express.json(), async (req, res) => {
    const admin = tgEhAdmin(req);
    if (!admin) return res.status(403).json({ ok: false, erro: 'Acesso restrito para Administradores.' });
    try {
        const b = req.body || {};
        const v = tgBot.vinculos.find(x => x.chat_id === String(b.chat_id || ''));
        if (!v) return res.status(404).json({ ok: false, erro: 'Vínculo não encontrado.' });
        const acao = String(b.acao || '');
        const agora = tgAgoraBR().texto;
        if (acao === 'remover' && TG_TOKEN) {   // avisa a pessoa antes de apagar o vínculo (só quem tinha acesso) e tira o menu de gestão do chat dela
            if (v.status === 'ativo' || v.status === 'pausado') await tgEnviar(v, `🔒 Seu acesso ao <b>${tgEsc(tgBot.nome || 'bot')}</b> foi removido.\nVocê não vai mais receber avisos nem usar os comandos.\nSe foi engano, fale com o seu líder.`, { tipo: 'removido' });
            await tgMenuPadrao(v);
        }
        if (acao === 'remover') { tgBot.vinculos = tgBot.vinculos.filter(x => x !== v); await tgSalvarVinculos(); return res.json({ ok: true }); }
        if (acao === 'aprovar' || acao === 'editar') {
            const papel = String(b.papel || '');
            if (!['agente', 'lider', 'diretoria'].includes(papel)) return res.status(400).json({ ok: false, erro: 'Escolha o papel.' });
            if (papel !== 'diretoria' && !TG_TURNOS[String(b.turno || '')]) return res.status(400).json({ ok: false, erro: 'Escolha o turno.' });
            if (papel === 'agente' && !b.agente_chatwoot) return res.status(400).json({ ok: false, erro: 'Escolha o agente do Chatwoot.' });
            const eraAtivo = v.status === 'ativo';
            Object.assign(v, { agente_id: String(b.agente_id || ''), agente_chatwoot: String(b.agente_chatwoot || ''), papel, turno: papel === 'diretoria' ? '' : String(b.turno), atualizado_em: agora, por: admin });
            if (acao === 'aprovar') v.status = 'ativo';
            await tgSalvarVinculos();
            if (acao === 'aprovar' && !eraAtivo && TG_TOKEN) {
                const papelTxt = papel === 'agente' ? `agente <b>${tgEsc(v.agente_chatwoot)}</b> — turno ${TG_TURNOS[v.turno].rotulo}` : (papel === 'lider' ? `líder do turno ${TG_TURNOS[v.turno].rotulo}` : 'gestão (relatório diário e semanal)');
                await tgEnviar(v, `✅ <b>Vínculo liberado!</b>\nVocê foi ligado como ${papelTxt}.\n\n${tgAjuda(v)}`, { tipo: 'vinculo' });
            }
            if (TG_TOKEN && (papel === 'lider' || papel === 'diretoria')) await tgComandosGestor(v);
            if (TG_TOKEN && !(papel === 'lider' || papel === 'diretoria')) await tgMenuPadrao(v);   // agente: sem o menu de gestão
            return res.json({ ok: true });
        }
        if (['pausar', 'ativar', 'recusar'].includes(acao)) {
            v.status = acao === 'pausar' ? 'pausado' : (acao === 'ativar' ? 'ativo' : 'recusado');
            v.atualizado_em = agora; v.por = admin;
            await tgSalvarVinculos();
            return res.json({ ok: true });
        }
        res.status(400).json({ ok: false, erro: 'Ação inválida.' });
    } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
app.post('/api/telegram/config', express.json(), async (req, res) => {
    if (!tgEhAdmin(req)) return res.status(403).json({ ok: false, erro: 'Acesso restrito para Administradores.' });
    try {
        const b = req.body || {};
        ['avisos', 'resumo_inicio', 'so_com_pendencia', 'lembrete_fim', 'visao_lider', 'relatorio_diario', 'relatorio_semanal'].forEach(k => { if (b[k] === 'sim' || b[k] === 'nao') tgBot.config[k] = b[k]; });
        const h = parseInt(b.hora_relatorio, 10); if (!isNaN(h) && h >= 0 && h <= 23) tgBot.config.hora_relatorio = String(h);
        const meta = parseInt(b.meta_semana, 10); if (!isNaN(meta) && meta > 0 && meta < 100000) tgBot.config.meta_semana = String(meta);
        const salvo = await tgSalvarConfig();
        res.json({ ok: true, config: tgBot.config, salvo_na_planilha: salvo });
    } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
app.post('/api/telegram/teste', express.json(), async (req, res) => {
    if (!tgEhAdmin(req)) return res.status(403).json({ ok: false, erro: 'Acesso restrito para Administradores.' });
    try {
        if (!TG_TOKEN) return res.json({ ok: false, erro: 'O bot está desligado: falta o TELEGRAM_TOKEN no Render.' });
        const v = tgBot.vinculos.find(x => x.chat_id === String((req.body || {}).chat_id || ''));
        if (!v) return res.status(404).json({ ok: false, erro: 'Vínculo não encontrado.' });
        const r = await tgEnviar(v, `🧪 <b>Mensagem de teste do Dash GEX</b>\n\nSe chegou, está tudo certo. Toque em ✅ Ciente para testar a confirmação.`, { tipo: 'teste' });
        res.json({ ok: !!r.ok, erro: r.ok ? '' : (r.description || 'não entregue') });
    } catch (e) { res.status(500).json({ ok: false, erro: e.message }); }
});
setTimeout(() => { tgIniciar().catch(e => console.error('[telegram] falha ao iniciar:', e.message)); }, 5000);
