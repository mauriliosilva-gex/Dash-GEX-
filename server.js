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
    ssl: false // SSL desligado conforme configurado
});

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
const MAX_CACHE_KEYS = 200; // Trava de segurança para impedir estouro de RAM

const cacheMiddleware = (req, res, next) => {
    const chaveUrl = req.originalUrl; 
    const agora = Date.now();

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

    if (cacheMemoria[chaveUrl] && (agora - cacheMemoria[chaveUrl].tempo < tempoCacheMinutos * 60 * 1000)) {
        console.log(`⚡ Retornando do Cache (${tempoCacheMinutos}m): ${chaveUrl}`);
        return res.json(cacheMemoria[chaveUrl].data);
    }

    const sendJsonOriginal = res.json;
    res.json = function(dados) {
        if (dados && dados.success) {
            cacheMemoria[chaveUrl] = { tempo: agora, data: dados };
            console.log(`🔄 Dados Atualizados e Cache Salvo (${tempoCacheMinutos}m): ${chaveUrl}`);
        }
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
        const PADRAO_ABA = "📊 Análise | Metas | Setembro";
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
            if (setorRaw.includes('48H') || nomes48H.some(n => nomeFormatado.includes(n))) {
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

        const meses = Array.from(mesesSet).sort((a, b) => b.localeCompare(a)); 
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

        const meses = Array.from(mesesSet).sort((a, b) => b.localeCompare(a)); 
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
                i.name AS caixa,
                COUNT(c.id) AS qtd
            FROM conversations c
            LEFT JOIN users u ON u.id = c.assignee_id
            LEFT JOIN inboxes i ON i.id = c.inbox_id
            WHERE c.status = 0 
              AND c.account_id = 1
            GROUP BY u.name, i.name
        `;
        const resultDist = await pool.query(qDist);
        
        const distAgentes = {};
        const caixasSet = new Set();
        
        resultDist.rows.forEach(r => {
            let nomeAgente = (r.agente || '').toUpperCase();
            let cx = r.caixa || '(Sem Time)';
            let cxUpper = cx.toUpperCase();
            
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
                if (siglaSetor === 'OUTROS') return; // Ignora as filas irrelevantes
                nome = `SEM ATRIBUIR - ${siglaSetor}`;
            } else {
                nome = nomeAgente;
                if(!nome.match(/- SAC|- RET|- BKO|- SMS|- 48H/)) return;
            }
            
            if (!distAgentes[nome]) distAgentes[nome] = { nome, total: 0 };
            distAgentes[nome][cx] = parseInt(r.qtd) || 0;
            distAgentes[nome].total += parseInt(r.qtd) || 0;
        });

        // 2. Query Resumo Casos Agente - Lógica de SLA
        const qCasos = `
            WITH OpenConversations AS (
                SELECT id, display_id, assignee_id, contact_id, first_reply_created_at, last_activity_at, team_id, inbox_id
                FROM conversations
                WHERE status = 0 AND account_id = 1
            ),
            LastMessages AS (
                SELECT DISTINCT ON (conversation_id) conversation_id, message_type
                FROM messages
                WHERE conversation_id IN (SELECT id FROM OpenConversations)
                  AND message_type IN (0, 1)
                  AND private = FALSE
                  AND (content_attributes->>'deleted')::boolean IS NOT TRUE
                ORDER BY conversation_id, created_at DESC
            )
            SELECT 
                u.name AS agente,
                t.name AS equipe_nome,
                i.name AS inbox_nome,
                oc.id AS conv_id,
                oc.display_id,
                ct.name AS cliente,
                oc.first_reply_created_at,
                oc.last_activity_at,
                lm.message_type AS last_msg_type
            FROM OpenConversations oc
            LEFT JOIN users u ON u.id = oc.assignee_id
            LEFT JOIN teams t ON t.id = oc.team_id
            LEFT JOIN inboxes i ON i.id = oc.inbox_id
            LEFT JOIN contacts ct ON ct.id = oc.contact_id
            LEFT JOIN LastMessages lm ON lm.conversation_id = oc.id
        `;
        const resultCasos = await pool.query(qCasos);
        const resCasosMap = {};
        const agora = new Date();
        
        resultCasos.rows.forEach(r => {
            let nomeAgente = (r.agente || '').toUpperCase();
            let equipeNome = (r.equipe_nome || r.inbox_nome || '').toUpperCase();

            // Descobre a sigla do time baseada no Inbox ou Team da conversa
            let siglaSetor = 'OUTROS';
            if (equipeNome.includes('RETEN') || equipeNome.includes('RET')) siglaSetor = 'RET';
            else if (equipeNome.includes('SAC')) siglaSetor = 'SAC';
            else if (equipeNome.includes('BACK') || equipeNome.includes('BKO')) siglaSetor = 'BKO';
            else if (equipeNome.includes('SMS')) siglaSetor = 'SMS';
            else if (equipeNome.includes('48')) siglaSetor = '48H';

            let nome;
            if (!nomeAgente) {
                if (siglaSetor === 'OUTROS') return;
                nome = `SEM ATRIBUIR - ${siglaSetor}`;
            } else {
                nome = nomeAgente;
                if(!nome.match(/- SAC|- RET|- BKO|- SMS|- 48H/)) return;
            }
            
            // Criando os novos baldes de SLA
            if (!resCasosMap[nome]) resCasosMap[nome] = { nome, retornos: 0, aguardando: 0, fora_sla: 0, total: 0, detalhes: [] };
            
            const diffHoras = (agora - new Date(r.last_activity_at)) / (1000 * 60 * 60);
            const isClientLast = (r.last_msg_type === 0);
            
            if (isClientLast) {
                let statusLabel, ordem;
                
                if (diffHoras > 48) {
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
            }
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
// 11. ROTA DE PRODUTIVIDADE E TEMPO OCIOSO (ADMIN-ONLY)
// ==========================================
app.get('/api/produtividade', async (req, res) => {
    try {
        let dataInicioSQL, dataFimSQL;
        if (req.query.since && req.query.until) {
            dataInicioSQL = unixParaYYYYMMDD(req.query.since); 
            dataFimSQL = unixParaYYYYMMDD(req.query.until);
        } else {
            // 🔥 CORREÇÃO RESTAURADA: Busca os últimos 7 dias por padrão em vez de só "hoje"
            const agora = new Date(new Date().toLocaleString("en-US", {timeZone: "America/Sao_Paulo"}));
            const seteDiasAtras = new Date(agora);
            seteDiasAtras.setDate(agora.getDate() - 7);
            
            dataInicioSQL = formatarDataSQL(seteDiasAtras); 
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
                'NeuroGolden', 'Marycept', 'YogTide', 'Rosedil', 'Retride', 'Olivaro', 'Lasiberry', 'USBREX'
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
        res.json({ success: true, dados: result.rows });
    } catch (error) { 
        console.error("Erro Rota Menções:", error);
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
// 16. ROTA DE URGÊNCIA: REEMBOLSOS PAGAMERICAN (SEGMENTADO E BLINDADO)
// ==========================================
app.get('/api/reembolsos-pagamerican', async (req, res) => {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    
    if (!adms.includes(emailUser)) {
        return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
    }
    
    try {
        // 🔥 AGORA ACEITA FILTRO DE PERÍODO (since/until). Sem filtro = mês atual.
        let dataInicioSQL, dataFimSQL;
        if (req.query.since && req.query.until) {
            dataInicioSQL = unixParaYYYYMMDD(req.query.since);
            dataFimSQL = unixParaYYYYMMDD(req.query.until);
        } else {
            const agora = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Sao_Paulo" }));
            const dInicio = new Date(agora.getFullYear(), agora.getMonth(), 1);
            dataInicioSQL = formatarDataSQL(dInicio);
            dataFimSQL = formatarDataSQL(agora);
        }

        const q = `
        WITH CasosFiltrados AS (
            SELECT 
                c.id AS conv_id,
                c.display_id,
                COALESCE(u.name, 'SEM ATRIBUIR') AS agente_nome,
                ct.name AS contato_nome,
                ct.email AS contato_email,
                c.created_at,
                COALESCE(c.custom_attributes->>'tipo_de_retencao_de_reembolso', ct.custom_attributes->>'tipo_de_retencao_de_reembolso', '') AS tipo_retencao
            FROM conversations c
            LEFT JOIN users u ON u.id = c.assignee_id
            LEFT JOIN contacts ct ON ct.id = c.contact_id
            WHERE c.account_id = 1
              AND (
                  (c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo' AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo')
                  OR
                  (c.updated_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo' AND c.updated_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo')
              )
              
              -- 🔥 1. PLATAFORMA: Caça todas as variações possíveis de PagAmerican de uma vez só
              AND (
                  COALESCE(c.custom_attributes::text, '') ILIKE ANY(ARRAY['%pagamerican%', '%pagamerica%', '%pag american%', '%pag_american%']) OR
                  COALESCE(ct.custom_attributes::text, '') ILIKE ANY(ARRAY['%pagamerican%', '%pagamerica%', '%pag american%', '%pag_american%'])
              )
              
              -- 🔥 2. OBRIGATÓRIO TER REEMBOLSO: A gaveta do Tipo de Retenção não pode estar vazia
              AND COALESCE(c.custom_attributes->>'tipo_de_retencao_de_reembolso', ct.custom_attributes->>'tipo_de_retencao_de_reembolso', '') != ''
              
              -- 🔥 3. EXCEÇÃO: Bloqueia se for "Sem reembolso"
              AND COALESCE(c.custom_attributes->>'tipo_de_retencao_de_reembolso', ct.custom_attributes->>'tipo_de_retencao_de_reembolso', '') NOT ILIKE '%sem reembolso%'
        )
        SELECT 
            agente_nome,
            COUNT(conv_id) AS total_reembolsos,
            
            COUNT(CASE WHEN tipo_retencao ILIKE '%10 a 30%' THEN 1 END) AS r_10_30,
            COUNT(CASE WHEN tipo_retencao ILIKE '%40 a 50%' THEN 1 END) AS r_40_50,
            COUNT(CASE WHEN tipo_retencao ILIKE '%60 a 90%' THEN 1 END) AS r_60_90,
            COUNT(CASE WHEN tipo_retencao ILIKE '%100%' THEN 1 END) AS r_100,
            COUNT(CASE WHEN tipo_retencao NOT ILIKE '%10 a 30%' AND tipo_retencao NOT ILIKE '%40 a 50%' AND tipo_retencao NOT ILIKE '%60 a 90%' AND tipo_retencao NOT ILIKE '%100%' THEN 1 END) AS r_outros,
            
            json_agg(
                json_build_object(
                    'id', display_id,
                    'nome', COALESCE(contato_nome, 'Sem Nome'),
                    'email', COALESCE(contato_email, 'Sem Email'),
                    'data', created_at,
                    'tipo', tipo_retencao
                ) ORDER BY created_at DESC
            ) AS detalhes
        FROM CasosFiltrados
        GROUP BY agente_nome
        ORDER BY total_reembolsos DESC;
        `;
        
        const result = await pool.query(q, [dataInicioSQL, dataFimSQL]);
        res.json({ success: true, dados: result.rows });
    } catch (error) { 
        console.error("Erro PagAmerican:", error);
        res.status(500).json({ success: false, error: error.message }); 
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
            const dInicio = new Date(agora.getFullYear(), agora.getMonth(), 1);
            dataInicioSQL = formatarDataSQL(dInicio);
            dataFimSQL = formatarDataSQL(agora);
        }

        const q = `
        WITH Etiquetas AS (
            SELECT id FROM tags WHERE name ILIKE 'time-48h' OR name ILIKE 'painel-do-pedido'
        ),
        TargetConversations AS (
            SELECT c.id AS conv_id, c.display_id, c.contact_id, c.created_at, c.first_reply_created_at, c.assignee_id
            FROM conversations c
            WHERE c.account_id = 1
              AND c.id IN (
                  SELECT tg.taggable_id FROM taggings tg
                  WHERE tg.taggable_type = 'Conversation' AND tg.tag_id IN (SELECT id FROM Etiquetas)
              )
              AND c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
        ),
        Mensagens AS (
            SELECT 
                m.conversation_id, m.message_type, m.created_at,
                LAG(m.created_at) OVER (PARTITION BY m.conversation_id ORDER BY m.created_at) as prev_msg_time,
                LAG(m.message_type) OVER (PARTITION BY m.conversation_id ORDER BY m.created_at) as prev_msg_type
            FROM messages m
            WHERE m.conversation_id IN (SELECT conv_id FROM TargetConversations)
              AND m.private = FALSE
              AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE
        ),
        MetricasAgente AS (
            SELECT 
                tc.conv_id,
                tc.display_id,
                ct.name AS cliente,
                COALESCE(u.name, 'SEM ATRIBUIR') AS agente,
                EXTRACT(EPOCH FROM (tc.first_reply_created_at - tc.created_at))/60 AS tmc_minutos,
                (SELECT COUNT(*) FROM Mensagens m2 WHERE m2.conversation_id = tc.conv_id AND m2.message_type = 1) AS qtd_msgs_agente,
                -- 🔥 INTELIGÊNCIA: Se o cliente (0) mandou msg DEPOIS do agente (1), foi um retorno!
                (SELECT COUNT(*) FROM Mensagens m5 WHERE m5.conversation_id = tc.conv_id AND m5.message_type = 0 AND m5.prev_msg_type = 1) AS interacoes_retorno,
                (SELECT AVG(EXTRACT(EPOCH FROM (m4.created_at - m4.prev_msg_time))/60) 
                 FROM Mensagens m4 
                 WHERE m4.conversation_id = tc.conv_id AND m4.message_type = 1 AND m4.prev_msg_type = 0
                ) AS tmr_minutos
            FROM TargetConversations tc
            LEFT JOIN users u ON u.id = tc.assignee_id
            LEFT JOIN contacts ct ON ct.id = tc.contact_id
        )
        SELECT 
            agente,
            COUNT(conv_id) AS tickets,
            -- Se teve 1 ou mais interações de retorno, marca este ticket como "Retornado"
            COALESCE(SUM(CASE WHEN interacoes_retorno > 0 THEN 1 ELSE 0 END), 0) AS retornos,
            COALESCE(SUM(qtd_msgs_agente), 0) AS mensagens,
            COALESCE(AVG(tmc_minutos), 0) AS tmc_medio_minutos,
            COALESCE(AVG(tmr_minutos), 0) AS tmr_medio_minutos,
            json_agg(json_build_object(
                'id', display_id,
                'cliente', COALESCE(cliente, 'Cliente sem nome'),
                'retornos', interacoes_retorno,
                'tmc', ROUND(COALESCE(tmc_minutos, 0))
            ) ORDER BY interacoes_retorno DESC NULLS LAST) AS detalhes
        FROM MetricasAgente
        WHERE agente ILIKE '%- 48H%'
        GROUP BY agente
        ORDER BY tickets DESC;
        `;
        const result = await pool.query(q, [dataInicioSQL, dataFimSQL]);
        res.json({ success: true, dados: result.rows });
    } catch (error) { 
        console.error("Erro Time 48h:", error);
        res.status(500).json({ success: false, error: error.message }); 
    }
});

const PORT = process.env.PORT || 3003;

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


app.listen(PORT, () => {
    console.log(`✅ Servidor rodando na porta ${PORT}`);
});
