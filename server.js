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
// 🛡️ 16/10/2026: política de conteúdo (CSP) ligada — o navegador só carrega script, estilo e fonte do próprio Dash e das CDNs que o index usa
// (Tailwind, jsDelivr, cdnjs, npmcdn/unpkg, Google Fonts); o Dash não abre dentro de iframe de outro site; sem plugin; formulário só para o próprio Dash;
// os dados (fetch) só vão para o próprio servidor. 'unsafe-inline' continua porque o index tem script e onclick no próprio HTML.
// Sem upgrade-insecure-requests: a cópia que roda no host local é http.
const CSP_SCRIPTS = ['https://cdn.tailwindcss.com', 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com', 'https://npmcdn.com', 'https://unpkg.com'];
app.use(helmet({
    contentSecurityPolicy: {
        useDefaults: false,
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", ...CSP_SCRIPTS],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdn.jsdelivr.net', 'https://npmcdn.com', 'https://unpkg.com'],
            fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
            imgSrc: ["'self'", 'data:', 'blob:'],
            connectSrc: ["'self'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            frameAncestors: ["'none'"]
        }
    }
}));
app.use((req, res, next) => { res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()'); next(); });   // 🛡️ 16/10/2026: o Dash não usa câmera, microfone, localização nem pagamento
// 🛡️ 16/10/2026: CORS fechado — o Dash só é chamado pelas próprias telas (mesma origem não precisa de CORS). Antes qualquer site podia pedir.
// Se um dia outro site precisar ler a API: CORS_ORIGENS=https://site1.com,https://site2.com no Render.
const CORS_ORIGENS = (process.env.CORS_ORIGENS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({ origin: (origem, cb) => cb(null, !!origem && CORS_ORIGENS.includes(origem)) }));

// 14/10/2026: o limite de 100 chamadas a cada 15 min passa a contar por SESSÃO (cookie de login assinado pelo servidor) — antes todo mundo atrás
// do mesmo IP (ex.: escritório) dividia as mesmas 100. Sem sessão válida continua por IP (cookie inventado não ganha cota nova).
function chaveDoLimiteApi(req) {
    try {
        const m = /(?:^|;\s*)connect\.sid=s%3A([^.;]+)\.([^;]+)/.exec(req.headers.cookie || '');
        if (m && decodeURIComponent(m[2]) === require('crypto').createHmac('sha256', process.env.SESSION_SECRET || 'chave_reserva_gex').update(m[1]).digest('base64').replace(/=+$/, '')) return 'sessao:' + m[1];
    } catch (e) { /* cookie malformado: conta por IP */ }
    return rateLimit.ipKeyGenerator ? rateLimit.ipKeyGenerator(req.ip) : req.ip;
}
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    keyGenerator: chaveDoLimiteApi,   // 14/10/2026: conta por sessão (cookie de login); por IP só sem sessão
    skip: (req) => req.path === '/raio-x-perf' || (req.headers['x-warm-token'] === WARM_TOKEN && ehChamadaInterna(req)),   // 14/10/2026: não contam o Raio-X de Desempenho (atualiza a cada 15 s, sem banco) nem a chamada interna do próprio servidor
    message: { success: false, error: "Muitas requisições. Aguarde alguns minutos." }
});
app.use('/api/', limiter);
// 🛡️ 16/10/2026: trava contra pedido forjado (CSRF) — ação (POST/PUT/PATCH/DELETE) na API só vale vinda das telas do próprio Dash.
// O navegador avisa de onde veio o pedido (Sec-Fetch-Site; nos antigos, Origin): de outro site → 403. A chamada interna do servidor continua.
app.use('/api/', (req, res, next) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
    if (req.headers['x-warm-token'] === WARM_TOKEN && ehChamadaInterna(req)) return next();
    const site = String(req.headers['sec-fetch-site'] || '').toLowerCase();
    let deFora = !!site && site !== 'same-origin' && site !== 'none';
    const origem = String(req.headers.origin || '');
    if (!site && origem && origem !== 'null') { let host = ''; try { host = new URL(origem).host; } catch (e) {} deFora = host !== String(req.headers.host || ''); }
    if (deFora) return res.status(403).json({ success: false, ok: false, error: 'Pedido de outro site bloqueado.', erro: 'Pedido de outro site bloqueado.' });
    next();
});
// 🛡️ 16/10/2026: resposta da API (dados de clientes e agentes) não fica guardada no disco do navegador nem em proxy — o cache que vale é o do servidor
app.use('/api/', (req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

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

// 26/10/2026: teto de período das rotas que varrem `messages` por queryTickets (Tickets Atual, Tickets Geral e o Excel diário).
// Sem teto, um período de anos no calendário vira varredura longa no banco do Chatwoot. Mesmo porte do Time 48H (186 dias).
const TK_MAX_DIAS = 186;
function tkPeriodoValido(ini, fim) {   // '' = ok · texto = motivo da recusa
    const d1 = new Date(ini + 'T00:00:00Z'), d2 = new Date(fim + 'T00:00:00Z');
    if (isNaN(d1) || isNaN(d2)) return 'Período inválido.';
    const dias = Math.round((d2 - d1) / 86400000) + 1;
    if (!(dias >= 1)) return 'Período inválido.';
    return dias > TK_MAX_DIAS ? `Período máximo de ${TK_MAX_DIAS} dias (o escolhido tem ${dias}). Escolha uma faixa menor no calendário.` : '';
}

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
// 23/10/2026: EQUIPES POR LIDER — turno e pausa de cada agente (nome EXATO do Chatwoot).
// Fonte unica: as rotas devolvem o campo `lider`; a Produtividade usa turno/pausa daqui.
// ==========================================
const TK_ROTULO = { flavia: 'Fl\u00e1via', adevania: 'Adev\u00e2nia', camila: 'Camila' };
const TK_TURNOS = { flavia: '09:00-18:00', adevania: '15:00-00:00', camila: '08:00-17:00' };
const TK_EQUIPE = {
    // Flávia — turno 09:00-18:00
    "Alexandre Filho - 48H": ['flavia', '13:00-14:30'],
    "Aline Martins - RET": ['flavia', '12:00-13:30'],
    "Ana Godinho - SMS": ['flavia', '13:00-14:30'],
    "Ariane Akutsu - SAC": ['flavia', '13:00-14:30'],
    "Barbara Ferreira - RET": ['flavia', '13:00-14:30'],
    "Bruno Lima - SMS": ['flavia', '12:00-13:30'],
    "Daniel Martins - 48H": ['flavia', '12:00-13:30'],
    "Daryson Matheus - 48H": ['flavia', '12:00-13:30'],
    "Giovana Feitosa - BKO": ['flavia', '13:00-14:30'],
    "Graziela Donini - RET": ['flavia', '13:00-14:30'],
    "Lucas Andrade - RET": ['flavia', '12:00-13:30'],
    "Lucas Azeredo - SAC": ['flavia', '13:00-14:30'],
    "Luiza Cavalcante - RET": ['flavia', '13:00-14:30'],
    "Maria Moura - BKO": ['flavia', '12:00-13:30'],
    "Maryana Peres - SAC": ['flavia', '12:00-13:30'],
    "Patricia Figueredo - RET": ['flavia', '13:00-14:30'],
    "Rafaela França - SAC": ['flavia', '13:00-14:30'],
    "Raíssa Mesel - RET": ['flavia', '13:00-14:30'],
    "Susana Barros - SAC": ['flavia', '12:00-13:30'],
    "Thais Fadino - RET": ['flavia', '12:00-13:30'],
    "Wanya Silva - RET": ['flavia', '13:00-14:30'],
    // Adevânia — turno 15:00-00:00
    "Agatha Cezar - RET": ['adevania', '18:30-20:00'],
    "Ana Tonon - SAC": ['adevania', '18:30-20:00'],
    "Bianca Cruz - SAC": ['adevania', '18:30-20:00'],
    "Bruno Silva - 48H": ['adevania', '18:30-20:00'],
    "Dayane Santos - RET": ['adevania', '20:00-21:30'],
    "Gabriela Andrade - 48H": ['adevania', '20:00-21:30'],
    "Henrique Morais - RET": ['adevania', '20:00-21:30'],
    "Jessica Leite - SAC": ['adevania', '20:00-21:30'],
    "Jose Neto - RET": ['adevania', '21:00-22:30'],
    "Juan Lima - RET": ['adevania', '20:00-21:30'],
    "Keroline Alves - RET": ['adevania', '20:00-21:30'],
    "Miriam Sa - SAC": ['adevania', '18:30-20:00'],
    "Rayssa Silva - RET": ['adevania', '20:00-21:30'],
    "Simone Silva - RET": ['adevania', '18:30-20:00'],
    "Tharyck Guerra - RET": ['adevania', '18:30-20:00'],
    "Thaylle Lopes - SAC": ['adevania', '18:30-20:00'],
    // Camila — turno 08:00-17:00
    "Igor Silva - RET": ['camila', '11:00-12:30'],
    "Karla Santos - RET": ['camila', '11:00-12:30'],
    "Keuliane Moura - SMS": ['camila', '11:00-12:30'],
    "Maria Rodrigues - 48H": ['camila', '11:00-12:30'],
    "Mariana Xavier - SAC": ['camila', '11:00-12:30'],
    "Paula Araujo - BKO": ['camila', '11:00-12:30'],
    "Ellen Medeiros - RET": ['camila', '12:30-14:00'],
    "Fernanda Campos - BKO": ['camila', '12:30-14:00'],
    "Giovana Souza - SAC": ['camila', '12:30-14:00'],
    "Giovanna Lira - SAC": ['camila', '12:30-14:00'],
    "Humberto Souza - RET": ['camila', '12:30-14:00'],
    "Luana Sousa - RET": ['camila', '12:30-14:00'],
    "Mariana Cardoso - RET": ['camila', '12:30-14:00'],
    "Rebeca Silva - SMS": ['camila', '12:30-14:00'],
    "Rebeca Souza - RET": ['camila', '12:30-14:00'],
    "Thauane Garcia - 48H": ['camila', '12:30-14:00'],
    "Xaiane Celestino - SAC": ['camila', '12:30-14:00'],
};
function tkNorm(s) { return (s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/\s+/g, ' ').trim().toUpperCase(); }
const _tkIdxEq = {};
for (const _k in TK_EQUIPE) _tkIdxEq[tkNorm(_k)] = TK_EQUIPE[_k];
function tkLiderDe(nome) { const e = _tkIdxEq[tkNorm(nome)]; return e ? e[0] : null; }
function tkHM(s) { const p = String(s).split(':'); const v = (+p[0]) * 60 + (+p[1]); return v; }
// turno que termina 00:00 vira 1440 (nao cruza a meia-noite: fecha exatamente nela)
function tkJornadaDe(nome) {
    const e = _tkIdxEq[tkNorm(nome)];
    if (!e) return null;
    const t = TK_TURNOS[e[0]].split('-'), p = e[1].split('-');
    const fim = tkHM(t[1]) === 0 ? 1440 : tkHM(t[1]);
    const pf = tkHM(p[1]) === 0 ? 1440 : tkHM(p[1]);
    return { tIni: tkHM(t[0]), tFim: fim, pIni: tkHM(p[0]), pFim: pf, lider: e[0], turno: TK_TURNOS[e[0]], pausa: e[1] };
}

// ==========================================
// 2. SISTEMA DE LOGIN GOOGLE E SESSÕES
// ==========================================
app.get('/ping', (req, res) => res.status(200).send('Servidor GEX Ativo!'));

app.set('trust proxy', 1);

// 30/10/2026: store próprio no lugar do MemoryStore padrão do express-session — aquele avisava no log do Render e nunca apagava sessão vencida
// (a memória só crescia). Este apaga as vencidas a cada 15 min. Continua em memória: deploy/reinício do Render ainda desloga todo mundo.
class LojaSessoes extends session.Store {
    constructor() {
        super();
        this.sessoes = new Map(); // sid -> { json, vence }
        setInterval(() => this.limpar(), 15 * 60 * 1000).unref();
    }
    vencimento(sess) { return sess.cookie && sess.cookie.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 24 * 60 * 60 * 1000; }
    get(sid, cb) {
        const s = this.sessoes.get(sid);
        if (!s) return cb(null, null);
        if (s.vence <= Date.now()) { this.sessoes.delete(sid); return cb(null, null); }
        cb(null, JSON.parse(s.json));
    }
    set(sid, sess, cb) {
        this.sessoes.set(sid, { json: JSON.stringify(sess), vence: this.vencimento(sess) });
        if (cb) cb(null);
    }
    // só renova o vencimento (cookie), sem sobrescrever o resto da sessão guardada
    touch(sid, sess, cb) {
        const s = this.sessoes.get(sid);
        if (s) { const atual = JSON.parse(s.json); atual.cookie = sess.cookie; this.set(sid, atual); }
        if (cb) cb(null);
    }
    destroy(sid, cb) {
        this.sessoes.delete(sid);
        if (cb) cb(null);
    }
    limpar() {
        const agora = Date.now();
        for (const [sid, s] of this.sessoes) if (s.vence <= agora) this.sessoes.delete(sid);
    }
}

app.use(session({
    store: new LojaSessoes(),
    secret: process.env.SESSION_SECRET || 'chave_reserva_gex',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax', secure: 'auto' } // Sessão guardada por 30 dias · 16/10/2026: script da página não lê o cookie (httpOnly), ele não vai em pedido que nasce em outro site (sameSite) e no Render só trafega por HTTPS (secure auto)
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
    // 30/10/2026: domínio novo da operação (@gexcorp.com.br) liberado; o antigo continua valendo para quem ainda não migrou
    if (email.endsWith('@institutoexperience.com.br') || email.endsWith('@gexcorp.com.br')) return cb(null, profile);
    else return cb(null, false, { message: 'Acesso negado.' });
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Servir logo público para a tela de login ANTES do bloqueio
app.get('/logo.jpg', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logo.jpg')));

// 🎨 TELA DE LOGIN ESTILIZADA GEX — 31/10/2026: padrão da home da Alura (fundo preto, título fino, botão azul #052fd3) com animação própria em canvas: partículas que giram como esfera e se juntam no símbolo da GEX (lido do /logo.jpg). Com "reduzir movimento" no sistema, mostra o símbolo parado. Mesmo bloqueio de botão direito/atalhos do Dash.
app.get('/login', (req, res) => {
    if (req.isAuthenticated()) return res.redirect('/');
    res.send(`
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dash GEX · Acesso</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Encode+Sans:wght@200;300;500;600&family=Roboto+Flex:wght@200;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
    /* 🎨 31/10/2026: login no padrão da home da Alura (fundo preto, título fino Encode Sans 200, botão azul #052fd3 cantos 4px)
       com animação própria: partículas que giram como uma esfera e se juntam no símbolo da GEX (canvas; nada da Alura é reutilizado) */
    :root { --preto: #000; --azul: #052fd3; --azul-h: #0d3ee3; --azul-claro: #7a9ff0; --tinta: #ffffff; --mudo: #7b7f8e; --borda: #383a42; --sup: #131316; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { height: 100%; }
    body { background: var(--preto); color: var(--tinta); font-family: 'Roboto Flex', system-ui, sans-serif; -webkit-font-smoothing: antialiased; overflow: hidden; }
    img { -webkit-user-drag: none; -webkit-touch-callout: none; }
    #particulas { position: fixed; inset: 0; width: 100%; height: 100%; display: block; }
    .vinheta { position: fixed; inset: 0; pointer-events: none; background: radial-gradient(ellipse at 50% 42%, transparent 35%, rgba(0, 0, 0, 0.55) 75%, #000 100%); }

    /* topo: marca à esquerda, status à direita (como o menu flutuante da Alura, mais discreto) */
    .topo { position: fixed; top: 0; left: 0; right: 0; z-index: 3; display: flex; align-items: center; justify-content: space-between; padding: 26px clamp(16px, 6vw, 112px); }
    .marca { display: flex; align-items: center; gap: 12px; font-family: 'Encode Sans', sans-serif; font-weight: 500; font-size: 18px; letter-spacing: .01em; }
    .marca img { width: 36px; height: 36px; border-radius: 10px; border: 1px solid var(--borda); }
    .status { display: inline-flex; align-items: center; gap: 10px; padding: 9px 16px; border-radius: 999px; border: 1px solid var(--borda); background: rgba(19, 19, 22, 0.7); font: 500 11px/1 'JetBrains Mono', monospace; letter-spacing: .12em; text-transform: uppercase; color: #b2b4bd; -webkit-backdrop-filter: blur(8px); backdrop-filter: blur(8px); }
    .status i { width: 7px; height: 7px; border-radius: 99px; background: #01cb29; box-shadow: 0 0 0 3px rgba(1, 203, 41, 0.18), 0 0 10px rgba(1, 203, 41, 0.8); animation: pisca 2s ease-in-out infinite; }
    @keyframes pisca { 50% { opacity: .35; } }

    /* centro: título fino e grande sobre as partículas, frase que troca, botão */
    .centro { position: relative; z-index: 2; height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: flex-end; text-align: center; padding: 0 16px clamp(56px, 11vh, 120px); pointer-events: none; }
    .centro > * { pointer-events: auto; }
    h1 { font-family: 'Encode Sans', sans-serif; font-weight: 200; font-size: clamp(44px, 7.2vw, 96px); line-height: 1; letter-spacing: -0.01em; color: rgba(255, 255, 255, 0.92); }
    h1 b { font-weight: 600; color: #fff; }
    .frase { position: relative; margin-top: 18px; height: 1.4em; font-family: 'Encode Sans', sans-serif; font-weight: 200; font-size: clamp(18px, 2.2vw, 28px); color: rgba(255, 255, 255, 0.7); min-width: 10px; }
    .frase span { display: inline-block; transition: opacity .5s ease, transform .5s ease; }
    .frase span.sai { opacity: 0; transform: translateY(6px); }
    .entrar { margin-top: 40px; display: inline-flex; align-items: center; gap: 14px; height: 52px; padding: 0 18px 0 8px; border-radius: 4px; background: var(--azul); border: 1px solid var(--azul); color: #fff; text-decoration: none; font-weight: 500; font-size: 16px; transition: background-color .2s cubic-bezier(.4, 0, .2, 1), box-shadow .2s cubic-bezier(.4, 0, .2, 1); box-shadow: 0 18px 40px -16px rgba(5, 47, 211, 0.9); }
    .entrar:hover { background: var(--azul-h); border-color: var(--azul-h); box-shadow: 0 18px 44px -12px rgba(13, 62, 227, 1); }
    .entrar:focus-visible { outline: 2px dashed #fff; outline-offset: 4px; }
    .entrar .g { display: inline-flex; align-items: center; justify-content: center; width: 36px; height: 36px; border-radius: 3px; background: #fff; }
    .entrar .g svg { width: 18px; height: 18px; }
    .entrar .seta { width: 18px; height: 18px; transition: transform .2s ease; }
    .entrar:hover .seta { transform: translateX(3px); }
    .nota { margin-top: 16px; font-size: 13px; font-weight: 200; color: var(--mudo); }

    /* rodapé de HUD: coordenadas do cursor e assinatura */
    .hud { position: fixed; bottom: 22px; z-index: 3; font: 400 10px/1 'JetBrains Mono', monospace; letter-spacing: .14em; text-transform: uppercase; color: rgba(178, 180, 189, 0.55); }
    .hud.esq { left: clamp(16px, 6vw, 112px); }
    .hud.dir { right: clamp(16px, 6vw, 112px); }

    @media (max-width: 640px) { .status span { display: none; } .hud { display: none; } .entrar { margin-top: 30px; } }
    @media (max-height: 620px) { .centro { justify-content: center; padding-top: 90px; } }
</style>
</head>
<body>
    <canvas id="particulas" aria-hidden="true"></canvas>
    <div class="vinheta"></div>

    <header class="topo">
        <div class="marca"><img src="/logo.jpg" alt="Logo GEX"><span>Dash GEX</span></div>
        <div class="status"><i></i><span>Sistema online</span></div>
    </header>

    <main class="centro">
        <h1>Dash <b>GEX</b></h1>
        <p class="frase" aria-live="polite"><span id="frase">Performance da operação em tempo real.</span></p>
        <a class="entrar" href="/auth/google">
            <span class="g">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 15.02 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                </svg>
            </span>
            Entrar com o Google
            <svg class="seta" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg>
        </a>
        <p class="nota">Acesso restrito à operação · use a sua conta Google corporativa</p>
    </main>

    <div class="hud esq" id="hud-xy">x: 0000 · y: 0000</div>
    <div class="hud dir">GEX · Grupo Experience</div>

    <script>
        (function () {   /* 🔒 mesmo bloqueio do Dash: botão direito e atalhos que abrem o código */
            document.addEventListener('contextmenu', function (e) { e.preventDefault(); }, true);
            document.addEventListener('keydown', function (e) {
                var k = String(e.key || '').toLowerCase(), ctrl = e.ctrlKey || e.metaKey;
                if (e.key === 'F12' || (ctrl && !e.shiftKey && !e.altKey && (k === 'u' || k === 's')) || (ctrl && e.shiftKey && ['i', 'j', 'c', 'k'].indexOf(k) >= 0) || (e.metaKey && e.altKey && ['i', 'j', 'c', 'u'].indexOf(k) >= 0)) { e.preventDefault(); e.stopPropagation(); }
            }, true);
            document.addEventListener('dragstart', function (e) { if (e.target && e.target.nodeName === 'IMG') e.preventDefault(); }, true);
        })();

        (function () {   /* frase que troca (como o título da Alura) — sempre animada, a pedido do usuário */
            var frases = ['Performance da operação em tempo real.', 'Retenção, tickets e qualidade num só lugar.', 'Dados que viram decisão.'], i = 0, el = document.getElementById('frase');
            setInterval(function () { el.className = 'sai'; setTimeout(function () { i = (i + 1) % frases.length; el.textContent = frases[i]; el.className = ''; }, 500); }, 3800);
        })();

        (function () {   /* 31/10/2026: o G da GEX se MONTA — partículas vêm espalhadas e vão formando o símbolo em espiral, seguindo o círculo;
                            depois o G vira esfera girando (como a home da Alura) e se monta de novo. Sempre animado (mesmo com "reduzir movimento"). */
            var cv = document.getElementById('particulas'), ctx = cv.getContext('2d'), hud = document.getElementById('hud-xy');
            var W = 0, H = 0, DPR = 1, N = 3400, P = [], rotulos = [], mouse = { x: -9999, y: -9999 }, t0 = 0;
            var CORES = ['#0a2cff', '#0a2cff', '#1f45ff', '#1f45ff', '#2f5bff', '#3d63ff', '#4d74ff', '#6f8cff', '#9ab7f3', '#d1def9'];
            var CICLO = 16000, MONTA_INI = 250, MONTA_ESPALHA = 2000, MONTA_DUR = 1900, FIM_MONTA = 4800, DESFAZ_INI = 11200, DESFAZ_FIM = 13200;
            function medir() { DPR = Math.min(2, window.devicePixelRatio || 1); W = innerWidth; H = innerHeight; cv.width = W * DPR; cv.height = H * DPR; ctx.setTransform(DPR, 0, 0, DPR, 0, 0); }
            function esfera(k, n) { var y = 1 - (k + 0.5) / n * 2, r = Math.sqrt(1 - y * y), a = k * 2.399963; return [Math.cos(a) * r * 0.82, y * 0.82, Math.sin(a) * r * 0.82]; }
            function nuvem() { var u = Math.random() * 2 - 1, a = Math.random() * 6.283, r = 1.5 + Math.random() * 1.6, q = Math.sqrt(1 - u * u); return [Math.cos(a) * q * r * 1.6, u * r, Math.sin(a) * q * r * 0.45]; }   /* nuvem achatada na profundidade: nada passa perto da câmera */
            function montar(alvos) {
                P = [];
                for (var k = 0; k < N; k++) {
                    var s = esfera(k, N), a = alvos.length ? alvos[Math.floor(Math.random() * alvos.length)] : s;
                    var lx = a[0] + (Math.random() - 0.5) * 0.012, ly = a[1] + (Math.random() - 0.5) * 0.012;
                    var ang = (Math.atan2(lx, -ly) + 6.2832) % 6.2832 / 6.2832;   /* posição no círculo, a partir do topo, sentido horário: ordem de montagem */
                    P.push({ s: s, n: nuvem(), l: [lx, ly, (Math.random() - 0.5) * 0.14], ang: ang, atraso: ang * MONTA_ESPALHA + Math.random() * 260, c: CORES[Math.floor(Math.random() * CORES.length)], tam: 1.4 + Math.random() * 2.6, ox: 0, oy: 0, fase: Math.random() * 6.283 });
                }
            }
            function pontosDoLogo(pronto) {   /* lê os pixels claros do logo (fundo navy, símbolo branco) e vira a forma-alvo */
                var img = new Image();
                img.onload = function () {
                    try {
                        var c = document.createElement('canvas'), L = 160; c.width = L; c.height = L;
                        var g = c.getContext('2d'); g.drawImage(img, 0, 0, L, L);
                        var d = g.getImageData(0, 0, L, L).data, pts = [];
                        for (var y = 0; y < L; y += 1) for (var x = 0; x < L; x += 1) { var i = (y * L + x) * 4; if (d[i] + d[i + 1] + d[i + 2] > 520) pts.push([(x / L - 0.5) * 2.1, (y / L - 0.5) * 2.1]); }
                        pronto(pts.length > 200 ? pts : []);
                    } catch (e) { pronto([]); }
                };
                img.onerror = function () { pronto([]); };
                img.src = '/logo.jpg';
            }
            function lim(x) { return x < 0 ? 0 : x > 1 ? 1 : x; }
            function suave(x) { x = lim(x); return x * x * (3 - 2 * x); }
            function saida(x) { x = lim(x); return 1 - Math.pow(1 - x, 3); }
            function escolherRotulos() { rotulos = []; for (var k = 0; k < 6; k++) rotulos.push(Math.floor(Math.random() * N)); }
            function quadro(agora) {
                var ms = agora - t0, q = ms % CICLO, primeira = ms < CICLO, tempo = ms / 1000;
                var cel = W < 640, R = cel ? Math.min(W * 0.40, H * 0.24) : Math.min(W * 0.27, H * 0.30, 330), cx = W / 2, cy = H * (cel ? 0.38 : 0.40), K = cel ? 0.62 : 1;
                /* quanto o conjunto está "G" (para o giro): sobe durante a montagem, 1 parado, desce ao desfazer, 0 na esfera */
                var g = q < FIM_MONTA ? suave((q - MONTA_INI) / (MONTA_ESPALHA + MONTA_DUR)) : q < DESFAZ_INI ? 1 : q < DESFAZ_FIM ? 1 - suave((q - DESFAZ_INI) / (DESFAZ_FIM - DESFAZ_INI)) : 0;
                var desfaz = q >= DESFAZ_INI ? suave((q - DESFAZ_INI) / (DESFAZ_FIM - DESFAZ_INI)) : 0;
                var giro = (1 - g) * tempo * 0.6 + g * Math.sin(tempo * 0.45) * 0.35, inc = 0.18 * (1 - g) + Math.sin(tempo * 0.3) * 0.05 * g;
                var cg = Math.cos(giro), sg = Math.sin(giro), ci = Math.cos(inc), si = Math.sin(inc), D = 3.2;
                ctx.clearRect(0, 0, W, H);
                var brilho = ctx.createRadialGradient(cx, cy, 0, cx, cy, R * 1.25);
                brilho.addColorStop(0, 'rgba(10, 44, 255, ' + (0.08 + 0.14 * g) + ')'); brilho.addColorStop(0.55, 'rgba(10, 44, 255, 0.05)'); brilho.addColorStop(1, 'rgba(10, 44, 255, 0)');
                ctx.fillStyle = brilho; ctx.fillRect(cx - R * 1.3, cy - R * 1.3, R * 2.6, R * 2.6);
                ctx.globalCompositeOperation = 'lighter';
                var proj = new Array(N), faiscas = [];
                for (var k = 0; k < N; k++) {
                    var p = P[k], x, y, z, mp;
                    if (q < DESFAZ_INI) {   /* montagem (e o G parado): cada partícula sai da origem no seu momento e vem em espiral */
                        mp = q < FIM_MONTA + 400 ? saida((q - MONTA_INI - p.atraso) / MONTA_DUR) : 1;
                        var o = primeira ? p.n : p.s, onda = mp * Math.sin(tempo * 1.6 + p.fase) * 0.035;
                        x = o[0] + (p.l[0] - o[0]) * mp; y = o[1] + (p.l[1] - o[1]) * mp; z = o[2] + (p.l[2] + onda - o[2]) * mp;
                        var vira = (1 - mp) * 2.4, cv2 = Math.cos(vira), sv2 = Math.sin(vira), xr = x * cv2 - y * sv2; y = x * sv2 + y * cv2; x = xr;
                        if (mp > 0.82 && mp < 0.995) faiscas.push(k);
                    } else {   /* o G se desfaz numa esfera e a esfera gira */
                        mp = 1 - desfaz;
                        x = p.l[0] + (p.s[0] - p.l[0]) * desfaz; y = p.l[1] + (p.s[1] - p.l[1]) * desfaz; z = p.l[2] + (p.s[2] - p.l[2]) * desfaz;
                    }
                    var x1 = x * cg + z * sg, z1 = -x * sg + z * cg, y1 = y * ci - z1 * si, z2 = y * si + z1 * ci;
                    var e = Math.min(2.2, D / (D - z2)), px = cx + x1 * R * e, py = cy + y1 * R * e;
                    var dx = px - mouse.x, dy = py - mouse.y, d2 = dx * dx + dy * dy;
                    if (d2 < 12000) { var f = (1 - d2 / 12000) * 18, dd = Math.sqrt(d2) || 1; p.ox += (dx / dd * f - p.ox) * 0.18; p.oy += (dy / dd * f - p.oy) * 0.18; } else { p.ox *= 0.9; p.oy *= 0.9; }
                    px += p.ox; py += p.oy;
                    var prof = lim((z2 + 1.6) / 3.2), s = p.tam * K * e * (0.75 + g * 0.25);
                    ctx.globalAlpha = Math.max(0.18, Math.min(1, 0.32 + prof * 0.9));
                    ctx.fillStyle = p.c;
                    ctx.fillRect(px - s / 2, py - s / 2, s, s);
                    proj[k] = [px, py, prof];
                }
                /* faísca branca quando a partícula chega no lugar dela */
                ctx.fillStyle = '#ffffff';
                for (var fk = 0; fk < faiscas.length; fk += 2) { var fq = proj[faiscas[fk]]; ctx.globalAlpha = 0.85; ctx.fillRect(fq[0] - 1.5, fq[1] - 1.5, 3, 3); }
                for (var b = 0; b < N; b += 23) { var bq = proj[b]; if (bq[2] > 0.62) { ctx.globalAlpha = 0.5 * Math.abs(Math.sin(tempo * 2 + b)); ctx.fillRect(bq[0] - 1, bq[1] - 1, 2, 2); } }
                ctx.globalCompositeOperation = 'source-over';
                /* arco de varredura acompanhando a montagem do G (de cima, sentido horário) */
                if (q > MONTA_INI && q < FIM_MONTA + 300) {
                    var frente = lim((q - MONTA_INI) / (MONTA_ESPALHA + 400)), aa = -Math.PI / 2 + frente * Math.PI * 2, rr = R * 1.13;
                    ctx.globalAlpha = 0.85 * (1 - suave((q - FIM_MONTA + 500) / 800));
                    ctx.strokeStyle = 'rgba(122, 159, 240, 0.9)'; ctx.lineWidth = 1.5;
                    ctx.beginPath(); ctx.arc(cx, cy, rr, aa - 0.5, aa); ctx.stroke();
                    ctx.fillStyle = '#ffffff'; ctx.fillRect(cx + Math.cos(aa) * rr - 2, cy + Math.sin(aa) * rr - 2, 4, 4);
                    ctx.font = '400 10px JetBrains Mono, monospace'; ctx.textBaseline = 'middle'; ctx.fillStyle = 'rgba(255, 255, 255, 0.7)';
                    ctx.fillText('GEX · ' + Math.round(frente * 100) + '%', cx + Math.cos(aa) * (rr + 14) - (Math.cos(aa) < 0 ? 62 : 0), cy + Math.sin(aa) * (rr + 14));
                }
                /* coordenadas flutuando junto de algumas partículas (toque "tech" da referência) */
                ctx.font = '400 10px JetBrains Mono, monospace'; ctx.textBaseline = 'middle';
                var feitos = [];
                for (var r = 0; r < rotulos.length; r++) {
                    var u = proj[rotulos[r]]; if (!u || u[2] < 0.45) continue;
                    var perto = false; for (var f2 = 0; f2 < feitos.length; f2++) { if (Math.abs(feitos[f2][0] - u[0]) < 150 && Math.abs(feitos[f2][1] - u[1]) < 26) perto = true; } if (perto) continue; feitos.push(u);
                    ctx.globalAlpha = 0.5; ctx.strokeStyle = 'rgba(181, 203, 246, 0.6)'; ctx.lineWidth = 1;
                    ctx.beginPath(); ctx.moveTo(u[0] + 3, u[1]); ctx.lineTo(u[0] + 22, u[1] - 12); ctx.stroke();
                    ctx.fillStyle = 'rgba(255, 255, 255, 0.75)';
                    ctx.fillText('x: ' + Math.round(u[0]) + '  y: ' + Math.round(u[1]), u[0] + 26, u[1] - 12);
                }
                ctx.globalAlpha = 1;
                requestAnimationFrame(quadro);
            }
            addEventListener('resize', medir);
            addEventListener('pointermove', function (e) { mouse.x = e.clientX; mouse.y = e.clientY; hud.textContent = 'x: ' + String(Math.round(e.clientX)).padStart(4, '0') + ' · y: ' + String(Math.round(e.clientY)).padStart(4, '0'); });
            addEventListener('pointerleave', function () { mouse.x = -9999; mouse.y = -9999; });
            medir();
            pontosDoLogo(function (alvos) {
                if (W < 640) N = 1900;
                montar(alvos); escolherRotulos();
                setInterval(escolherRotulos, 3200);
                t0 = performance.now();
                requestAnimationFrame(quadro);
            });
        })();
    </script>
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
            role: adms.includes(email) ? 'admin' : 'agente',
            acessos: { adiar: ehDonoAdiar(req), telegram: !!tgEhAdmin(req), raiox: ehDonoRaioX(req) }   // 🔒 16/10/2026: o que este login vê (mesmas listas do Render que as rotas conferem) — antes o index tinha os e-mails escritos no código
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
const ROTAS_DO_DONO_CACHE = ['/api/casos-para-adiar', '/api/adiar-casos', '/api/transferir/', '/api/telegram/', '/api/raio-x-perf'];   // 🛡️ 16/10/2026: rotas de um dono só (EMAILS_ADIAR / EMAILS_TELEGRAM / EMAILS_RAIOX): cache por e-mail
const cacheMiddleware = (req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') return next();   // 14/10/2026: ação (POST) nunca usa nem guarda cache — o 2º "Adiar casos" em 30 min não rodava
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
    // 🛡️ 16/10/2026: cache separado por perfil — o que foi buscado por um admin nunca é entregue a um agente. Antes a chave era só a URL: quem abrisse
    // /api/time48 (ou outra rota de admin) direto no navegador recebia o dado guardado do admin sem passar pela trava da rota. Rota do dono: pelo e-mail.
    const _rotaDono = ROTAS_DO_DONO_CACHE.some(p => chaveUrl.toLowerCase().startsWith(p));
    const _emailCache = ((req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value : '').toLowerCase();
    chaveUrl = (_rotaDono ? 'dono:' + _emailCache : (ehAdminReq(req) ? 'admin' : 'agente')) + ' ' + chaveUrl;

    if (chaveUrl.includes('/api/raio-x-perf')) return next(); // Raio-X de Desempenho: sempre ao vivo, nunca cacheado

    // 🛡️ PROTEÇÃO DoS: Se o cache inchar de forma anormal, limpa a memória
    if (Object.keys(cacheMemoria).length > MAX_CACHE_KEYS) {
        console.warn("🚨 ALERTA: Limite de cache atingido. Esvaziando memória para prevenir Memory Exhaustion (DoS).");
        cacheMemoria = {}; 
        tempoRotas = {};   // 14/10/2026: o tempo por rota (Raio-X) é limpo junto com o cache — antes guardava toda URL já pedida, sem limite
    }

    // Lógica inteligente: Planilhas = 15 min / Banco de Dados (Tickets puros) = 30 min
    let tempoCacheMinutos = 30; 
    if (chaveUrl.includes('/api/qualidade') || chaveUrl.includes('/api/retencao') || chaveUrl.includes('/api/sinalizacoes')) {
        tempoCacheMinutos = 15;
    }

    // 14/10/2026: ?fresh=1 de AGENTE só fura o cache se o dado guardado tiver mais de 1 min (o 🔄 Recarregar do Tickets Atual do agente continua; repetir fresh=1 não martela o banco). Admin e chamada interna furam sempre.
    // 26/10/2026: a trava de refresh passa a valer para TODO MUNDO (antes só o agente era segurado).
    // agente e admin: 1 min · chamada interna (aquecedor e bot do Telegram): 4 min — o bot roda de 5 em 5 min, então
    // não perde atualização; só para de repetir no banco uma consulta que alguém acabou de fazer.
    // Isentas da trava: recarregadas logo DEPOIS de uma ação (precisam do dado novo na hora) ou que nem leem o Postgres do Chatwoot.
    const ROTAS_SEM_TRAVA_REFRESH = ['/api/casos-para-adiar', '/api/q3'];
    const _semTrava = ROTAS_SEM_TRAVA_REFRESH.some(r => chaveUrl.includes(r));
    const _interno = req.headers['x-warm-token'] === WARM_TOKEN && ehChamadaInterna(req);
    const _janelaFura = _interno ? 4 * 60 * 1000 : 60 * 1000;
    if (bypass && !_semTrava && cacheMemoria[chaveUrl] && agora - cacheMemoria[chaveUrl].tempo < _janelaFura) bypass = false;
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
        if (dados && dados.success && !dados.sem_cache) {   // 14/10/2026: resposta com sem_cache: true é entregue normalmente, mas não fica guardada
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
const WARM_TOKEN = process.env.WARM_TOKEN || require('crypto').randomBytes(32).toString('hex');   // 14/10/2026: sem WARM_TOKEN no ambiente, senha aleatória criada ao ligar (só o próprio servidor usa) — antes valia a senha escrita aqui
// 14/10/2026: a senha interna só vale em chamada do PRÓPRIO servidor (aquecedor, bot do Telegram, Pergunte ao Dash: http.get em 127.0.0.1, sem proxy no meio)
const ehChamadaInterna = (req) => ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket && req.socket.remoteAddress) && !req.headers['x-forwarded-for'];
const EMAIL_ADM_WARM = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',')[0].trim();
let ultimoAcessoApi = 0;
app.use('/api', (req, res, next) => {
    if (req.headers['x-warm-token'] === WARM_TOKEN && ehChamadaInterna(req)) {   // 14/10/2026: + só do próprio servidor
        req.user = { emails: [{ value: EMAIL_ADM_WARM }], role: 'admin' };
        req.isAuthenticated = () => true;
    } else {
        ultimoAcessoApi = Date.now();
    }
    next();
});
app.use('/api', verificarLogin, cacheMiddleware);
// 🛡️ 16/10/2026: rota de tela de admin — o servidor confere (antes só o botão ficava escondido para o agente)
const soAdmin = (req, res, next) => ehAdminReq(req) ? next() : res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
// 🔒 16/10/2026: o index.html sai por aqui (e não direto da pasta): admin recebe o arquivo inteiro; agente recebe sem os blocos marcados
// ADMIN-HTML-INI/FIM e ADMIN-JS-INI/FIM (telas e código de gestão) — o código das telas de admin não chega no navegador de quem não é admin.
// Se os marcadores estiverem quebrados (INI sem FIM), o agente recebe o arquivo inteiro e fica um aviso no log: a tela dele nunca quebra.
const ARQ_INDEX = path.join(__dirname, 'public', 'index.html');
let indexMem = { mtime: -1, admin: '', agente: '' };
function versaoAgenteIndex(html) {
    const marc = [...html.matchAll(/ADMIN-(HTML|JS)-(INI|FIM): ([^*>]*?)\s*(?:-->|\*\/)/g)].map(m => m[1] + '|' + m[2] + '|' + m[3]);
    for (let k = 0; k < marc.length; k += 2) {
        const a = (marc[k] || '').split('|'), b = (marc[k + 1] || '').split('|');
        if (a[1] !== 'INI' || b[1] !== 'FIM' || a[0] !== b[0] || a[2] !== b[2]) { console.warn('⚠️ index.html: marcadores ADMIN-* quebrados perto de', marc[k], '— o agente recebe o arquivo inteiro'); return html; }
    }
    return html.replace(/[ \t]*<!-- ADMIN-HTML-INI: [^>]*-->[\s\S]*?<!-- ADMIN-HTML-FIM: [^>]*-->[ \t]*(\r?\n)?/g, '')
               .replace(/[ \t]*\/\* ADMIN-JS-INI: [^*]*\*\/[\s\S]*?\/\* ADMIN-JS-FIM: [^*]*\*\/[ \t]*(\r?\n)?/g, '');
}
// 🔒 30/10/2026: o index sai ENXUTO para o navegador — sem comentários (HTML, CSS e JS) e sem indentação. Não muda o que a página faz:
// cada <script> enxugado tem a sintaxe conferida (vm.Script) e, se não passar, aquele bloco sai como estava. Se der qualquer erro, sai o arquivo inteiro como antes.
// Acompanha o bloqueio de botão direito/atalhos que está no próprio index. (Esconder 100% não existe: o navegador precisa receber o código para mostrar a tela.)
const vmEnxugar = require('vm');

function enxugarJs(src) {
    const linhas = []; let ln = '', i = 0, inicioLinha = true;
    const n = src.length, pilha = []; let chaves = 0;   // pilha: templates abertos (profundidade de chaves de cada ${ })
    const PALAVRAS = /(?:^|[^\w$])(return|typeof|case|do|else|in|of|new|delete|void|throw|yield|await|instanceof)$/;
    const SIMBOLOS = '(,=:[!&|?{};+-*%<>~^';
    const regexPode = () => {
        let t = ln.trimEnd();
        for (let k = linhas.length - 1; !t && k >= 0; k--) t = linhas[k];
        if (!t) return true;
        return SIMBOLOS.includes(t[t.length - 1]) || PALAVRAS.test(t.slice(-12));
    };
    const fimLinha = () => { ln = ln.trimEnd(); if (ln) linhas.push(ln); ln = ''; inicioLinha = true; };
    function lerString(q) {
        const a = i; i++;
        while (i < n) { const c = src[i]; i++; if (c === '\\') { i++; continue; } if (c === q || c === '\n') break; }
        return src.slice(a, i);
    }
    function lerTemplate() {   // texto de template até a crase (fecha) ou ${ (abre expressão)
        const a = i;
        while (i < n) {
            const c = src[i];
            if (c === '\\') { i += 2; continue; }
            if (c === '`') { i++; return { s: src.slice(a, i), fechou: true }; }
            if (c === '$' && src[i + 1] === '{') { i += 2; return { s: src.slice(a, i), fechou: false }; }
            i++;
        }
        return { s: src.slice(a, i), fechou: true };
    }
    function lerRegex() {
        const a = i; let classe = false; i++;
        while (i < n) {
            const c = src[i]; i++;
            if (c === '\\') { i++; continue; }
            if (c === '[') classe = true; else if (c === ']') classe = false;
            else if ((c === '/' && !classe) || c === '\n') break;
        }
        while (i < n && /[a-z]/i.test(src[i])) i++;
        return src.slice(a, i);
    }
    const ESPECIAIS = new Set(['/', '"', "'", '`', '{', '}', '\r', '\n']);
    while (i < n) {
        const c = src[i], d = src[i + 1];
        if (inicioLinha && (c === ' ' || c === '\t')) { i++; continue; }
        if (c === '\r') { i++; continue; }
        if (c === '\n') { fimLinha(); i++; continue; }
        inicioLinha = false;
        if (c === '/' && d === '/') { while (i < n && src[i] !== '\n') i++; continue; }
        if (c === '/' && d === '*') {
            const f = src.indexOf('*/', i + 2), e = f < 0 ? n : f + 2, multi = src.slice(i, e).includes('\n');
            i = e; if (multi) fimLinha(); else if (ln && !/\s$/.test(ln)) ln += ' ';
            continue;
        }
        if (c === '"' || c === "'") { ln += lerString(c); continue; }
        if (c === '`') { i++; const r = lerTemplate(); ln += '`' + r.s; if (!r.fechou) { pilha.push(chaves); chaves = 0; } continue; }
        if (c === '/' && regexPode()) { ln += lerRegex(); continue; }
        if (c === '{') { chaves++; ln += c; i++; continue; }
        if (c === '}') {
            if (pilha.length && chaves === 0) { i++; const r = lerTemplate(); ln += '}' + r.s; if (r.fechou) chaves = pilha.pop(); continue; }
            chaves--; ln += c; i++; continue;
        }
        let j = i + 1; while (j < n && !ESPECIAIS.has(src[j])) j++;   // trecho comum de código: copia de uma vez
        ln += src.slice(i, j); i = j;
    }
    fimLinha();
    return linhas.join('\n');
}

function enxugarCss(src) {
    let out = '', i = 0;
    while (i < src.length) {
        const c = src[i];
        if (c === '"' || c === "'") { const j = src.indexOf(c, i + 1); out += src.slice(i, j < 0 ? src.length : j + 1); i = j < 0 ? src.length : j + 1; continue; }
        if (c === '/' && src[i + 1] === '*') { const f = src.indexOf('*/', i + 2); i = f < 0 ? src.length : f + 2; continue; }
        out += c; i++;
    }
    return out.split(/\r?\n/).map(l => l.trim()).filter(Boolean).join('\n');
}

function enxugarHtml(html) {
    const partes = html.split(/(<script\b[^>]*>[\s\S]*?<\/script>|<style\b[^>]*>[\s\S]*?<\/style>|<pre\b[\s\S]*?<\/pre>|<textarea\b[\s\S]*?<\/textarea>)/i);
    let falhas = 0;
    const saida = partes.map((p, k) => {
        if (k % 2 === 0) return p.replace(/<!--(?!\[if)[\s\S]*?-->/g, '').split(/\r?\n/).map(l => l.trim()).filter(Boolean).join('\n');
        if (/^<pre|^<textarea/i.test(p)) return p;
        const m = /^(<(script|style)\b[^>]*>)([\s\S]*?)(<\/\2>)$/i.exec(p);
        if (!m) return p;
        if (m[2].toLowerCase() === 'style') return m[1] + '\n' + enxugarCss(m[3]) + '\n' + m[4];
        if (/\bsrc=/.test(m[1]) || !m[3].trim()) return p;
        try { const js = enxugarJs(m[3]); new vmEnxugar.Script(js); return m[1] + '\n' + js + '\n' + m[4]; }
        catch (e) { falhas++; return p; }   // não passou na conferência: sai como estava
    }).join('\n');
    if (falhas) console.warn('🔒 enxugar index:', falhas, 'bloco(s) de script saíram sem enxugar (a conferência de sintaxe não passou)');
    return saida;
}
function enxugarIndex(html) {
    try { return enxugarHtml(html); } catch (e) { console.warn('🔒 enxugar index falhou, vai o arquivo como está:', e.message); return html; }
}
function indexDoPerfil(admin) {
    const st = fs.statSync(ARQ_INDEX);
    if (st.mtimeMs !== indexMem.mtime) { const html = fs.readFileSync(ARQ_INDEX, 'utf8'); indexMem = { mtime: st.mtimeMs, admin: enxugarIndex(html), agente: enxugarIndex(versaoAgenteIndex(html)) }; }   // 🔒 30/10/2026: enxuto (sem comentários) — os marcadores ADMIN-* são cortados ANTES
    return admin ? indexMem.admin : indexMem.agente;
}
app.get(['/', '/index.html'], verificarLogin, (req, res) => {
    let html;
    try { html = indexDoPerfil(ehAdminReq(req)); } catch (e) { console.error('[index]', e.message); return res.status(500).send('Não achei o index.html na pasta public.'); }
    res.set({ 'Cache-Control': 'no-store', 'Vary': 'Cookie' });   // a versão do admin não fica guardada no navegador para o próximo login da mesma máquina
    res.type('html').send(html);
});
// 🔎 16/10/2026: para o admin conferir o que chega no navegador do agente — mostra o código da versão do agente como texto (agente não abre)
app.get('/versao-agente.txt', verificarLogin, (req, res) => {
    if (!ehAdminReq(req)) return res.status(403).type('text').send('Acesso restrito para Administradores.');
    let html;
    try { html = indexDoPerfil(false); } catch (e) { console.error('[versao-agente]', e.message); return res.status(500).type('text').send('Não achei o index.html na pasta public.'); }
    res.set({ 'Cache-Control': 'no-store' });
    res.type('text/plain; charset=utf-8').send(html);
});
// 🔒 16/10/2026: da pasta public saem só imagens (logo) — nenhum outro arquivo que cair na pasta (cópia do index, planilha, backup) fica aberto
const publicoEstatico = express.static(path.join(__dirname, 'public'), { index: false });
const PASTA_PUBLIC = path.join(__dirname, 'public'), publicoBloqueadoAvisado = new Set();
app.use(verificarLogin, (req, res, next) => {
    if (/\.(jpe?g|png|gif|svg|ico|webp)$/i.test(req.path)) return publicoEstatico(req, res, next);
    try {   // arquivo que existe na pasta mas não é imagem: fica bloqueado e avisa 1x no log do Render (se alguma tela precisar dele, o nome aparece lá)
        const alvo = path.normalize(path.join(PASTA_PUBLIC, decodeURIComponent(req.path)));
        if (alvo.startsWith(PASTA_PUBLIC + path.sep) && !publicoBloqueadoAvisado.has(alvo) && fs.existsSync(alvo) && fs.statSync(alvo).isFile()) { publicoBloqueadoAvisado.add(alvo); console.warn('🔒 pasta public: bloqueei', path.relative(PASTA_PUBLIC, alvo), '— da pasta só saem imagens (o index sai pela rota própria)'); }
    } catch (e) { /* caminho malformado: segue para o 404 */ }
    next();
});

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
// 30/10/2026: l\u00edder do agente aceitando TAMB\u00c9M o nome sem o sufixo de time \u2014 a Qualidade manda "ALINE MARTINS" e o
// TK_EQUIPE tem "Aline Martins - RET". Fonte \u00fanica continua o TK_EQUIPE e a normaliza\u00e7\u00e3o \u00e9 a que o Dash j\u00e1 usa
// (tkNorm primeiro, normalizeNome depois). Nos 54 agentes de hoje os nomes curtos s\u00e3o todos distintos (sem empate).
const _tkIdxEqCurto = {};
for (const _kCurto in TK_EQUIPE) _tkIdxEqCurto[normalizeNome(_kCurto)] = TK_EQUIPE[_kCurto];
function tkLiderDeNome(nome) { const e = _tkIdxEq[tkNorm(nome)] || _tkIdxEqCurto[normalizeNome(nome)]; return e ? e[0] : null; }
const vincularTickets = (nomePlanilha, ticketsMap, totalSemanas, nomesDaPlanilha) => {   // 14/10/2026: nomesDaPlanilha (opcional) = nomes que já estão na planilha
    const nomeLimpo = normalizeNome(nomePlanilha);
    let agenteEncontrado = ticketsMap[nomeLimpo];

    if (!agenteEncontrado) {
        const partes = nomeLimpo.split(' ');
        const primeiroNome = partes[0];
        const candidatos = Object.keys(ticketsMap).filter(k => k.split(' ')[0] === primeiroNome && !(nomesDaPlanilha && nomesDaPlanilha.has(k)));   // 14/10/2026: quem está na planilha com o próprio nome não empresta os tickets para outra linha (antes contava 2x)
        if (candidatos.length === 1) agenteEncontrado = ticketsMap[candidatos[0]];
        else if (candidatos.length > 1 && partes.length > 1) {
            for (let c of candidatos) {
                const ultimoPlanilha = partes[partes.length - 1];
                if (c.split(' ').includes(ultimoPlanilha) || (!['DA', 'DE', 'DO', 'DAS', 'DOS'].includes(partes[1]) && c.split(' ').includes(partes[1]))) {   // 14/10/2026: palavra inteira e sem "de/da/do" (antes o "DE" de "Maria de Souza" casava dentro de "FERNANDES")
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
        const anoPlanilha = agoraBR.getFullYear();   // 14/10/2026: ano atual de Brasília (antes fixo em 2026); o ano de cada aba sai de ordemDaAbaRet

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
        // 14/10/2026: aba padrão = a do mês atual de Brasília; se ainda não existir, a mais recente (antes fixa em "Outubro": em 01/11 o agente continuava vendo Outubro).
        // Mês depois do atual é do ano anterior ("Dezembro" vista em janeiro/2027 = 2026).
        const ordemDaAbaRet = (aba) => { const m = MESES_PT.findIndex(mm => aba.toLowerCase().includes(mm.toLowerCase())); return (m > agoraBR.getMonth() ? anoPlanilha - 1 : anoPlanilha) * 12 + m; };
        const abaDoMesAtualRet = '📊 Análise | Metas | ' + MESES_PT[agoraBR.getMonth()];
        const PADRAO_ABA = abasDisponiveis.includes(abaDoMesAtualRet) ? abaDoMesAtualRet : (abasDisponiveis.reduce((melhor, t) => (melhor === null || ordemDaAbaRet(t) > ordemDaAbaRet(melhor)) ? t : melhor, null) || abaDoMesAtualRet);
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
            const anoPlanilha = Math.floor(ordemDaAbaRet(aba) / 12);   // 14/10/2026: ano desta aba (mês depois do atual = ano anterior)
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
                const dd = new Date((row.dia instanceof Date ? row.dia.toISOString() : String(row.dia)).split('T')[0] + 'T12:00:00Z');   // 14/10/2026: o pg devolve a data como Date — String(Date) ("Thu Oct 01…") virava data inválida e o hist_tickets saía zerado
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
            const nomesDaPlanilha = new Set(rows.slice(10).map(r => normalizeNome(String(r[3] || r[2] || '').trim())).filter(Boolean));   // 14/10/2026: para o vincularTickets não emprestar tickets de quem já está na planilha
            rows.slice(10).filter(r => String(r[3] || r[2] || '').trim() !== '' && parseMoeda(r[6] || r[7]) > 0).forEach(row => {
                const nome = String(row[3] || row[2] || '').trim();
                const nb = normalizeNome(nome);
                const tk = vincularTickets(nome, tkMap, nSem, nomesDaPlanilha);   // 14/10/2026: + nomesDaPlanilha
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

        selecionadas.sort((a, b) => ordemDaAbaRet(a) - ordemDaAbaRet(b));   // 14/10/2026: ordem por ano + mês (antes só pelo mês: Janeiro/2027 vinha antes de Dezembro/2026)
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
// 30/10/2026: nome da BASE_MONITORIA → nome no Chatwoot (TK_EQUIPE), só para achar o líder. Sem isso esses analistas sumiam das abas por líder.
const QUAL_NOME_CHATWOOT = {
    'HENRIQUE MORAES': 'Henrique Morais - RET',
    'REBECA SOUSA': 'Rebeca Souza - RET',
    'SUSANA GARCIA': 'Susana Barros - SAC',
    'PATRICIA MAIA': 'Patricia Figueredo - RET',
    'DARYSON NASCIMENTO': 'Daryson Matheus - 48H',
    'GABRIELA PENHA': 'Gabriela Andrade - 48H',
};
// 30/10/2026: quem saiu da empresa não está mais no Chatwoot, mas as monitorias do mês continuam contando para o time em que estava (como no relatório da Qualidade)
const QUAL_LIDER_DE_QUEM_SAIU = { 'LAVINIA BOAVENTURA': 'flavia', 'VERONICA OLIVEIRA': 'flavia', 'WILLIAN SANTOS': 'flavia' };

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
        const response = await sheets.spreadsheets.values.get({ spreadsheetId: sheetIdQualidade, range: `'BASE_MONITORIA'!A1:Z` });   // 14/10/2026: aba inteira (antes só até a linha 5000: o mês novo sumia sem aviso)
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

            monitoriasGerais.push({ mes: mesRaw, nome: nomeFormatado, time: siglaSetor, qual: nota, ciclo: cicloNum, nomeOriginal: nomeRaw, adapt: siglaSetor === 'ADAPTACAO' });
        }

        const meses = Array.from(mesesSet).sort(qualMesesDoMaisNovo);   // mês mais novo primeiro (calendário, não alfabeto) 
        const mesSelecionado = req.query.mes || (meses.length > 0 ? meses[0] : '');
        const monitoriasDoMes = monitoriasGerais.filter(m => m.mes === mesSelecionado);

        // 30/10/2026: mesma regra do relatório da Qualidade — a monitoria de Adaptação (C1 do analista novo) aparece, mas não entra na média;
        // a nota do analista é a média dos ciclos dele (2 monitorias no mesmo ciclo viram a média das duas) e o setor é o da 1ª monitoria fora da Adaptação.
        // Antes: média de todas as linhas (com a Adaptação) e setor da 1ª linha do mês (o novato ficava "Adaptação" o mês inteiro).
        const agentesAgrupados = {};
        monitoriasDoMes.forEach(m => {
            if (!agentesAgrupados[m.nome]) agentesAgrupados[m.nome] = { nome: m.nome, time: null, ciclos: {}, nomeOriginal: m.nomeOriginal };
            const a = agentesAgrupados[m.nome];
            if (!m.adapt && !a.time) a.time = m.time;
            const c = a.ciclos[`c${m.ciclo}`] || (a.ciclos[`c${m.ciclo}`] = { normal: [], adapt: [] });
            c[m.adapt ? 'adapt' : 'normal'].push(m.qual);
        });
        const qualMedia = v => v.reduce((s, x) => s + x, 0) / v.length;

        const resultados = Object.values(agentesAgrupados).map(a => {
            const notaCiclo = {}, adapt = [];
            Object.keys(a.ciclos).forEach(k => {
                const c = a.ciclos[k];
                if (c.normal.length) notaCiclo[k] = qualMedia(c.normal);
                else { notaCiclo[k] = qualMedia(c.adapt); adapt.push(k); }
            });
            const contam = Object.keys(notaCiclo).filter(k => !adapt.includes(k));
            const emAdaptacao = contam.length === 0;   // só tem a monitoria de Adaptação no mês: mostra a nota dela, fora das médias de equipe
            const qual = qualMedia((emAdaptacao ? Object.keys(notaCiclo) : contam).map(k => notaCiclo[k]));
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
                nome: a.nomeOriginal.toUpperCase(), time: a.time || 'ADAPTACAO', qual,
                lider: tkLiderDeNome(QUAL_NOME_CHATWOOT[normalizeNome(a.nomeOriginal)] || a.nomeOriginal) || QUAL_LIDER_DE_QUEM_SAIU[normalizeNome(a.nomeOriginal)] || null,   // 30/10/2026: abas por líder nas Notas de Monitoria (fonte única: TK_EQUIPE)
                c1: notaCiclo['c1'] !== undefined ? notaCiclo['c1'] : null,
                c2: notaCiclo['c2'] !== undefined ? notaCiclo['c2'] : null,
                c3: notaCiclo['c3'] !== undefined ? notaCiclo['c3'] : null,
                c4: notaCiclo['c4'] !== undefined ? notaCiclo['c4'] : null,
                adapt, emAdaptacao,   // 30/10/2026: ciclos de Adaptação (fora da média) e quem ainda só tem a Adaptação
                link: linkPastaDrive
            };
        });
        
        res.json({ success: true, meses: meses, mesAtual: mesSelecionado, agentes: resultados });

    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// 14/10/2026: regra de setor da Qualidade (mesma ordem e listas da rota /api/qualidade) — a Sinalizações passa a usar esta mesma regra
// (antes, só na Sinalizações: "SAC - SMS" virava SAC, Bruno Lima virava 48H e Adaptação virava RET)
function qualSiglaDoSetor(setorRaw, nomeFormatado) {
    const nomes48H = ['THAUANE GARCIA', 'BRUNO SILVA', 'ALEXANDRE FILHO', 'DARYSON MATHEUS', 'DARYSON NASCIMENTO', 'GABRIELA ANDRADE', 'GABRIELA PENHA'];
    const nomesSMS = ['ANA GODINHO', 'REBECA SILVA', 'BRUNO LIMA', 'KEULIANE MOURA'];
    if (setorRaw.includes('ADAPTA')) return 'ADAPTACAO';
    if (setorRaw.includes('48H') || nomes48H.some(n => nomeFormatado.includes(n))) return '48H';
    if (setorRaw.includes('SMS') || nomesSMS.some(n => nomeFormatado.includes(n))) return 'SMS';
    if (setorRaw.includes('SAC')) return 'SAC';
    if (setorRaw.includes('BKO') || setorRaw.includes('BACKOFFICE')) return 'BKO';
    return 'RET';
}

// ==========================================
// 7.5 ROTA DE SINALIZAÇÕES (PLANILHA C - BASE_SINALIZACOES)
// ==========================================
app.get('/api/sinalizacoes', soAdmin, async (req, res) => {   // 🛡️ 16/10/2026: + soAdmin (tela de admin)
    try {
        let privateKey = (process.env.GOOGLE_PRIVATE_KEY || '').replace(/\\n/g, '\n').replace(/"/g, '').trim();
        const auth = new google.auth.GoogleAuth({
            credentials: { client_email: (process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || '').trim(), private_key: privateKey },
            scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
        });
        const sheets = google.sheets({ version: 'v4', auth });
        
        const sheetIdQualidade = process.env.GOOGLE_SHEET_ID_QUALIDADE ? process.env.GOOGLE_SHEET_ID_QUALIDADE.trim() : '1YVu29a_MiqU73_Za_Daj7nmfMJz-phTec2gxX6VKqwk';
        
        const response = await sheets.spreadsheets.values.get({ spreadsheetId: sheetIdQualidade, range: `'BASE_SINALIZACOES'!A1:Z` });   // 14/10/2026: aba inteira (antes só até a linha 5000: o mês novo sumia sem aviso)
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
            
            siglaSetor = qualSiglaDoSetor(setorRaw, nomeFormatado);   // 14/10/2026: mesma regra de setor da Qualidade (antes: "SAC - SMS" virava SAC, Bruno Lima virava 48H e Adaptação virava RET)

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

        const _errPer = tkPeriodoValido(dataInicioSQL, dataFimSQL);   // 26/10/2026: teto de período
        if (_errPer) return res.status(400).json({ success: false, error: _errPer });
        const result = await pool.query(queryTickets, [dataInicioSQL, dataFimSQL]);
        const agentesMap = {};
        result.rows.forEach(row => {
            const nome = (row.agente || '').toUpperCase();
            if (!nome.match(/- SAC|- RET|- BKO|- SMS|- 48H/)) return;
            if (!agentesMap[nome]) agentesMap[nome] = { nome: row.agente, lider: tkLiderDe(row.agente), seg:0, ter:0, qua:0, qui:0, sex:0, sab:0, dom:0, total:0 };   // 30/10/2026: lider p/ a aba por líder da Tickets (Atual e Visão Mensal)

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
            const dInicio = new Date(agora.getFullYear(), agora.getMonth(), 1);
            const dFim = agora; 
            dataInicioSQL = formatarDataSQL(dInicio); dataFimSQL = formatarDataSQL(dFim);
        }

        const dInicio = new Date(dataInicioSQL + 'T12:00:00Z');
        const dFim = new Date(dataFimSQL + 'T12:00:00Z');
        const domingoBase = new Date(dInicio.getTime());
        domingoBase.setUTCDate(dInicio.getUTCDate() - dInicio.getUTCDay());
        const diffMsTotal = dFim.getTime() - domingoBase.getTime();
        const totalSemanas = Math.floor((diffMsTotal / (1000 * 60 * 60 * 24)) / 7) + 1; 
        const metaCalculada = totalSemanas * 400; 

        const _errPer = tkPeriodoValido(dataInicioSQL, dataFimSQL);   // 26/10/2026: teto de período
        if (_errPer) return res.status(400).json({ success: false, error: _errPer });
        const result = await pool.query(queryTickets, [dataInicioSQL, dataFimSQL]);
        const agentesMap = {};
        result.rows.forEach(row => {
            const nome = (row.agente || '').toUpperCase();
            if (!nome.match(/- SAC|- RET|- BKO|- SMS|- 48H/)) return;
            if (!agentesMap[nome]) agentesMap[nome] = { nome: row.agente, lider: tkLiderDe(row.agente), semanas: new Array(totalSemanas).fill(0), total: 0 };

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
app.get('/api/distribuicao', soAdmin, async (req, res) => {   // 🛡️ 16/10/2026: + soAdmin (tela de admin)
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
            
            if (!distAgentes[nome]) distAgentes[nome] = { nome, lider: tkLiderDe(nome), total: 0 };   // 30/10/2026: lider p/ a aba por líder da Tickets (Distribuição)
            distAgentes[nome][cx] = (distAgentes[nome][cx] || 0) + (parseInt(r.qtd) || 0);   // 14/10/2026: soma — o mesmo agente na mesma caixa vem em mais de 1 linha quando o time da conversa muda
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
            if (!resCasosMap[nome]) resCasosMap[nome] = { nome, lider: tkLiderDe(nome), em_aberto: 0, retornos: 0, aguardando: 0, fora_sla: 0, total: 0, detalhes: [] };
            
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
app.get('/api/diag-setores', soAdmin, async (req, res) => {   // 🛡️ 16/10/2026: + soAdmin (tela de admin)
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
app.get('/api/produtividade', soAdmin, async (req, res) => {   // 🛡️ 16/10/2026: + soAdmin (tela de admin)
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
            const mSigProd = nome.match(/[\s\-]+(RET|SAC|BKO|SMS|48H)\b/);   // 14/10/2026: time pelo nome na regra padrão do Dash (a mesma do Status de Casos)
            if (!mSigProd) return;
            if (!nome.includes('- ' + mSigProd[1])) nome = nome.replace(/[\s\-]+(RET|SAC|BKO|SMS|48H)\b.*$/, '').trim() + ' - ' + mSigProd[1];   // 14/10/2026: nome fora do padrão ("FULANO RET") aparece como "FULANO - RET", igual ao Status de Casos (o filtro de time da tela acha)
            
            let d = new Date(r.data_hora.replace(' ', 'T'));
            let diaStr = r.data_hora.split(' ')[0];
            
            if (!relatorio[nome]) relatorio[nome] = { dias: {} };
            if (!relatorio[nome].dias[diaStr]) relatorio[nome].dias[diaStr] = [];
            relatorio[nome].dias[diaStr].push(d);
        });

        const formatHora = (d) => String(d.getHours()).padStart(2,'0') + ':' + String(d.getMinutes()).padStart(2,'0');

        const output = [];
        for (const [agente, dados] of Object.entries(relatorio)) {
            // 23/10/2026: jornada real do agente (turno da lider + pausa dele). Sem lider = regra antiga.
            const _jor = tkJornadaDe(agente) || { tIni: 9 * 60, tFim: 18 * 60, pIni: 12 * 60 + 30, pFim: 14 * 60 };
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
                horas.sort((a, b) => a - b);   // 14/10/2026: 2 nomes do mesmo agente (regra padrão do time) juntam as mensagens; as pausas precisam da ordem do horário
                
                let inicio = horas[0];
                let fim = horas[horas.length - 1];
                let objDia = dia.split('-').reverse().join('/');
                jornadas.push(`${objDia} (${formatHora(inicio)} as ${formatHora(fim)})`);

                let diaDaSemana = inicio.getDay(); // 0=Dom, 6=Sab
                let isFDS = (diaDaSemana === 0 || diaDaSemana === 6);
                
                if (!isFDS) diasUteis++;
                ticketsPorDia[objDia] = horas.length;
                ociosoPorDia[objDia] = 0;

                if (!isFDS) ticketsPorHora[inicio.getHours()] = (ticketsPorHora[inicio.getHours()] || 0) + 1;   // 14/10/2026: a 1ª mensagem do dia também conta no pico por hora (o laço abaixo começa na 2ª)
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
                        
                        let idleUtil = overlap(startMin, endMin, _jor.tIni, _jor.pIni) + overlap(startMin, endMin, _jor.pFim, _jor.tFim);
                        
                        let overlapAlmoco = overlap(startMin, endMin, _jor.pIni, _jor.pFim);
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
            
            const _hIni = Math.floor(_jor.tIni / 60), _hFim = Math.min(24, Math.ceil(_jor.tFim / 60));
            for(let h=_hIni; h<_hFim; h++) {
                if (h * 60 >= _jor.pIni && (h + 1) * 60 <= _jor.pFim) continue; // hora inteira dentro da pausa
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
                lider: _jor.lider || null,
                turno: _jor.turno || null,
                pausa: _jor.pausa || null,
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
app.get('/api/recorrencia', soAdmin, async (req, res) => {   // 🛡️ 16/10/2026: + soAdmin (tela de admin)
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
                TO_CHAR(created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo', 'YYYY-MM') as mes_retorno -- 14/10/2026: de UTC para Brasília (antes ficava 6 h adiantado e a virada do mês saía errada)
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
app.get('/api/produtos-metricas', soAdmin, async (req, res) => {   // 🛡️ 16/10/2026: + soAdmin (tela de admin)
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
                m.sender_type,   -- 14/10/2026: TMR só com resposta de agente humano (robô/automação não contam)
                COUNT(*) FILTER (WHERE m.message_type = 1 AND m.sender_type = 'User') OVER (PARTITION BY m.conversation_id ORDER BY m.created_at ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS resp_humanas_antes,   -- 14/10/2026: separa as esperas do cliente
                LAG(m.created_at) OVER (PARTITION BY m.conversation_id ORDER BY m.created_at) as prev_msg_time,
                LAG(m.message_type) OVER (PARTITION BY m.conversation_id ORDER BY m.created_at) as prev_msg_type
            FROM messages m
            JOIN ConversasBase cb ON cb.conversation_id = m.conversation_id
            WHERE m.private = FALSE 
              AND m.account_id = 1 
              AND m.message_type IN (0, 1) 
              AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE
        ),
        EsperasHumanas AS (   -- 14/10/2026: cada espera = da 1ª mensagem do cliente ainda sem resposta até a 1ª resposta de agente humano
            SELECT conversation_id, resp_humanas_antes,
                MIN(created_at) FILTER (WHERE message_type = 0) AS inicio_espera,
                MIN(created_at) FILTER (WHERE message_type = 1 AND sender_type = 'User') AS resposta_humana
            FROM BaseMessages
            GROUP BY conversation_id, resp_humanas_antes
        ),
        TmrConversa AS (   -- 14/10/2026: TMR da conversa = média das esperas que tiveram resposta humana (sem resposta fica de fora, não vira 0)
            SELECT conversation_id, AVG(EXTRACT(EPOCH FROM (resposta_humana - inicio_espera))/60) AS tmr_minutos
            FROM EsperasHumanas
            WHERE inicio_espera IS NOT NULL AND resposta_humana IS NOT NULL
            GROUP BY conversation_id
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
                MAX(tc.tmr_minutos) AS tmr_minutos   -- 14/10/2026: da 1ª mensagem do cliente que esperou até a 1ª resposta humana (TmrConversa)
            FROM BaseMessages LEFT JOIN TmrConversa tc USING (conversation_id)   -- 14/10/2026: 1 linha por conversa no TmrConversa (não multiplica as mensagens)
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
            AVG(a.tmr_minutos) AS sla_tmr_minutos,   -- 14/10/2026: sem resposta humana = null (a tela mostra –), não 0
            
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
app.get('/api/mencoes-abertos', soAdmin, async (req, res) => {   // 🛡️ 16/10/2026: + soAdmin (tela de admin)
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

        // 14/10/2026: período de no máximo 62 dias (período gigante gera consulta pesada no banco do Chatwoot); o padrão (hoje) não muda
        const diasMonTk = Math.round((Date.parse(dataFimSQL) - Date.parse(dataInicioSQL)) / 86400000) + 1;
        if (diasMonTk > 62) return res.status(400).json({ success: false, error: `Período muito grande (${diasMonTk} dias). Escolha no máximo 62 dias na Monitoria de Tickets.` });

        const q = `
        WITH BaseAcoes AS MATERIALIZED (   -- 14/10/2026: calcula quem fez a ação 1 vez por mensagem (com a busca nova de quem agiu, sem isto a consulta ficava ~45% mais lenta)
            SELECT 
                m.conversation_id,
                c.display_id,
                m.message_type,
                m.content,
                m.created_at AS m_created_at,
                c.status AS conv_status,
                -- 🔥 O HISTORIADOR: Tenta pegar o tempo exato no momento que o botão foi clicado!
                COALESCE(m.content_attributes->>'snoozed_until', to_char(c.snoozed_until, 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')) AS snoozed_until,   -- 14/10/2026: com fuso (Z), igual ao horário da ação (a tela faz adiamento − ação)
                COALESCE(
                    (CASE WHEN m.message_type = 1 THEN u_sender.name END), 
                    SUBSTRING(m.content FROM '(?i)por (.*?[[:space:]-]+(?:RET|SAC|BKO|SMS|48H))[[:>:]]'),   -- 14/10/2026: reconhece o 48H (e o nome fora do padrão, como no Status de Casos)
                    (CASE WHEN SUBSTRING(m.content FROM '(?i)^(.*?[[:space:]-]+(?:RET|SAC|BKO|SMS|48H))[[:>:]]') IN (SELECT u_ini.name FROM users u_ini)
                          THEN SUBSTRING(m.content FROM '(?i)^(.*?[[:space:]-]+(?:RET|SAC|BKO|SMS|48H))[[:>:]]') END)   -- 14/10/2026: quem fez a ação no começo do texto ("Fulano - SAC adicionou..."), se for um usuário; não usa mais o responsável atual
                ) AS agente_nome
            FROM messages m
            JOIN conversations c ON c.id = m.conversation_id
            LEFT JOIN users u_sender ON u_sender.id = m.sender_id
            LEFT JOIN users u_assignee ON u_assignee.id = c.assignee_id
            WHERE m.account_id = 1
              AND m.message_type IN (1, 2) 
              AND (m.message_type = 2 OR m.sender_type = 'User')   -- 14/10/2026: resposta só de agente humano (robô/automação não viram ação de ninguém)
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
                COALESCE(SUBSTRING(UPPER(agente_nome) FROM '[[:space:]-]+(RET|SAC|BKO|SMS|48H)[[:>:]]'), 'OUTROS') AS equipe,   -- 14/10/2026: time pelo nome na regra padrão do Dash (a mesma do Status de Casos)
                display_id,
                conversation_id,
                COUNT(CASE WHEN message_type = 2 AND content ILIKE '%adiad%' THEN 1 END) AS qtd_adiado,
                COUNT(CASE WHEN message_type = 2 AND content ILIKE '%resolvid%' THEN 1 END) AS qtd_resolvido,
                json_agg(
                    json_build_object(
                        'tipo', message_type,
                        'texto', COALESCE(content, 'Ação do Sistema'),
                        'data', to_char(m_created_at, 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),   -- 14/10/2026: horário em UTC com fuso (Z): o navegador mostra certo em Brasília
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
            const rlog = await sheetsLog.spreadsheets.values.get({ spreadsheetId: SNOOZE_SHEET_ID, range: `${SNOOZE_ABA}!A2:F` });   // 14/10/2026: aba inteira (com o teto de 100 mil linhas os adiamentos novos, no fim da aba, ficavam de fora)
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

        result.rows.forEach(r => { r.lider = tkLiderDeNome(r.agente_nome); });   // 30/10/2026: abas por líder na Monitoria de Tickets (fonte única: TK_EQUIPE)
        res.json({ success: true, dados: result.rows });
    } catch (error) { 
        console.error("Erro Rota Monitoria:", error);
        res.status(500).json({ success: false, error: error.message }); 
    }
});

// ==========================================
// 16. ROTA DE URGÊNCIA: REEMBOLSOS PAGAMERICAN (COM GOOGLE SHEETS)
// ==========================================
// ==========================================
// ⚠️ 27/10/2026 — NO LOG MAS NÃO NO PAINEL
// A planilha de log só CORRIGE a data e os campos de um ticket que a consulta do Chatwoot já trouxe: ela nunca
// traz um ticket novo. Se o reembolso foi lançado na planilha mas no Chatwoot ainda falta a plataforma ou o
// "tipo de retenção", o ticket some da extração daquele dia e só aparece dias depois, com a data certa do log.
// Esta função acha esses tickets e diz, para cada um, POR QUE ele não entrou. Só LEITURA, e só roda se houver pendente.
// ==========================================
const RB_MARCAS = {
    pagamerican: ['pagamerican', 'pagamerica', 'pag american', 'pag_american'],
    buygoods: ['buygoods', 'buy goods', 'buy_goods'],
    cartpanda: ['cartpanda', 'cart panda', 'cart_panda'],
};
const RB_ROTULO = { pagamerican: 'PagAmerican', buygoods: 'BuyGoods', cartpanda: 'CartPanda' };
async function rbPendentesDoLog(logMap, idsNoPainel, dInicio, dFim, plataforma) {
    const alvo = [];
    for (const tk in logMap) {
        const L = logMap[tk];
        if (!L || !L.data || idsNoPainel.has(String(tk))) continue;
        if (!(L.data >= dInicio && L.data <= dFim)) continue;
        const n = parseInt(String(tk).replace(/\D/g, ''), 10);
        if (n > 0) alvo.push({ ticket: String(tk), n, L });
    }
    if (!alvo.length) return [];
    const base = (a, motivo, agente) => ({ ticket: a.ticket, data: a.L.data, tipo: a.L.tipo || '', pedido: a.L.pedido || '', produto: a.L.produto || '', agente: agente || '', motivo });
    let achados = {};
    try {
        const r = await pool.query(`
            SELECT c.display_id,
                   COALESCE(u.name, 'SEM ATRIBUIR') AS agente,
                   COALESCE(c.custom_attributes->>'tipo_de_retencao_de_reembolso', ct.custom_attributes->>'tipo_de_retencao_de_reembolso', '') AS tipo,
                   LOWER(COALESCE(c.custom_attributes::text, '') || ' ' || COALESCE(ct.custom_attributes::text, '')) AS atributos
            FROM conversations c
            LEFT JOIN users u ON u.id = c.assignee_id
            LEFT JOIN contacts ct ON ct.id = c.contact_id
            WHERE c.account_id = 1 AND c.display_id = ANY($1::int[])`, [alvo.map(a => a.n)]);
        r.rows.forEach(x => { achados[String(x.display_id)] = x; });
    } catch (e) {
        return alvo.map(a => base(a, 'Não deu para conferir no Chatwoot agora (' + String(e.message || e).slice(0, 60) + ')'));
    }
    const marcas = RB_MARCAS[plataforma] || [];
    const outras = Object.keys(RB_MARCAS).filter(x => x !== plataforma);
    return alvo.map(a => {
        const c = achados[a.ticket];
        if (!c) return base(a, 'Este número de ticket não existe no Chatwoot — confira o número lançado na planilha');
        const tipo = String(c.tipo || '').trim(), attrs = String(c.atributos || '');
        if (!tipo) return base(a, 'No Chatwoot falta preencher o campo "Tipo de retenção de reembolso"', c.agente);
        if (/sem reembolso/i.test(tipo)) return base(a, 'No Chatwoot o tipo está como "sem reembolso" — o painel não conta esses', c.agente);
        if (!marcas.some(m => attrs.includes(m))) {
            const outra = outras.find(x => RB_MARCAS[x].some(m => attrs.includes(m)));
            return base(a, outra ? `A conversa está marcada como ${RB_ROTULO[outra]} no Chatwoot, não como ${RB_ROTULO[plataforma]}`
                                 : 'A conversa não tem a plataforma preenchida no Chatwoot', c.agente);
        }
        return base(a, 'Passou a valer no Chatwoot depois desta consulta — use o 🔄 Atualizar', c.agente);
    });
}
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
        let avisoLogPag = '';   // 14/10/2026: motivo curto quando o log falha — vai na resposta (aviso_log) e a resposta não fica no cache (sem_cache)
        const _pLog = (async () => {
            let logMap = {};
            const _ctlLog = new AbortController(), _timerLog = setTimeout(() => _ctlLog.abort(), 20000);   // 14/10/2026: tempo limite de 20 s (Apps Script travado não segura mais a tela)
            try {
                const _r = await fetch(URL_PLANILHA, { redirect: 'follow', signal: _ctlLog.signal });
                const _t = (await _r.text()).trim();
                if (!_r.ok) throw new Error(`a planilha de log respondeu HTTP ${_r.status}`);   // 14/10/2026: erro do Apps Script não passa mais como "log vazio"
                if (!(_t.startsWith('[') || _t.startsWith('{'))) throw new Error('a planilha de log devolveu uma página de erro');
                const dadosPlanilha = (_t.startsWith('[') || _t.startsWith('{')) ? JSON.parse(_t) : [];
                if (!Array.isArray(dadosPlanilha)) throw new Error('a planilha de log devolveu um formato inesperado');   // 14/10/2026
                if (Array.isArray(dadosPlanilha)) dadosPlanilha.forEach(l => {
                    const tk = String(l.ticket || l[0] || '').trim();
                    if (!tk || logMap[tk] || /sem reembolso/i.test(String(l.tipo || l[2] || ''))) return;
                    const dl = new Date(l.data_hora || l[1]);
                    logMap[tk] = { data: isNaN(dl) ? null : dl, tipo: l.tipo || '', pedido: l.pedido || '', produto: l.produto || '', cliente: l.cliente || '', email: l.email || '' };
                });
            } catch (err) {   // 14/10/2026: a falha vira aviso_log (a tela avisa); os dados seguem do banco, como antes
                avisoLogPag = err.name === 'AbortError' ? 'a planilha de log não respondeu em 20 s'
                    : (err instanceof SyntaxError ? 'a planilha de log devolveu dados inválidos'
                    : (/^a planilha de log/.test(String(err.message)) ? String(err.message) : 'falha ao ler a planilha de log (' + String(err.message || err).slice(0, 80) + ')'));
                console.log("Aviso: falha ao ler o log de reembolso.", avisoLogPag);
            } finally { clearTimeout(_timerLog); }
            return logMap;
        })();

        // 2. FILTRO DE DATAS DO PAINEL
        let dInicio, dFim;
        if (req.query.since && req.query.until) {
            dInicio = new Date(parseInt(req.query.since) * 1000);
            dFim = new Date(parseInt(req.query.until) * 1000);
        } else {
            const agora = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Sao_Paulo" }));
            dInicio = new Date(Date.UTC(agora.getFullYear(), agora.getMonth(), 1, 3));        // 14/10/2026: dia 1 às 00:00 de Brasília (03:00 UTC), com o servidor em qualquer fuso
            dFim = new Date(Date.UTC(agora.getFullYear(), agora.getMonth() + 1, 1, 3) - 1);   // 14/10/2026: fim do mês 23:59:59 de Brasília (antes "agora" ficava 3 h atrasado com o servidor em UTC)
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

        const pendentesLog = await rbPendentesDoLog(logMap, new Set(result.rows.map(x => String(x.display_id))), dInicio, dFim, 'pagamerican');   // 27/10/2026
        res.json(Object.assign({ success: true, dados: arrayFinal, pendentes_log: pendentesLog }, avisoLogPag ? { aviso_log: avisoLogPag, sem_cache: true } : {}));   // 14/10/2026: log com falha → aviso_log na tela e sem_cache (o cache não guarda)
    } catch (error) { 
        console.error("Erro PagAmerican:", error);
        res.status(500).json({ success: false, error: "Erro interno no servidor." }); 
    }
});

// ==========================================
// 17. ROTA: TIME 48 HORAS (ETIQUETAS + RETORNOS)
// ==========================================
// 🛡️ 14/10/2026 — teto de período nas rotas de agente e do Time 48H: período gigante vira consulta pesada no banco do Chatwoot (sem data escolhida, o padrão de cada rota não muda)
const T48_MAX_DIAS = 186;
function t48PeriodoGrande(dataInicioSQL, dataFimSQL) {   // 'AAAA-MM-DD' × 'AAAA-MM-DD' → o texto do erro se passar do teto ('' se estiver dentro)
    const dias = Math.round((new Date(dataFimSQL + 'T00:00:00Z') - new Date(dataInicioSQL + 'T00:00:00Z')) / 86400000) + 1;
    return dias > T48_MAX_DIAS ? `Período grande demais: ${dias} dias. Escolha no máximo ${T48_MAX_DIAS} dias (cerca de 6 meses) no calendário.` : '';
}
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

        const erroPeriodo = t48PeriodoGrande(dataInicioSQL, dataFimSQL);   // 🛡️ 14/10/2026: teto de período (consulta pesada no banco do Chatwoot)
        if (erroPeriodo) return res.status(400).json({ success: false, error: erroPeriodo });
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

        const erroPeriodo = t48PeriodoGrande(dataInicioSQL, dataFimSQL);   // 🛡️ 14/10/2026: teto de período (consulta pesada no banco do Chatwoot)
        if (erroPeriodo) return res.status(400).json({ success: false, error: erroPeriodo });
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

        const erroPeriodo = t48PeriodoGrande(dataInicioSQL, dataFimSQL);   // 🛡️ 14/10/2026: teto de período (consulta pesada no banco do Chatwoot)
        if (erroPeriodo) return res.status(400).json({ success: false, error: erroPeriodo });
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
        await tjAplicar(dados, linhas, dataInicioSQL, dataFimSQL);   // ⚖️ TMC/TMR justos (13/10/2026): só na vez do agente

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

        const erroPeriodo = t48PeriodoGrande(dataInicioSQL, dataFimSQL);   // 🛡️ 14/10/2026: teto de período (consulta pesada no banco do Chatwoot)
        if (erroPeriodo) return res.status(400).json({ success: false, error: erroPeriodo });
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
        await tjAplicar(dados, linhas, dataInicioSQL, dataFimSQL);   // ⚖️ TMC/TMR justos (13/10/2026): só na vez do agente

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
// 15.3.1 TIME 48H — ⏱️ 1º CONTATO 15 MIN (08/10/2026)
// O relógio começa na ATRIBUIÇÃO do agente (o registro "Atribuído a ... por ..." que o Chatwoot grava dentro da conversa)
// e para no 1º contato = 1ª mensagem pública de agente depois da atribuição (mesma regra do TMC). Passou de 15 min sem contato = atraso.
// Só conta atribuição com o cliente esperando resposta. Se o caso saiu do agente (ou foi encerrado) antes dos 15 min, sem contato, fica fora da conta.
// Universo: tickets com etiqueta 48H ou Painel (time-48h* e painel-do-pedido*), de qualquer agente. Só LÊ o banco do Chatwoot.
// Atribuição automática antiga (round robin, que não grava o registro): vem da tabela conversation_participants (só a do agente atual do ticket).
// Rota da sub-aba: /api/time48-primeiro-contato (?since&until = dia da atribuição; sem período = mês atual)
// Monitor: a cada 5 min grava os atrasos novos na aba t48_1contato da planilha de log (sem repetir o caso) · conferência: /api/raio-x-atribuicao
// ==========================================
const T48P_PRAZO_MIN = 15;                 // prazo do 1º contato depois da atribuição (min)
const T48P_FOLGA_SEG = 60;                 // folga de relógio: o Chatwoot grava o registro da atribuição um instante depois da atribuição
const T48P_ABA = 't48_1contato';           // aba nova na planilha de log (a mesma do snooze e do bot)
const T48P_CAB = ['registrado_em', 'chave', 'conversa', 'link', 'cliente', 'agente', 'atribuido_em', 'atribuido_por', 'origem', 'prazo_ate', 'situacao', 'minutos', 'primeiro_contato_em', 'primeiro_contato_por', 'status_conversa'];
const T48P_STATUS = { 0: 'Em aberto', 1: 'Resolvido', 2: 'Pendente', 3: 'Adiado' };
const T48P_FIM_TXT = { reatribuido: 'depois foi para outro agente', desatribuido: 'depois ficou sem agente', encerrado: 'depois foi resolvido', trocou_time: 'depois mudou de time' };
// registros de atribuição (pt-BR e inglês): "Atribuído a X por Y", "Atribuído a X via TIME por Y", "Y atribuiu a si mesmo essa conversa"
const T48P_SQL_ATRIB = `(m.content ILIKE 'Atribu%' OR m.content ILIKE 'Assigned to %' OR m.content ILIKE '% atribuiu a si mesmo essa conversa' OR m.content ILIKE '% self-assigned this conversation')`;
// o que pode encerrar a vez do agente: outra atribuição, desatribuição, troca de time ou conversa resolvida
const T48P_SQL_FIM = `(${T48P_SQL_ATRIB} OR m.content ILIKE 'Conversa desatribu%' OR m.content ILIKE 'Conversation unassigned by %' OR m.content ILIKE 'Desatribu%' OR m.content ILIKE 'Unassigned from %'
    OR m.content ILIKE '%conversa foi marcada como resolvida%' OR m.content ILIKE '%conversa foi resolvida por%' OR m.content ILIKE 'Conversation was marked resolved%' OR m.content ILIKE 'Conversation was resolved by%')`;
const T48P_JANELA_DIA = (col) => `${col} >= ((($1::date)::timestamp AT TIME ZONE 'America/Sao_Paulo') AT TIME ZONE 'UTC') AND ${col} < (((($2::date) + 1)::timestamp AT TIME ZONE 'America/Sao_Paulo') AT TIME ZONE 'UTC')`;   // dias de Brasília (período da tela)
const T48P_JANELA_TS = (col) => `${col} >= (to_timestamp($1::float8) AT TIME ZONE 'UTC') AND ${col} <= (to_timestamp($2::float8) AT TIME ZONE 'UTC')`;   // instantes em segundos (monitor)
const t48pMonitor = { rodando: false, ultimaRodada: 0, ultimoErro: '', registrados: 0, chaves: new Set(), chavesLidas: false, abaOk: false };
let t48pNomesCache = { em: 0, usuarios: [], times: [], membros: null, nomePorId: {} };

function t48pTextoBR(ms) {   // 'AAAA-MM-DD HH:MM:SS' no horário de Brasília (vai para a planilha)
    if (ms == null || isNaN(ms)) return '';
    const p = {};
    new Intl.DateTimeFormat('en-GB', { timeZone: 'America/Sao_Paulo', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' })
        .formatToParts(new Date(ms)).forEach(x => { p[x.type] = x.value; });
    return `${p.year}-${p.month}-${p.day} ${String(parseInt(p.hour, 10) % 24).padStart(2, '0')}:${p.minute}:${p.second}`;
}
const t48pNomeBase = (n) => String(n || '').replace(/\s*-\s*(RET|SAC|BKO|SMS|48H|LD)\b.*$/i, '').trim().toLowerCase();
const t48pOrigem = (por) => /^(Sistema de Automa|Automation System|Pol[ií]tica Padr|Default Policy)/i.test(String(por || '')) ? 'automática' : 'manual';

async function t48pNomes() {   // agentes, times e quem é de cada time (guardado por 10 min: tabelas pequenas)
    if (Date.now() - t48pNomesCache.em < 10 * 60 * 1000) return t48pNomesCache;
    const usuarios = (await pool.query(`SELECT id, name FROM users`)).rows
        .filter(u => String(u.name || '').trim().length >= 2).map(u => ({ id: Number(u.id), name: String(u.name) }));
    const times = (await pool.query(`SELECT id, name FROM teams WHERE account_id = 1`)).rows
        .filter(t => String(t.name || '').trim()).map(t => ({ id: Number(t.id), name: String(t.name) }));
    let membros = new Set();
    try { (await pool.query(`SELECT team_id, user_id FROM team_members`)).rows.forEach(r => membros.add(`${r.team_id}|${r.user_id}`)); } catch (e) { membros = null; }
    usuarios.sort((a, b) => b.name.length - a.name.length);   // o nome mais longo primeiro ("Ana Paula" antes de "Ana")
    times.sort((a, b) => b.name.length - a.name.length);
    const nomePorId = {};
    usuarios.forEach(u => { nomePorId[u.id] = u.name; });
    t48pNomesCache = { em: Date.now(), usuarios, times, membros, nomePorId };
    return t48pNomesCache;
}
function t48pAcharAgente(nome, nomes) {   // nome exato; se não achar, pelo nome sem a sigla do time ("Maria Souza" × "Maria Souza - 48H"), só se der 1 agente
    const exato = nomes.usuarios.find(u => u.name === nome);
    if (exato) return exato;
    const base = t48pNomeBase(nome);
    const parecidos = base ? nomes.usuarios.filter(u => t48pNomeBase(u.name) === base) : [];
    return parecidos.length === 1 ? parecidos[0] : null;
}
function t48pLerRegistro(txt, nomes) {   // lê o registro de atividade da conversa: atribuido | desatribuido | time | time_removido | encerrado | null
    const s = String(txt || '').trim();
    let m = s.match(/^(.+) atribuiu a si mesmo essa conversa$/) || s.match(/^(.+) self-assigned this conversation$/);
    if (m) { const u = t48pAcharAgente(m[1], nomes); return { tipo: 'atribuido', agente: u ? u.name : m[1], agente_id: u ? u.id : null, por: m[1], origem: 'pegou para si' }; }
    if (/^Conversa desatribu/i.test(s) || /^Conversation unassigned by /.test(s)) return { tipo: 'desatribuido' };
    m = s.match(/^Desatribu\S* de (.*) por (.+)$/i) || s.match(/^Unassigned from (.*) by (.+)$/);
    if (m) return { tipo: 'time_removido', time: m[1] };
    let resto = null, POR = ' por ';
    if (/^Atribu\S* a /i.test(s)) resto = s.replace(/^Atribu\S* a /i, '');
    else if (/^Assigned to /.test(s)) { resto = s.slice('Assigned to '.length); POR = ' by '; }
    if (resto !== null) {
        const u = nomes.usuarios.find(x => resto.startsWith(x.name + POR) || resto.startsWith(x.name + ' via '));
        if (u) {
            let depois = resto.slice(u.name.length), por = '';
            if (depois.startsWith(' via ')) {   // "via TIME por Y": o time pode ter " por " no nome, então procura pelo nome do time
                const semVia = depois.slice(5);
                const t = nomes.times.find(x => semVia.startsWith(x.name + POR));
                const i = semVia.indexOf(POR);
                por = t ? semVia.slice(t.name.length + POR.length) : (i >= 0 ? semVia.slice(i + POR.length) : '');
            } else por = depois.slice(POR.length);
            return { tipo: 'atribuido', agente: u.name, agente_id: u.id, por, origem: t48pOrigem(por) };
        }
        const t = nomes.times.find(x => resto.startsWith(x.name + POR));
        if (t) return { tipo: 'time', time: t.name, time_id: t.id, por: resto.slice(t.name.length + POR.length) };
        // nome que mudou no Chatwoot depois do registro (ex.: ganhou o " - 48H"): separa no 1º " via " / " por "
        const mm = resto.match(POR === ' por ' ? /^(.+?)(?: via .+?)? por (.+)$/ : /^(.+?)(?: via .+?)? by (.+)$/);
        if (!mm) return null;
        const u2 = t48pAcharAgente(mm[1], nomes);
        return { tipo: 'atribuido', agente: u2 ? u2.name : mm[1], agente_id: u2 ? u2.id : null, por: mm[2], origem: t48pOrigem(mm[2]) };
    }
    if (/conversa foi marcada como resolvida|conversa foi resolvida por|^Conversation was marked resolved|^Conversation was resolved by/i.test(s)) return { tipo: 'encerrado' };
    return null;
}

// Avalia cada atribuição da janela (janela = T48P_JANELA_DIA com 'AAAA-MM-DD' ou T48P_JANELA_TS com segundos) e devolve a situação do 1º contato
async function t48pAvaliar(janela, p1, p2) {
    const nomes = await t48pNomes();
    const diag = { registros: 0, participantes_usados: 0, sem_cliente_esperando: 0 };   // números da conferência (Raio-X da Atribuição)
    const ids = (await pool.query(`SELECT DISTINCT t.taggable_id AS id FROM taggings t JOIN tags tg ON tg.id = t.tag_id WHERE t.taggable_type = 'Conversation' AND (tg.name ILIKE '%time-48h%' OR tg.name ILIKE 'painel-do-pedido%')`)).rows.map(r => r.id);
    if (!ids.length) return { eventos: [], diag };

    // 1) registros de atribuição gravados na conversa (mensagem de atividade) dentro da janela
    const regs = (await pool.query(`
        SELECT m.id, m.conversation_id AS conv_id, m.content, EXTRACT(EPOCH FROM m.created_at)::float8 AS ts
        FROM messages m
        WHERE m.conversation_id = ANY($3::bigint[]) AND m.account_id = 1 AND m.message_type = 2
          AND ${janela('m.created_at')} AND ${T48P_SQL_ATRIB}
        ORDER BY m.created_at, m.id`, [p1, p2, ids])).rows;
    diag.registros = regs.length;
    const eventos = [];
    regs.forEach(r => {
        const l = t48pLerRegistro(r.content, nomes);
        if (!l || l.tipo !== 'atribuido') return;   // só o que atribui a um agente abre a contagem
        eventos.push({ chave: `${r.conv_id}-m${r.id}`, conv_id: Number(r.conv_id), msg_id: Number(r.id), ts: Number(r.ts), agente: l.agente, agente_id: l.agente_id, por: l.por, origem: l.origem });
    });

    // 2) atribuição automática antiga (sem registro na conversa): conversation_participants do agente ATUAL do ticket
    let parts = [];
    try {
        parts = (await pool.query(`
            SELECT cp.conversation_id AS conv_id, cp.user_id, EXTRACT(EPOCH FROM cp.created_at)::float8 AS ts
            FROM conversation_participants cp
            JOIN conversations c ON c.id = cp.conversation_id AND c.assignee_id = cp.user_id
            WHERE cp.conversation_id = ANY($3::bigint[]) AND ${janela('cp.created_at')}`, [p1, p2, ids])).rows;
    } catch (e) { parts = []; }   // Chatwoot sem a tabela: segue só com os registros da conversa
    if (parts.length) {
        const idsP = [...new Set(parts.map(p => Number(p.conv_id)))];
        const todos = (await pool.query(`
            SELECT m.conversation_id AS conv_id, m.content, EXTRACT(EPOCH FROM m.created_at)::float8 AS ts
            FROM messages m
            WHERE m.conversation_id = ANY($1::bigint[]) AND m.account_id = 1 AND m.message_type = 2 AND ${T48P_SQL_ATRIB}`, [idsP])).rows;
        const comRegistro = new Set(), regPorConv = {};
        todos.forEach(r => {
            const l = t48pLerRegistro(r.content, nomes);
            if (l && l.tipo === 'atribuido' && l.agente_id) comRegistro.add(`${r.conv_id}|${l.agente_id}`);
            (regPorConv[r.conv_id] = regPorConv[r.conv_id] || []).push(Number(r.ts));
        });
        parts.forEach(p => {
            const ts = Number(p.ts);
            if (comRegistro.has(`${p.conv_id}|${p.user_id}`)) return;                          // essa atribuição já tem o registro na conversa
            if ((regPorConv[p.conv_id] || []).some(t => Math.abs(t - ts) <= 120)) return;      // registro de atribuição no mesmo instante
            diag.participantes_usados += 1;
            eventos.push({ chave: `${p.conv_id}-p${p.user_id}`, conv_id: Number(p.conv_id), msg_id: 0, ts, agente: nomes.nomePorId[Number(p.user_id)] || ('Agente #' + p.user_id), agente_id: Number(p.user_id), por: 'Distribuição automática', origem: 'automática (sem registro)' });
        });
    }
    if (!eventos.length) return { eventos: [], diag };

    // 3) por atribuição: última mensagem do cliente, última mensagem de agente antes, 1ª mensagem de agente depois (índice da conversa)
    const ctx = (await pool.query(`
        WITH ev AS (
            SELECT x.i, x.conv_id, (to_timestamp(x.ts) AT TIME ZONE 'UTC') AS t
            FROM unnest($1::int[], $2::bigint[], $3::float8[]) AS x(i, conv_id, ts)
        )
        SELECT ev.i,
            (SELECT EXTRACT(EPOCH FROM MAX(mi.created_at))::float8 FROM messages mi
               WHERE mi.conversation_id = ev.conv_id AND mi.account_id = 1 AND mi.message_type = 0 AND mi.private = FALSE
                 AND mi.created_at <= ev.t + interval '${T48P_FOLGA_SEG} seconds') AS cliente_ts,
            (SELECT EXTRACT(EPOCH FROM MAX(ma.created_at))::float8 FROM messages ma
               WHERE ma.conversation_id = ev.conv_id AND ma.account_id = 1 AND ma.message_type = 1 AND ma.private = FALSE AND ma.sender_type = 'User'
                 AND ma.created_at < ev.t - interval '${T48P_FOLGA_SEG} seconds') AS agente_antes_ts,
            pc.ts AS contato_ts, pc.sender_id AS contato_id
        FROM ev
        LEFT JOIN LATERAL (
            SELECT EXTRACT(EPOCH FROM mc.created_at)::float8 AS ts, mc.sender_id
            FROM messages mc
            WHERE mc.conversation_id = ev.conv_id AND mc.account_id = 1 AND mc.message_type = 1 AND mc.private = FALSE AND mc.sender_type = 'User'
              AND mc.created_at >= ev.t - interval '${T48P_FOLGA_SEG} seconds'
              AND (mc.created_at >= ev.t OR mc.sender_id = ($4::bigint[])[ev.i + 1])   -- 14/10/2026: antes do registro só vale a mensagem do próprio agente atribuído (a do agente anterior, logo antes da transferência, não é contato)
            ORDER BY mc.created_at, mc.id LIMIT 1
        ) pc ON TRUE`, [eventos.map((e, i) => i), eventos.map(e => e.conv_id), eventos.map(e => e.ts), eventos.map(e => e.agente_id || 0)])).rows;   // 14/10/2026: $4 = agente atribuído de cada evento
    const ctxPorI = {};
    ctx.forEach(r => { ctxPorI[r.i] = r; });

    // 4) o que veio depois de cada atribuição (outra atribuição, desatribuição, troca de time, resolvida) e os dados do ticket
    const idsEv = [...new Set(eventos.map(e => e.conv_id))];
    const menorTs = eventos.reduce((a, e) => Math.min(a, e.ts), Infinity) - 1;
    const finsPorConv = {};
    (await pool.query(`
        SELECT m.id, m.conversation_id AS conv_id, m.content, EXTRACT(EPOCH FROM m.created_at)::float8 AS ts
        FROM messages m
        WHERE m.conversation_id = ANY($1::bigint[]) AND m.account_id = 1 AND m.message_type = 2
          AND m.created_at >= (to_timestamp($2::float8) AT TIME ZONE 'UTC') AND ${T48P_SQL_FIM}
        ORDER BY m.conversation_id, m.created_at, m.id`, [idsEv, menorTs])).rows
        .forEach(r => { (finsPorConv[r.conv_id] = finsPorConv[r.conv_id] || []).push({ id: Number(r.id), ts: Number(r.ts), l: t48pLerRegistro(r.content, nomes) }); });
    const convs = {};
    (await pool.query(`SELECT c.id, c.display_id, c.status, ct.name AS cliente FROM conversations c LEFT JOIN contacts ct ON ct.id = c.contact_id WHERE c.id = ANY($1::bigint[])`, [idsEv])).rows
        .forEach(r => { convs[Number(r.id)] = r; });

    // 5) situação de cada atribuição
    const agora = Date.now() / 1000, prazoSeg = T48P_PRAZO_MIN * 60;
    const saida = [];
    eventos.forEach((e, i) => {
        const c = ctxPorI[i] || {};
        const clienteTs = c.cliente_ts == null ? null : Number(c.cliente_ts);
        const antesTs = c.agente_antes_ts == null ? null : Number(c.agente_antes_ts);
        if (clienteTs == null || (antesTs != null && antesTs >= clienteTs)) { diag.sem_cliente_esperando += 1; return; }   // o cliente não estava esperando resposta
        let fim = null;   // fim da vez do agente
        for (const f of (finsPorConv[e.conv_id] || [])) {
            if (f.id === e.msg_id || f.ts < e.ts || (f.ts === e.ts && f.id < e.msg_id)) continue;
            const l = f.l;
            if (!l || l.tipo === 'time_removido') continue;   // tirar o time não tira o agente
            if (l.tipo === 'atribuido') {
                if ((l.agente_id && l.agente_id === e.agente_id) || (!l.agente_id && l.agente === e.agente)) continue;   // registro do mesmo agente: a vez continua
                fim = { ts: f.ts, tipo: 'reatribuido' }; break;
            }
            if (l.tipo === 'time') {
                if (nomes.membros && l.time_id && e.agente_id && nomes.membros.has(`${l.time_id}|${e.agente_id}`)) continue;   // mudou para um time do qual o agente faz parte: o caso continua com ele
                fim = { ts: f.ts, tipo: 'trocou_time' }; break;
            }
            fim = { ts: f.ts, tipo: l.tipo };   // desatribuido | encerrado
            break;
        }
        const contatoTs = c.contato_ts == null ? null : Number(c.contato_ts);
        const contatoNaVez = contatoTs != null && (!fim || contatoTs < fim.ts);
        const prazo = e.ts + prazoSeg;
        let situacao, minutos = null;
        if (contatoNaVez && contatoTs <= prazo) { situacao = 'no_prazo'; minutos = Math.max(0, (contatoTs - e.ts) / 60); }
        else if (fim && fim.ts <= prazo) situacao = fim.tipo;                                   // saiu do agente (ou encerrou) antes dos 15 min, sem contato: fora da conta
        else if (agora < prazo) situacao = 'aguardando';                                        // ainda dentro dos 15 min
        else if (contatoNaVez) { situacao = 'atrasado'; minutos = (contatoTs - e.ts) / 60; }    // contato depois dos 15 min
        else { situacao = 'sem_contato'; minutos = ((fim ? fim.ts : agora) - e.ts) / 60; }      // passou dos 15 min sem contato
        const cv = convs[e.conv_id] || {};
        saida.push({
            chave: e.chave, conv_id: e.conv_id, id: cv.display_id || e.conv_id, cliente: cv.cliente || 'Cliente sem nome',
            status: cv.status == null ? null : Number(cv.status),
            agente: e.agente, agente_id: e.agente_id, atribuido_por: e.por, origem: e.origem,
            atribuido_ms: Math.round(e.ts * 1000), prazo_ms: Math.round(prazo * 1000), cliente_ms: Math.round(clienteTs * 1000),
            contato_ms: contatoNaVez ? Math.round(contatoTs * 1000) : null,
            contato_por: contatoNaVez ? (nomes.nomePorId[Number(c.contato_id)] || (c.contato_id ? 'Agente #' + c.contato_id : '')) : null,
            minutos: minutos == null ? null : Math.round(minutos * 10) / 10,
            situacao, fim_tipo: fim ? fim.tipo : null, fim_ms: fim ? Math.round(fim.ts * 1000) : null
        });
    });
    return { eventos: saida, diag };
}

function t48pContar(lista) {   // atribuições contadas = no prazo + contato atrasado + sem contato (prazo já vencido e o caso ainda com o agente)
    const r = { atribuicoes: 0, no_prazo: 0, atrasado: 0, sem_contato: 0, atrasos: 0, aguardando: 0, fora_da_conta: 0, pct_no_prazo: null, tempo_medio_min: null };
    let soma = 0, n = 0;
    lista.forEach(e => {
        if (e.situacao === 'aguardando') { r.aguardando += 1; return; }
        if (!['no_prazo', 'atrasado', 'sem_contato'].includes(e.situacao)) { r.fora_da_conta += 1; return; }
        r.atribuicoes += 1; r[e.situacao] += 1;
        if (e.situacao !== 'no_prazo') r.atrasos += 1;
        if (e.situacao !== 'sem_contato' && e.minutos != null) { soma += e.minutos; n += 1; }
    });
    if (r.atribuicoes) r.pct_no_prazo = r.no_prazo / r.atribuicoes * 100;
    if (n) r.tempo_medio_min = soma / n;
    return r;
}
function t48pRegistroInfo() {   // situação do registro na planilha de log (aparece na sub-aba)
    return { aba: T48P_ABA, configurado: !!(process.env.GOOGLE_PRIVATE_KEY && process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL), intervalo_min: 5, ultima_rodada: t48pMonitor.ultimaRodada || null, ultimo_erro: t48pMonitor.ultimoErro || '', registrados: t48pMonitor.registrados };
}

app.get('/api/time48-primeiro-contato', async (req, res) => {
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
        const erroPeriodo = t48PeriodoGrande(dataInicioSQL, dataFimSQL);   // 🛡️ 14/10/2026: teto de período (consulta pesada no banco do Chatwoot)
        if (erroPeriodo) return res.status(400).json({ success: false, error: erroPeriodo });
        const r = await t48pAvaliar(T48P_JANELA_DIA, dataInicioSQL, dataFimSQL);
        const porAgente = {};
        r.eventos.forEach(e => {
            const k = e.agente_id ? 'id' + e.agente_id : 'nome' + e.agente;
            (porAgente[k] = porAgente[k] || { agente: e.agente, agente_id: e.agente_id, lista: [] }).lista.push(e);
        });
        const agentes = Object.values(porAgente).map(a => Object.assign({ agente: a.agente, agente_id: a.agente_id }, t48pContar(a.lista)))
            .sort((x, y) => (y.atrasos - x.atrasos) || (y.atribuicoes - x.atribuicoes) || String(x.agente).localeCompare(String(y.agente)));
        const casos = r.eventos.filter(e => e.situacao === 'atrasado' || e.situacao === 'sem_contato').sort((x, y) => y.atribuido_ms - x.atribuido_ms);
        res.json({
            success: true,
            periodo: { inicio: dataInicioSQL, fim: dataFimSQL },
            prazo_min: T48P_PRAZO_MIN,
            resumo: Object.assign(t48pContar(r.eventos), { agentes: agentes.filter(a => a.atribuicoes > 0).length }),
            agentes: agentes,
            casos: casos.slice(0, 3000),   // os atrasos (contato atrasado e sem contato), do mais novo para o mais antigo
            casos_total: casos.length,
            registro: t48pRegistroInfo()
        });
    } catch (error) {
        console.error("Erro Time 48h (1º contato 15 min):", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Monitor do 1º contato: a cada 5 min olha as atribuições das últimas 6h com o prazo vencido e grava os atrasos novos na aba t48_1contato.
// Não repete caso: a chave (conversa + registro da atribuição) é conferida na própria aba antes de gravar (as 2 cópias do Dash usam a mesma planilha).
async function t48pGarantirAba(sheets) {
    if (t48pMonitor.abaOk) return;
    const meta = await sheets.spreadsheets.get({ spreadsheetId: SNOOZE_SHEET_ID, fields: 'sheets.properties.title' });
    const existe = ((meta.data && meta.data.sheets) || []).some(s => s.properties && s.properties.title === T48P_ABA);
    if (!existe) await sheets.spreadsheets.batchUpdate({ spreadsheetId: SNOOZE_SHEET_ID, requestBody: { requests: [{ addSheet: { properties: { title: T48P_ABA } } }] } });
    const r = await sheets.spreadsheets.values.get({ spreadsheetId: SNOOZE_SHEET_ID, range: `${T48P_ABA}!A1:O1` });
    if (!r.data.values || !r.data.values.length) {
        await sheets.spreadsheets.values.update({ spreadsheetId: SNOOZE_SHEET_ID, range: `${T48P_ABA}!A1`, valueInputOption: 'RAW', requestBody: { values: [T48P_CAB] } });
    }
    t48pMonitor.abaOk = true;
}
function t48pLinhaPlanilha(e) {
    return [
        t48pTextoBR(Date.now()), e.chave, Number(e.id), `https://chat.institutoexperience.com/app/accounts/1/conversations/${encodeURIComponent(e.id)}`,
        String(e.cliente || ''), String(e.agente || ''), t48pTextoBR(e.atribuido_ms), String(e.atribuido_por || ''), String(e.origem || ''), t48pTextoBR(e.prazo_ms),
        e.situacao === 'atrasado' ? 'contato atrasado' : ('sem contato' + (e.fim_tipo ? ` (${T48P_FIM_TXT[e.fim_tipo] || e.fim_tipo})` : '')), e.minutos == null ? '' : Math.round(e.minutos),
        e.contato_ms ? t48pTextoBR(e.contato_ms) : '', String(e.contato_por || ''), T48P_STATUS[e.status] || ''
    ];
}
const t48pGravado = new Map();   // 14/10/2026: chave → colunas K:O (situação, minutos, 1º contato, status) que esta cópia gravou por último — só das atribuições da janela de 6 h
async function t48pRodarMonitor() {
    if (t48pMonitor.rodando) return;
    if (!process.env.GOOGLE_PRIVATE_KEY || !process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL) { t48pMonitor.ultimoErro = 'sem credenciais do Google (GOOGLE_PRIVATE_KEY / GOOGLE_SERVICE_ACCOUNT_EMAIL): nada é gravado na planilha'; return; }
    if (pool.waitingCount > 0 || Date.now() < FREIO.ate) return;   // 🛡️ banco ocupado (fila) ou com freio: tenta na próxima rodada
    t48pMonitor.rodando = true;
    try {
        const agora = Date.now() / 1000;
        const r = await t48pAvaliar(T48P_JANELA_TS, agora - 6 * 3600, agora - T48P_PRAZO_MIN * 60);
        const atrasos = r.eventos.filter(e => (e.situacao === 'atrasado' || e.situacao === 'sem_contato') && !t48pMonitor.chaves.has(e.chave));
        const mudaram = r.eventos.filter(e => (e.situacao === 'atrasado' || e.situacao === 'sem_contato') && t48pGravado.get(e.chave) !== JSON.stringify(t48pLinhaPlanilha(e).slice(10)));   // 14/10/2026: atraso que esta cópia ainda não gravou como está agora (linha nova ou que mudou)
        if (atrasos.length || mudaram.length || !t48pMonitor.chavesLidas) {   // 14/10/2026: + mudaram (atualiza a linha que já existe)
            const sheets = getSheetsRW();
            await t48pGarantirAba(sheets);
            const lidas = await sheets.spreadsheets.values.get({ spreadsheetId: SNOOZE_SHEET_ID, range: `${T48P_ABA}!B2:B` });   // relê as chaves: a outra cópia do Dash pode ter gravado
            ((lidas.data && lidas.data.values) || []).forEach(l => { if (l && l[0]) t48pMonitor.chaves.add(String(l[0])); });
            t48pMonitor.chavesLidas = true;
            const linhasDe = {};   // 14/10/2026: chave → linhas da aba (2, 3, ...), lidas logo antes de gravar; chave repetida (as 2 cópias gravaram no mesmo segundo) atualiza todas
            ((lidas.data && lidas.data.values) || []).forEach((l, k) => { if (l && l[0]) (linhasDe[String(l[0])] = linhasDe[String(l[0])] || []).push(k + 2); });
            const novos = atrasos.filter(e => !t48pMonitor.chaves.has(e.chave)).sort((x, y) => x.atribuido_ms - y.atribuido_ms);
            if (novos.length) {
                await sheets.spreadsheets.values.append({ spreadsheetId: SNOOZE_SHEET_ID, range: `${T48P_ABA}!A:O`, valueInputOption: 'RAW', insertDataOption: 'INSERT_ROWS', requestBody: { values: novos.map(t48pLinhaPlanilha) } });
                novos.forEach(e => t48pMonitor.chaves.add(e.chave));
                novos.forEach(e => t48pGravado.set(e.chave, JSON.stringify(t48pLinhaPlanilha(e).slice(10))));   // 14/10/2026
                t48pMonitor.registrados += novos.length;
                console.log(`⏱️ 1º contato 48H: ${novos.length} atraso(s) gravado(s) na planilha de log (aba ${T48P_ABA})`);
            }
            const paraAtualizar = mudaram.filter(e => linhasDe[e.chave]);   // 14/10/2026: a linha já está na aba → atualiza as colunas K:O dela (não grava de novo)
            if (paraAtualizar.length) {
                await sheets.spreadsheets.values.batchUpdate({ spreadsheetId: SNOOZE_SHEET_ID, requestBody: { valueInputOption: 'RAW', data: [].concat(...paraAtualizar.map(e => linhasDe[e.chave].map(n => ({ range: `${T48P_ABA}!K${n}:O${n}`, values: [t48pLinhaPlanilha(e).slice(10)] })))) } });
                paraAtualizar.forEach(e => t48pGravado.set(e.chave, JSON.stringify(t48pLinhaPlanilha(e).slice(10))));
                console.log(`⏱️ 1º contato 48H: ${paraAtualizar.length} linha(s) atualizada(s) na planilha de log (aba ${T48P_ABA})`);
            }
        }
        [...t48pGravado.keys()].forEach(k => { if (!r.eventos.some(e => e.chave === k)) t48pGravado.delete(k); });   // 14/10/2026: memória só das atribuições que ainda estão na janela de 6 h
        t48pMonitor.ultimaRodada = Date.now();
        t48pMonitor.ultimoErro = '';
    } catch (e) {
        t48pMonitor.ultimoErro = String((e && e.message) || e).slice(0, 200);
        console.error('[1º contato 48H] falha no monitor (tenta de novo em 5 min):', t48pMonitor.ultimoErro);
    } finally { t48pMonitor.rodando = false; }
}
function t48pAgendar(ms) {   // a cada 5 min (± 30 s, para as 2 cópias do Dash não rodarem no mesmo segundo)
    setTimeout(async () => { await t48pRodarMonitor(); t48pAgendar(5 * 60 * 1000 + Math.floor(Math.random() * 60000) - 30000); }, ms);
}
t48pAgendar(2 * 60 * 1000);   // 1ª rodada 2 min depois de ligar

// ==========================================
// 15.3.2 ⚖️ TMC E TMR JUSTOS (13/10/2026) — o relógio só corre na VEZ do agente
// A vez começa quando o caso fica com o agente: registro "Atribuído a X por Y" / "X atribuiu a si mesmo essa conversa" (registro gravado até 60 s
// depois da mensagem dele vale desde a mensagem) ou, sem registro, a tabela conversation_participants (só o agente atual, igual ao 1º contato 15 min).
// A vez termina quando o caso sai dele: outro agente, sem agente ou troca para um time do qual ele não faz parte. Resolver NÃO tira o caso dele: só zera a espera.
// Espera do cliente = 1ª mensagem dele ainda sem resposta (bot, nota e atividade não respondem). Cada resposta conta 1 e o relógio começa no que vier
// por último: essa 1ª mensagem do cliente ou o início da vez. TMC = 1ª resposta do agente na vez · TMR = as demais respostas dele na vez.
// Tempo corrido (24h, sábado e domingo contam). Período = data da resposta. Só LÊ o banco do Chatwoot.
// À parte (fora da média): "fora da vez" = respondeu o cliente com o caso fora dele · "saiu sem resposta" = o caso saiu dele com o cliente esperando 15 min ou mais na vez dele.
// Vale para 🧑‍💻 Atendimento por Agente e Time 48H (⏳ Visão Geral, 🏷️ Etiqueta 48H, 📦 Etiqueta Painel, 👥 Todos os Agentes e o /relatorio do bot).
// 🧠 Inteligência por Produto segue contando da mensagem do cliente (mede quanto o cliente esperou). O cálculo antigo (SQL das rotas) fica em tmc_antigo_minutos / tmr_antigo_minutos.
// Conferência: /api/raio-x-tmc
// ==========================================
const TJ_LOTE = 1000;   // conversas por consulta (não pesa no banco nem na memória do Dash)
const TJ_ATRIB = /^(atribu|assigned to )|( atribuiu a si mesmo essa conversa| self-assigned this conversation)$/i;   // o mesmo filtro do T48P_SQL_ATRIB

function tjUnixDia(dataStr, fimDoDia) {   // 00:00:00 (ou 23:59:59) do dia 'AAAA-MM-DD' no horário de Brasília, em segundos (UTC−3, igual ao bot)
    const [a, m, d] = String(dataStr).split('-').map(Number);
    return Date.UTC(a, m - 1, d, 3, 0, 0) / 1000 + (fimDoDia ? 86399 : 0);
}

// Mede cada resposta de agente das conversas (ids internos) enviada entre iniSeg e fimSeg (segundos). opcoes.amostras = guarda cada medição (Raio-X)
async function tjCalcular(convIds, iniSeg, fimSeg, opcoes) {
    const op = opcoes || {};
    const nomes = await t48pNomes();
    const porUsuario = {}, amostras = [];
    const tot = (uid) => (porUsuario[uid] = porUsuario[uid] || { tmcS: 0, tmcN: 0, tmrS: 0, tmrN: 0, fora: 0, saiu: 0 });
    const noPeriodo = (ts) => ts >= iniSeg && ts <= fimSeg;
    const baseDe = (uid) => t48pNomeBase(nomes.nomePorId[uid]);
    const mesmo = (id1, base1, id2, base2) => (id1 && id2) ? id1 === id2 : (!!base1 && base1 === base2);   // pelo id; sem id, pelo nome sem a sigla do time
    const ids = [...new Set((convIds || []).map(Number).filter(n => n > 0))];
    for (let i = 0; i < ids.length; i += TJ_LOTE) {
        const lote = ids.slice(i, i + TJ_LOTE);
        // 1) mensagens do cliente e respostas de agente (públicas, não apagadas) até o fim do período + registros de atribuição, desatribuição, time e resolvida
        const msgs = (await pool.query(`
            SELECT m.id, m.conversation_id AS conv_id, m.message_type AS tipo, m.sender_id, EXTRACT(EPOCH FROM m.created_at)::float8 AS ts,
                   CASE WHEN m.message_type = 2 THEN m.content END AS content
            FROM messages m
            WHERE m.conversation_id = ANY($1::bigint[]) AND m.account_id = 1
              AND ((m.message_type = 2 AND ${T48P_SQL_FIM})
                OR (m.created_at <= (to_timestamp($2::float8) AT TIME ZONE 'UTC') AND m.private = FALSE
                    AND (m.message_type = 0 OR (m.message_type = 1 AND m.sender_type = 'User' AND m.sender_id IS NOT NULL AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE))))`,
            [lote, fimSeg + T48P_FOLGA_SEG])).rows;
        // 2) atribuição automática antiga (sem registro na conversa): conversation_participants do agente ATUAL do ticket
        let parts = [];
        try {
            parts = (await pool.query(`
                SELECT cp.conversation_id AS conv_id, cp.user_id, EXTRACT(EPOCH FROM cp.created_at)::float8 AS ts
                FROM conversation_participants cp
                JOIN conversations c ON c.id = cp.conversation_id AND c.assignee_id = cp.user_id
                WHERE cp.conversation_id = ANY($1::bigint[])`, [lote])).rows;
        } catch (e) { parts = []; }   // Chatwoot sem a tabela: segue só com os registros da conversa
        // 3) linha do tempo de cada conversa
        const evPorConv = {}, regPorConv = {};
        const add = (cid, ev) => { (evPorConv[cid] = evPorConv[cid] || []).push(ev); };
        msgs.forEach(r => {
            const cid = Number(r.conv_id), ts = Number(r.ts), id = Number(r.id), tipo = Number(r.tipo);
            if (tipo === 0) { add(cid, { k: 'cli', ts, ord: 1, id }); return; }
            if (tipo === 1) { add(cid, { k: 'ag', ts, ord: 2, id, uid: Number(r.sender_id) }); return; }
            const txt = String(r.content || ''), l = t48pLerRegistro(txt, nomes);
            const rg = regPorConv[cid] = regPorConv[cid] || { ts: [], com: new Set() };
            if (TJ_ATRIB.test(txt)) rg.ts.push(ts);
            if (!l) return;
            if (l.tipo === 'atribuido') { if (l.agente_id) rg.com.add(l.agente_id); add(cid, { k: 'dono', ts, ord: 0, id, agente_id: l.agente_id, agente: l.agente }); }
            else if (l.tipo === 'desatribuido') add(cid, { k: 'sem_dono', ts, ord: 0, id });
            else if (l.tipo === 'time') add(cid, { k: 'time', ts, ord: 0, id, time_id: l.time_id });
            else if (l.tipo === 'encerrado') add(cid, { k: 'resolvido', ts, ord: 0, id });
            // time_removido: tirar o time não tira o agente
        });
        parts.forEach(p => {
            const cid = Number(p.conv_id), uid = Number(p.user_id), ts = Number(p.ts), rg = regPorConv[cid];
            if (rg && rg.com.has(uid)) return;                              // essa atribuição já tem o registro na conversa
            if (rg && rg.ts.some(t => Math.abs(t - ts) <= 120)) return;     // registro de atribuição no mesmo instante
            add(cid, { k: 'dono', ts, ord: 0, id: 0, agente_id: uid, agente: nomes.nomePorId[uid] || ('Agente #' + uid) });
        });
        // 4) a vez de cada agente, resposta por resposta
        Object.keys(evPorConv).forEach(chave => {
            const cid = Number(chave);
            const evs = evPorConv[chave].sort((a, b) => (a.ts - b.ts) || (a.ord - b.ord) || (a.id - b.id));
            const donos = evs.filter(e => e.k === 'dono');
            let dono = null, espera = null;   // dono = de quem é a vez · espera = 1ª mensagem do cliente ainda sem resposta
            const ehDele = (uid) => !!dono && mesmo(dono.id, dono.base, uid, baseDe(uid));
            const sair = (ts) => {   // o caso saiu do agente: "saiu sem resposta" se o cliente esperava 15 min ou mais na vez dele
                if (dono && dono.id && espera !== null && noPeriodo(ts)) {
                    const seg = ts - Math.max(espera, dono.desde);
                    if (seg >= T48P_PRAZO_MIN * 60) {
                        tot(dono.id).saiu += 1;
                        if (op.amostras) amostras.push({ conv_id: cid, uid: dono.id, tipo: 'saiu sem resposta', ts, espera, desde: dono.desde, seg });
                    }
                }
                dono = null;
            };
            const assumir = (e, ts) => {   // o caso passa a ser de e.agente a partir de ts (registro do mesmo agente: a vez continua)
                if (dono && mesmo(dono.id, dono.base, e.agente_id, t48pNomeBase(e.agente))) return;
                sair(ts);
                dono = { id: e.agente_id || null, nome: e.agente, base: t48pNomeBase(e.agente), desde: ts, respondeu: false };
            };
            evs.forEach(e => {
                if (e.k === 'dono') { assumir(e, e.ts); return; }
                if (e.k === 'sem_dono') { sair(e.ts); return; }
                if (e.k === 'time') {   // mudou de time: se o agente faz parte do time novo, o caso continua com ele
                    if (dono && dono.id && nomes.membros && e.time_id && nomes.membros.has(`${e.time_id}|${dono.id}`)) return;
                    sair(e.ts); return;
                }
                if (e.k === 'resolvido') { espera = null; return; }   // resolvida: zera a espera (o caso continua com o agente)
                if (e.k === 'cli') { if (espera === null) espera = e.ts; return; }
                // resposta de agente
                if (!ehDele(e.uid)) {   // folga: o registro da atribuição dele foi gravado até 60 s depois desta mensagem
                    const prox = donos.find(d => d.ts > e.ts && d.ts <= e.ts + T48P_FOLGA_SEG && mesmo(d.agente_id, t48pNomeBase(d.agente), e.uid, baseDe(e.uid)));
                    if (prox) assumir(prox, e.ts);
                }
                const daVez = ehDele(e.uid);
                if (espera !== null && noPeriodo(e.ts)) {
                    if (daVez) {
                        const seg = Math.max(0, e.ts - Math.max(espera, dono.desde)), t = tot(e.uid);
                        if (dono.respondeu) { t.tmrS += seg; t.tmrN += 1; } else { t.tmcS += seg; t.tmcN += 1; }
                        if (op.amostras) amostras.push({ conv_id: cid, uid: e.uid, tipo: dono.respondeu ? 'TMR' : 'TMC', ts: e.ts, espera, desde: dono.desde, seg });
                    } else {
                        tot(e.uid).fora += 1;
                        if (op.amostras) amostras.push({ conv_id: cid, uid: e.uid, tipo: 'fora da vez', ts: e.ts, espera, desde: null, seg: e.ts - espera, dono: dono ? dono.nome : '' });
                    }
                }
                espera = null;   // o cliente foi respondido (por quem for)
                if (daVez) dono.respondeu = true;
            });
        });
    }
    return { porUsuario, amostras, conversas: ids.length };
}

// Troca o TMC/TMR das linhas da tela pelo justo (mesmos agentes e tickets da rota) e guarda o antigo para conferência
async function tjAplicar(dados, linhas, dataInicioSQL, dataFimSQL) {
    if (!dados || !dados.length) return;
    const nomePorUid = {};
    (linhas || []).forEach(r => { nomePorUid[Number(r.user_id)] = r.agente; });
    const r = await tjCalcular((linhas || []).map(x => x.conv_id), tjUnixDia(dataInicioSQL, false), tjUnixDia(dataFimSQL, true));
    const porNome = {};
    Object.keys(r.porUsuario).forEach(uid => {
        const nome = nomePorUid[Number(uid)];
        if (nome === undefined) return;   // agente que não está nesta tela
        const s = r.porUsuario[uid], a = porNome[nome] = porNome[nome] || { tmcS: 0, tmcN: 0, tmrS: 0, tmrN: 0, fora: 0, saiu: 0 };
        a.tmcS += s.tmcS; a.tmcN += s.tmcN; a.tmrS += s.tmrS; a.tmrN += s.tmrN; a.fora += s.fora; a.saiu += s.saiu;
    });
    dados.forEach(d => {
        const a = porNome[d.agente] || { tmcS: 0, tmcN: 0, tmrS: 0, tmrN: 0, fora: 0, saiu: 0 };
        d.tmc_antigo_minutos = d.tmc_medio_minutos;   // regra antiga (SQL da rota), só para conferência
        d.tmr_antigo_minutos = d.tmr_medio_minutos;
        d.tmc_medio_minutos = a.tmcN ? a.tmcS / a.tmcN / 60 : 0;
        d.tmr_medio_minutos = a.tmrN ? a.tmrS / a.tmrN / 60 : 0;
        d.tmc_qtd = a.tmcN;                 // base do TMC: 1ª resposta de cada vez
        d.tmr_qtd = a.tmrN;                 // base do TMR: as demais respostas na vez
        d.fora_da_vez = a.fora;             // à parte: respostas com o caso fora do agente
        d.saiu_sem_resposta = a.saiu;       // à parte: casos que saíram do agente com o cliente esperando 15 min ou mais
    });
}

// 🩻 RAIO-X DO TMC/TMR JUSTOS (somente leitura) — SOMENTE ADMIN · confere, num dia, cada resposta medida (dá para apagar esta rota sem afetar nada)
// Abra: /api/raio-x-tmc (hoje) ou /api/raio-x-tmc?dia=AAAA-MM-DD
app.get('/api/raio-x-tmc', async (req, res) => {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    if (!adms.includes(emailUser)) return res.status(403).send('<h1>Acesso restrito a administradores.</h1>');

    const esc = (v) => String(v === null || v === undefined ? '' : v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const tabela = (cab, linhas) => '<table><tr>' + cab.map(c => `<th>${esc(c)}</th>`).join('') + '</tr>' + linhas.map(l => '<tr>' + l.map(v => `<td>${v}</td>`).join('') + '</tr>').join('') + '</table>';
    const dur = (min) => { if (!min) return '—'; const t = Math.round(min); return t < 60 ? t + ' min' : `${Math.floor(t / 60)}h ${t % 60}m`; };
    const hora = (seg) => seg == null ? '—' : esc(t48pTextoBR(seg * 1000).slice(5, 16).replace(/^(\d\d)-(\d\d)/, '$2/$1'));   // 'DD/MM HH:MM' no horário de Brasília
    const dia = /^\d{4}-\d{2}-\d{2}$/.test(String(req.query.dia || '')) ? String(req.query.dia) : t48pTextoBR(Date.now()).slice(0, 10);
    let html = `<!doctype html><html lang="pt-br"><head><meta charset="utf-8"><title>Raio-X do TMC/TMR</title>
    <style>
      body{font-family:system-ui,Segoe UI,Arial;background:#0f172a;color:#e2e8f0;padding:24px;}
      h1{color:#22d3ee;} h2{color:#93c5fd;margin-top:22px;border-bottom:1px solid #334155;padding-bottom:6px;font-size:16px;}
      a{color:#38bdf8;text-decoration:none;} a:hover{text-decoration:underline;}
      table{border-collapse:collapse;width:100%;margin-top:8px;font-size:13px;}
      th,td{border:1px solid #334155;padding:6px 8px;text-align:left;vertical-align:top;}
      th{background:#1e293b;color:#cbd5e1;} tr:nth-child(even){background:#111c30;}
      .box{background:#1e293b;padding:10px 14px;border-radius:8px;margin-top:6px;line-height:1.6;}
      .aviso{background:#064e3b;color:#a7f3d0;padding:8px 12px;border-radius:8px;display:inline-block;margin-bottom:10px;}
      code{color:#fbbf24;}
    </style></head><body>
    <h1>🩻 Raio-X do TMC/TMR justos — ${esc(dia.split('-').reverse().join('/'))}</h1>
    <div class="aviso">🔒 Modo leitura: só executa SELECT. Nada é criado, alterado ou apagado no Chatwoot.</div>
    <div class="box">Regra: o relógio só corre na <b>vez do agente</b> (da atribuição até o caso sair dele). Cada resposta conta desde o que vier por último: a 1ª mensagem do cliente ainda sem resposta ou o início da vez.
    <b>TMC</b> = 1ª resposta do agente na vez · <b>TMR</b> = as demais respostas dele na vez · tempo corrido. Outro dia: <code>/api/raio-x-tmc?dia=AAAA-MM-DD</code></div>`;
    try {
        const ini = tjUnixDia(dia, false), fim = tjUnixDia(dia, true);
        // 1) antes × agora por agente: a própria rota do 🧑‍💻 Atendimento por Agente nesse dia
        const ag = await tgGetInterno(`/api/atendimento-agentes?since=${ini}&until=${fim}`, 120000);
        html += `<h2>1) Antes × agora por agente (🧑‍💻 Atendimento por Agente, mensagens enviadas no dia)</h2>`;
        html += ag && ag.success && (ag.dados || []).length ? tabela(['agente', 'time', 'tickets', 'TMC antes', 'TMC agora', 'base TMC', 'TMR antes', 'TMR agora', 'base TMR', 'fora da vez', 'saiu sem resposta'], ag.dados.map(d => [
            esc(d.agente), esc(d.time), esc(d.tickets), dur(d.tmc_antigo_minutos), `<b>${dur(d.tmc_medio_minutos)}</b>`, esc(d.tmc_qtd), dur(d.tmr_antigo_minutos), `<b>${dur(d.tmr_medio_minutos)}</b>`, esc(d.tmr_qtd), esc(d.fora_da_vez), esc(d.saiu_sem_resposta)
        ])) : `<div class="box">${ag && ag.success ? '(nenhum agente enviou mensagem nesse dia)' : '(não consegui ler a rota do Atendimento por Agente agora)'}</div>`;

        // 2) cada medição do dia (mais recentes primeiro), para conferir no Chatwoot
        const ids = (await pool.query(`
            SELECT DISTINCT m.conversation_id AS id
            FROM messages m
            WHERE m.account_id = 1 AND m.message_type = 1 AND m.private = FALSE AND m.sender_type = 'User' AND m.sender_id IS NOT NULL
              AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE
              AND m.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
              AND m.created_at <= ($1 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'`, [dia])).rows.map(r => r.id);
        const r = await tjCalcular(ids, ini, fim, { amostras: true });
        const nomes = await t48pNomes();
        const cont = {};
        r.amostras.forEach(a => { cont[a.tipo] = (cont[a.tipo] || 0) + 1; });
        const am = r.amostras.sort((a, b) => b.ts - a.ts).slice(0, 60);
        const disp = {};
        if (am.length) (await pool.query(`SELECT id, display_id FROM conversations WHERE id = ANY($1::bigint[])`, [[...new Set(am.map(a => a.conv_id))]])).rows.forEach(x => { disp[Number(x.id)] = x.display_id; });
        html += `<h2>2) As 60 medições mais recentes do dia · ${r.conversas} conversas · ${Object.keys(cont).map(k => esc(k) + ': ' + cont[k]).join(' · ') || 'nenhuma medição'}</h2>`;
        html += am.length ? tabela(['ticket', 'agente', 'medição', 'cliente esperando desde', 'vez do agente desde', 'resposta / saída', 'tempo contado', 'observação'], am.map(a => {
            const id = disp[a.conv_id] || a.conv_id;
            const obs = a.tipo === 'fora da vez' ? 'não entra na média · ' + (a.dono ? 'o caso estava com ' + esc(a.dono) : 'o caso estava sem agente')
                : a.tipo === 'saiu sem resposta' ? 'não entra na média · o caso saiu do agente com o cliente esperando'
                : (a.desde > a.espera ? 'o cliente já esperava antes da vez: conta desde o início da vez' : 'conta desde a 1ª mensagem do cliente sem resposta');
            return [`<a href="https://chat.institutoexperience.com/app/accounts/1/conversations/${encodeURIComponent(id)}" target="_blank">#${esc(id)}</a>`,
                esc(nomes.nomePorId[a.uid] || ('Agente #' + a.uid)), esc(a.tipo), hora(a.espera), hora(a.desde), hora(a.ts), esc((a.seg / 60).toFixed(1)) + ' min', obs];
        })) : '<div class="box">(nenhuma resposta a cliente esperando nesse dia)</div>';
        html += '</body></html>';
        res.send(html);
    } catch (e) {
        res.status(500).send(`<body style="background:#0f172a;color:#f87171;font-family:system-ui;padding:24px"><h1>Erro (nada foi alterado)</h1><pre>${String(e.message).replace(/</g,'&lt;')}</pre></body>`);
    }
});

// 🩻 RAIO-X DA ATRIBUIÇÃO (somente leitura) — SOMENTE ADMIN · mostra os registros de atribuição que o banco tem nos tickets 48H/Painel
// Abra: /api/raio-x-atribuicao
app.get('/api/raio-x-atribuicao', async (req, res) => {
    const emailUser = (req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value.toLowerCase() : '';
    const adms = (process.env.EMAILS_ADM || 'maurilio@institutoexperience.com.br').split(',').map(e => e.trim().toLowerCase());
    if (!adms.includes(emailUser)) return res.status(403).send('<h1>Acesso restrito a administradores.</h1>');

    const esc = (v) => (v === null || v === undefined) ? '<i style="color:#64748b">null</i>'
        : String(typeof v === 'object' ? JSON.stringify(v) : v).replace(/</g, '&lt;');
    const tabela = (cab, linhas) => '<table><tr>' + cab.map(c => `<th>${esc(c)}</th>`).join('') + '</tr>' + linhas.map(l => '<tr>' + l.map(v => `<td>${v}</td>`).join('') + '</tr>').join('') + '</table>';
    let html = `<!doctype html><html lang="pt-br"><head><meta charset="utf-8"><title>Raio-X da Atribuição</title>
    <style>
      body{font-family:system-ui,Segoe UI,Arial;background:#0f172a;color:#e2e8f0;padding:24px;}
      h1{color:#22d3ee;} h2{color:#93c5fd;margin-top:22px;border-bottom:1px solid #334155;padding-bottom:6px;font-size:16px;}
      a{color:#38bdf8;text-decoration:none;} a:hover{text-decoration:underline;}
      table{border-collapse:collapse;width:100%;margin-top:8px;font-size:13px;}
      th,td{border:1px solid #334155;padding:6px 8px;text-align:left;vertical-align:top;}
      th{background:#1e293b;color:#cbd5e1;} tr:nth-child(even){background:#111c30;}
      .box{background:#1e293b;padding:10px 14px;border-radius:8px;margin-top:6px;line-height:1.6;}
      .aviso{background:#064e3b;color:#a7f3d0;padding:8px 12px;border-radius:8px;display:inline-block;margin-bottom:10px;}
      .ok{color:#34d399;} .fail{color:#f87171;} code{color:#fbbf24;}
    </style></head><body>
    <h1>🩻 Raio-X da Atribuição — ⏱️ 1º Contato 15 min do Time 48H</h1>
    <div class="aviso">🔒 Modo leitura: só executa SELECT. Nada é criado, alterado ou apagado no Chatwoot.</div>
    <div class="box">De onde vem a atribuição: <b>1)</b> o registro que o Chatwoot grava dentro da conversa toda vez que alguém atribui, pega para si, distribui por time ou a automação atribui (ex.: <code>Atribuído a Maria por Leo</code>) · <b>2)</b> a tabela <code>conversation_participants</code>, para a distribuição automática antiga, que não grava esse registro (só a do agente atual do ticket).<br>
    Não servem: <code>audits</code> (o Chatwoot só guarda conversa apagada) e <code>reporting_events</code> (não tem evento de atribuição). Não precisa de webhook nem do Raio-X para puxar os dados.</div>`;
    try {
        const tabs = (await pool.query(`SELECT to_regclass('public.conversation_participants') IS NOT NULL AS conversation_participants, to_regclass('public.team_members') IS NOT NULL AS team_members, to_regclass('public.audits') IS NOT NULL AS audits`)).rows[0] || {};
        html += `<h2>1) Tabelas</h2>` + tabela(['tabela', 'existe?', 'uso'], [
            ['messages (registro de atividade, message_type 2)', '<span class="ok">sim</span>', 'fonte principal: quem atribuiu, para quem e quando'],
            ['conversation_participants', tabs.conversation_participants ? '<span class="ok">sim</span>' : '<span class="fail">não</span>', 'distribuição automática antiga (sem registro na conversa)'],
            ['team_members', tabs.team_members ? '<span class="ok">sim</span>' : '<span class="fail">não</span>', 'quando o ticket muda de time: o agente é desse time? (se for, o caso continua com ele)'],
            ['audits', tabs.audits ? 'sim' : 'não', 'não usado (o Chatwoot não audita a conversa, só a exclusão)']
        ]);

        const nomes = await t48pNomes();
        const ids = (await pool.query(`SELECT DISTINCT t.taggable_id AS id FROM taggings t JOIN tags tg ON tg.id = t.tag_id WHERE t.taggable_type = 'Conversation' AND (tg.name ILIKE '%time-48h%' OR tg.name ILIKE 'painel-do-pedido%')`)).rows.map(r => r.id);
        const regs = ids.length ? (await pool.query(`
            SELECT m.content
            FROM messages m
            WHERE m.conversation_id = ANY($1::bigint[]) AND m.account_id = 1 AND m.message_type = 2
              AND m.created_at >= ((now() - interval '30 days') AT TIME ZONE 'UTC') AND ${T48P_SQL_FIM}
            ORDER BY m.created_at DESC`, [ids])).rows : [];
        const porTipo = {};
        regs.forEach(r => {
            const l = t48pLerRegistro(r.content, nomes);
            const k = l ? (l.tipo === 'atribuido' ? 'atribuido · ' + l.origem + (l.agente_id ? '' : ' · agente não achado pelo nome') : l.tipo) : 'não reconhecido';
            const o = porTipo[k] || (porTipo[k] = { n: 0, ex: [] });
            o.n += 1;
            if (o.ex.length < (k === 'não reconhecido' ? 15 : 2)) o.ex.push(r.content);
        });
        html += `<h2>2) Registros de atribuição nos tickets 48H/Painel — últimos 30 dias (${ids.length} tickets com a etiqueta, ${regs.length} registros)</h2>`;
        html += Object.keys(porTipo).length ? tabela(['tipo', 'quantidade', 'exemplos'], Object.keys(porTipo).sort((a, b) => porTipo[b].n - porTipo[a].n).map(k => [esc(k), porTipo[k].n, porTipo[k].ex.map(esc).join('<br>')]))
            : '<div class="box">(nenhum registro nos últimos 30 dias)</div>';

        const agora = Date.now() / 1000;
        const av = await t48pAvaliar(T48P_JANELA_TS, agora - 7 * 86400, agora);
        const cont = t48pContar(av.eventos), d = av.diag;
        const porSit = {};
        av.eventos.forEach(e => { porSit[e.situacao] = (porSit[e.situacao] || 0) + 1; });
        html += `<h2>3) Avaliação dos últimos 7 dias (mesma regra da sub-aba ⏱️ 1º Contato 15 min)</h2>`;
        html += tabela(['item', 'quantidade'], [
            ['registros de atribuição lidos', d.registros], ['atribuições pela conversation_participants (sem registro)', d.participantes_usados],
            ['atribuições sem o cliente esperando resposta (não entram)', d.sem_cliente_esperando],
            ['contadas (prazo vencido)', cont.atribuicoes], ['✅ no prazo (até 15 min)', cont.no_prazo], ['🟠 contato atrasado', cont.atrasado], ['🔴 sem contato', cont.sem_contato],
            ['⏳ ainda dentro dos 15 min', cont.aguardando], ['fora da conta (saiu do agente ou encerrou antes dos 15 min)', cont.fora_da_conta],
            ['por situação', esc(porSit)]
        ]);
        const amostra = av.eventos.slice().sort((x, y) => y.atribuido_ms - x.atribuido_ms).slice(0, 30);
        html += `<h2>4) Amostra: as 30 atribuições mais recentes (confira no Chatwoot)</h2>`;
        html += amostra.length ? tabela(['ticket', 'agente', 'atribuído em', 'por', 'origem', 'cliente escreveu', '1º contato', 'minutos', 'situação', 'fim da vez'], amostra.map(e => [
            `<a href="https://chat.institutoexperience.com/app/accounts/1/conversations/${encodeURIComponent(e.id)}" target="_blank">#${esc(e.id)}</a>`,
            esc(e.agente), esc(t48pTextoBR(e.atribuido_ms)), esc(e.atribuido_por), esc(e.origem), esc(t48pTextoBR(e.cliente_ms)),
            e.contato_ms ? esc(t48pTextoBR(e.contato_ms) + ' · ' + (e.contato_por || '')) : '—', e.minutos == null ? '—' : esc(e.minutos), esc(e.situacao),
            e.fim_tipo ? esc(e.fim_tipo + ' · ' + t48pTextoBR(e.fim_ms)) : '—'
        ])) : '<div class="box">(nenhuma atribuição nos últimos 7 dias)</div>';

        const reg = t48pRegistroInfo();
        html += `<h2>5) Registro na planilha de log (aba <code>${T48P_ABA}</code>)</h2><div class="box">Credenciais do Google: ${reg.configurado ? '<span class="ok">ok</span>' : '<span class="fail">faltando — o monitor não grava</span>'} · roda a cada ${reg.intervalo_min} min · última rodada: ${reg.ultima_rodada ? esc(t48pTextoBR(reg.ultima_rodada)) : '—'} · gravados desde que o Dash ligou: ${reg.registrados}${reg.ultimo_erro ? ` · <span class="fail">último erro: ${esc(reg.ultimo_erro)}</span>` : ''}</div>`;
        html += '</body></html>';
        res.send(html);
    } catch (e) {
        res.status(500).send(`<body style="background:#0f172a;color:#f87171;font-family:system-ui;padding:24px"><h1>Erro (nada foi alterado)</h1><pre>${String(e.message).replace(/</g,'&lt;')}</pre></body>`);
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
        const erroPeriodo = t48PeriodoGrande(dataInicioSQL, dataFimSQL);   // 🛡️ 14/10/2026: teto de período (consulta pesada no banco do Chatwoot)
        if (erroPeriodo) return res.status(400).json({ success: false, error: erroPeriodo });
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
                lider: tkLiderDe(a.agente),   // 27/10/2026: abas por lider na tela de Atendimento por Agente (fonte unica: TK_EQUIPE)
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
        await tjAplicar(dados, todasLinhas, dataInicioSQL, dataFimSQL);   // ⚖️ TMC/TMR justos (13/10/2026): só na vez do agente (todasLinhas: o mesmo resultado com ou sem filtro de time)

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

        // 27/10/2026: mesmo resumo cruzando time x lider (chave "TIME::lider"), sem repetir ticket — para as abas por lider da tela
        const porCombo = {};
        ['todos', 'flavia', 'adevania', 'camila'].forEach(ld => {
            ['TODOS', ...TIMES].forEach(t => {
                const tks = new Set(), abs = new Set(), rets = new Set(), ags = new Set();
                let msgs = 0;
                linhas.forEach(r => {
                    if (t !== 'TODOS' && r.time !== t) return;
                    if (ld !== 'todos' && tkLiderDe(r.agente) !== ld) return;
                    const id = String(r.conv_id);
                    tks.add(id); ags.add(r.agente);
                    if (parseInt(r.status) === 0) abs.add(id);
                    if (r.ultimo_retorno) rets.add(id);
                    msgs += parseInt(r.msgs) || 0;
                });
                porCombo[t + '::' + ld] = { agentes: ags.size, tickets: tks.size, em_aberto: abs.size, retornos: rets.size, mensagens: msgs };
            });
        });

        // 28/10/2026: a aba de um líder precisa mostrar a EQUIPE INTEIRA, não só quem mandou mensagem no período.
        // Manda a lista do TK_EQUIPE (mesma fonte do campo `lider`) para a tela completar com os zerados.
        const equipes = Object.keys(TK_EQUIPE).map(n => ({ agente: n, time: atdTimeDoAgente(n), lider: TK_EQUIPE[n][0] }));

        res.json({ success: true, dados: dados, por_time: porTime, por_combo: porCombo, equipes: equipes, periodo: { inicio: dataInicioSQL, fim: dataFimSQL } });
    } catch (error) {
        console.error("Erro Atendimento por Agente:", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==========================================
// 15.5 TICKETS OPERAÇÃO — 📥 RECEBIMENTO DE TICKETS (06/10/2026 · regra nova em 14/10/2026)
// Conversas NOVAS criadas no período, separadas por time pela mesma regra do Status de Casos:
// etiqueta 48H/Painel colocada na chegada (até 10 min) → 48H · caixa [GEX] SMS Support → SMS · time do Chatwoot → RET/SAC/BKO/SMS
// · etiqueta colocada depois e time desconhecido → 48H · sem time → OUTROS · compara com o período anterior do mesmo tamanho · hoje = dia parcial
// 14/10: só conta a conversa aberta pelo cliente (1ª mensagem pública é dele) · duplicadas (etiqueta "duplicado"), abertas por nós
// e sem mensagem ficam à parte em "fora" · caixas "Atendimento | Brasil" e "Pitaco Teste" fora, sem exceção
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
                SELECT tg.taggable_id AS conv_id, MIN(tg.created_at) AS etiquetada_em   -- 14/10: quando a etiqueta 48H/Painel foi colocada
                FROM taggings tg
                JOIN tags t2 ON t2.id = tg.tag_id
                WHERE tg.taggable_type = 'Conversation' AND (t2.name ILIKE '%time-48h%' OR t2.name ILIKE 'painel-do-pedido%')
                GROUP BY tg.taggable_id
            ),
            Recebidos AS (
                SELECT
                    c.status,
                    c.assignee_id,
                    (c.created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo') AS criado_br,
                    CASE
                        WHEN c48.etiquetada_em <= c.created_at + interval '10 minutes' THEN '48H'   -- 14/10: 48H só com a etiqueta colocada na chegada
                        WHEN i.name = '[GEX] SMS Support' THEN 'SMS'
                        WHEN t.name ILIKE '%reten%' THEN 'RET'
                        WHEN t.name ILIKE '%sac%' THEN 'SAC'
                        WHEN t.name ILIKE '%back office%' OR t.name ILIKE '%backoffice%' OR t.name ILIKE '%bko%' THEN 'BKO'
                        WHEN t.name ILIKE '%sms%' THEN 'SMS'
                        WHEN c48.conv_id IS NOT NULL THEN '48H'   -- 14/10: etiqueta colocada depois e time desconhecido
                        ELSE 'OUTROS'
                    END AS setor,
                    CASE   -- 14/10: só a conversa aberta pelo cliente conta; o resto fica à parte
                        WHEN COALESCE(c.cached_label_list, '') ILIKE '%duplicado%' THEN 'duplicado'
                        WHEN pm.message_type IS NULL THEN 'sem_mensagem'
                        WHEN pm.message_type IN (1, 3) THEN 'aberto_por_nos'
                        ELSE 'valido'
                    END AS tipo
                FROM conversations c
                LEFT JOIN teams t ON t.id = c.team_id
                LEFT JOIN inboxes i ON i.id = c.inbox_id
                LEFT JOIN Conv48 c48 ON c48.conv_id = c.id
                LEFT JOIN LATERAL (   -- 14/10: 1ª mensagem pública (0 = do cliente · 1 e 3 = nossa)
                    SELECT m.message_type FROM messages m
                    WHERE m.conversation_id = c.id AND m.private = FALSE AND m.message_type IN (0, 1, 3)
                    ORDER BY m.created_at, m.id LIMIT 1
                ) pm ON TRUE
                WHERE c.account_id = 1
                  AND c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                  AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
                  AND (i.name IS NULL OR i.name NOT IN ('Atendimento | Brasil', 'Pitaco Teste'))   -- 14/10: fora, sem exceção
                  AND COALESCE(c.cached_label_list, '') NOT ILIKE '%spam%'   -- 30/10/2026: spam fora da conta (mesma regra da tela Recebimento de Tickets)
            )
            ${selecao}`;
        const linhas = (await pool.query(base(`
            SELECT setor, TO_CHAR(criado_br, 'YYYY-MM-DD') AS dia, EXTRACT(HOUR FROM criado_br)::int AS hora, status, (assignee_id IS NULL) AS sem_agente, tipo, COUNT(*)::int AS qtd
            FROM Recebidos GROUP BY 1, 2, 3, 4, 5, 6`), [dataInicioSQL, dataFimSQL])).rows;
        const linhasAnt = (await pool.query(base(`SELECT setor, COUNT(*)::int AS qtd FROM Recebidos WHERE tipo = 'valido' GROUP BY 1`), [ymd(antIni), ymd(antFim)])).rows;

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
        const fora = {};   // 14/10: o que ficou fora da conta, por time
        ['TODOS', ...TIMES].forEach(t => { fora[t] = { duplicados: 0, abertos_por_nos: 0, sem_mensagem: 0 }; });
        linhas.forEach(r => {
            const t = TIMES.includes(r.setor) ? r.setor : 'OUTROS', n = parseInt(r.qtd) || 0, st = parseInt(r.status);
            if (r.tipo !== 'valido') {   // 14/10: duplicada, aberta por nós ou sem mensagem → à parte
                const k = r.tipo === 'duplicado' ? 'duplicados' : (r.tipo === 'aberto_por_nos' ? 'abertos_por_nos' : 'sem_mensagem');
                fora.TODOS[k] += n; fora[t][k] += n;
                return;
            }
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
            fora: fora,   // 14/10
            anterior: { inicio: ymd(antIni), fim: ymd(antFim), dias: dias, por_time: anterior }
        });
    } catch (error) {
        console.error("Erro Recebimento de Tickets:", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==========================================
// 15.5.1 ⏱️ SLA DO RECEBIMENTO (16/10/2026) — sub-aba ⏱️ SLA de Recebimento de Tickets · SOMENTE ADMIN · só leitura
// Uma consulta por carga traz todos os blocos (cards, hora, dia, faixa, próxima resposta, capacidade, agora) em formato longo; o filtro de time é feito na tela.
// O cache de 30 min por período é o do cacheMiddleware (a URL tem o período); o 🔄 Atualizar fura o cache com fresh=1.
// Período máximo de 92 dias; a comparação com o período anterior (mesmo tamanho) vai até 46 dias, para não pesar no banco.
// ==========================================
const SLA_MAX_DIAS = 31, SLA_MAX_DIAS_COMPARACAO = 31;   // 17/10/2026: SLA por aberturas — período máximo 31 dias, sempre compara com o anterior do mesmo tamanho
const SLA_SQL = `
-- ⏱️ SLA do Recebimento v2 (17/10/2026) — base de ABERTURAS (clientes N+R). Uma consulta por carga, só leitura.
-- Espera (w) = do instante da abertura até o 1º contato humano (message_type 1, público, sender_id <> 2), tempo corrido.
-- "% em até 1h" só conta a abertura que já passou de 1h (mad1); "% em até 24h" só a que já passou de 24h (mad24); sem contato = fora.
-- $1 = início · $2 = fim (AAAA-MM-DD, Brasília) · $2 = início da leitura (período anterior; = $1 sem comparação) · $3 = dia seguinte ao fim.
-- Saída em formato longo: bloco, periodo, setor, k, n, v1..v9.
WITH conv AS (
    SELECT c.id, c.inbox_id
    FROM conversations c JOIN inboxes i ON i.id = c.inbox_id
    WHERE c.account_id = 1
      AND i.name NOT IN ('Atendimento | Brasil', 'Pitaco Teste')
      AND COALESCE(c.cached_label_list, '') NOT ILIKE '%duplicado%'
      AND COALESCE(c.cached_label_list, '') NOT ILIKE '%spam%'
      AND COALESCE(c.cached_label_list, '') NOT ILIKE '%compra_teste%'
      AND c.contact_id NOT IN (279944, 244572, 9950, 272736, 244905, 4133, 271799)
      AND c.last_activity_at >= ($2 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
),
ev AS (
    SELECT c.id AS cid, c.created_at AS t, 1 AS pri, 'criacao' AS src FROM conversations c
    WHERE c.account_id = 1 AND c.created_at >= ($2 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo' AND c.created_at < ($3 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
    UNION ALL
    SELECT m.conversation_id, m.created_at, 2, CASE WHEN m.content ILIKE '%Sarah Williams%' OR m.content ILIKE 'O sistema reabriu%' THEN 'reab_cli' ELSE 'reab_ag' END
    FROM messages m WHERE m.account_id = 1 AND m.message_type = 2
      AND (m.content ILIKE 'Conversa foi reaberta%' OR m.content ILIKE 'O sistema reabriu%' OR m.content ILIKE 'Conversation was reopened%')
      AND m.created_at >= ($2 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo' AND m.created_at < ($3 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
    UNION ALL
    SELECT re.conversation_id, re.created_at, 3, 'evt' FROM reporting_events re
    WHERE re.account_id = 1 AND re.name = 'conversation_opened'
      AND re.created_at >= ($2 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo' AND re.created_at < ($3 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
),
ev2 AS (SELECT ev.*, lag(t) OVER (PARTITION BY cid ORDER BY t, pri) AS tprev FROM ev WHERE cid IN (SELECT id FROM conv)),
grp AS (SELECT *, sum(CASE WHEN tprev IS NULL OR t - tprev > interval '2 minutes' THEN 1 ELSE 0 END) OVER (PARTITION BY cid ORDER BY t, pri) AS g FROM ev2),
ab AS (SELECT cid, g, min(t) AS t, bool_or(src = 'criacao') AS criacao, bool_or(src = 'reab_cli') AS rcli, bool_or(src = 'reab_ag') AS rag FROM grp GROUP BY cid, g),
cli AS (
    SELECT conv.inbox_id, i.name AS caixa,
      CASE WHEN i.channel_type = 'Channel::Email' THEN 'E-mail' WHEN i.name = '[GEX] SMS Support' THEN 'SMS' WHEN i.channel_type = 'Channel::WebWidget' THEN 'Chat web' ELSE 'Outros' END AS canal,
      ab.t,
      (ab.t AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo') AS tb,
      CASE WHEN ab.t >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo' THEN 'atual' ELSE 'anterior' END AS periodo,
      CASE WHEN ab.criacao THEN CASE WHEN (SELECT m.message_type FROM messages m WHERE m.conversation_id = ab.cid AND m.private = false AND m.message_type IN (0,1,3) ORDER BY m.created_at, m.id LIMIT 1) = 0 THEN 'N' ELSE 'F' END
           WHEN EXISTS (SELECT 1 FROM messages x WHERE x.conversation_id = ab.cid AND x.message_type = 0 AND x.created_at BETWEEN ab.t - interval '2 minutes' AND ab.t + interval '2 minutes') THEN 'R'
           ELSE 'S' END AS tipo,   -- 20/10: reabertura com msg do cliente = Retorno (R); sem = Follow-up nosso (S)
      (SELECT min(m.created_at) FROM messages m WHERE m.conversation_id = ab.cid AND m.message_type = 1 AND m.private = false AND m.sender_type = 'User' AND m.sender_id <> 2 AND coalesce(m.content_attributes::text, '') NOT LIKE '%deleted%true%' AND m.created_at >= ab.t - interval '2 minutes') AS t1,
      (SELECT min(m.created_at) FROM messages m LEFT JOIN users uia ON uia.id = m.sender_id WHERE m.conversation_id = ab.cid AND m.message_type = 1 AND m.private = false AND (m.sender_id = 2 OR uia.name ILIKE '%sarah williams%' OR uia.name ILIKE '%copilot%') AND coalesce(m.content_attributes::text, '') NOT LIKE '%deleted%true%' AND m.created_at >= ab.t - interval '2 minutes') AS t1_ia
    FROM ab JOIN conv ON conv.id = ab.cid JOIN inboxes i ON i.id = conv.inbox_id
),
c AS (  -- só clientes (N+R), com a espera em minutos e as marcas de prazo
    SELECT inbox_id, caixa, canal, periodo, tb,
      extract(hour from tb)::int AS ha,
      CASE WHEN t1 IS NULL THEN NULL WHEN t1::date <> t::date THEN 99 ELSE extract(hour from (t1 AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo'))::int END AS hc,
      CASE WHEN t1 IS NULL THEN NULL ELSE greatest(0, extract(epoch from (t1 - t)) / 60.0) END AS w,
      CASE WHEN t1_ia IS NULL THEN NULL ELSE greatest(0, extract(epoch from (t1_ia - t)) / 60.0) END AS w_ia,
      (t1_ia IS NOT NULL) AS tocou_ia,
      (t1_ia IS NOT NULL AND (t1 IS NULL OR t1_ia < t1)) AS robo_antes,
      (t <= (now() AT TIME ZONE 'UTC') - interval '1 hour') AS mad1,
      (t <= (now() AT TIME ZONE 'UTC') - interval '2 hours') AS mad2,
      (t <= (now() AT TIME ZONE 'UTC') - interval '24 hours') AS mad24
    FROM cli WHERE tipo IN ('N', 'R')
)
-- 1) por CANAL (+ Geral) — cards, tabela e metas
SELECT 'canal' AS bloco, periodo, coalesce(canal, 'Geral') AS setor, NULL::text AS k,
  count(*)::numeric AS n,
  count(*) FILTER (WHERE mad1)::numeric AS v1,
  count(*) FILTER (WHERE mad1 AND w <= 60)::numeric AS v2,
  count(*) FILTER (WHERE mad24)::numeric AS v3,
  count(*) FILTER (WHERE mad24 AND w <= 1440)::numeric AS v4,
  count(w)::numeric AS v5,
  count(*) FILTER (WHERE w IS NULL)::numeric AS v6,
  round((percentile_cont(0.5) WITHIN GROUP (ORDER BY w))::numeric, 0) AS v7,
  round((percentile_cont(0.9) WITHIN GROUP (ORDER BY w))::numeric, 0) AS v8,
  count(*) FILTER (WHERE mad2)::numeric AS v9,
  count(*) FILTER (WHERE mad2 AND w <= 120)::numeric AS v10
FROM c GROUP BY GROUPING SETS ((periodo, canal), (periodo))
UNION ALL
-- 1b) ROBÔ/IA: 1º contato do robô/IA (FLAGADO — não é atendimento humano; só pra ficarmos cientes)
SELECT 'robo' AS bloco, periodo, coalesce(canal, 'Geral') AS setor, NULL::text AS k,
  count(*)::numeric AS n,
  count(*) FILTER (WHERE tocou_ia)::numeric AS v1,
  count(*) FILTER (WHERE robo_antes)::numeric AS v2,
  round((percentile_cont(0.5) WITHIN GROUP (ORDER BY w_ia))::numeric, 0) AS v3,
  NULL::numeric AS v4, NULL::numeric AS v5, NULL::numeric AS v6, NULL::numeric AS v7, NULL::numeric AS v8, NULL::numeric AS v9, NULL::numeric AS v10
FROM c GROUP BY GROUPING SETS ((periodo, canal), (periodo))
UNION ALL
-- 1c) COMPOSIÇÃO (27/10/2026): de onde veio cada abertura, ANTES do filtro de clientes —
-- N = caso novo (o cliente abriu) · R = retorno do cliente (reabriu escrevendo) · S = follow-up nosso (reabrimos sem msg dele) · F = aberta por nós.
-- Clientes = N + R (é o que o resto do SLA conta); S e F ficam de fora da espera, mas aqui aparecem para dar o contexto.
SELECT 'tipos' AS bloco, periodo, coalesce(canal, 'Geral') AS setor, NULL::text AS k,
  count(*)::numeric AS n,
  count(*) FILTER (WHERE tipo = 'N')::numeric AS v1,
  count(*) FILTER (WHERE tipo = 'R')::numeric AS v2,
  count(*) FILTER (WHERE tipo = 'S')::numeric AS v3,
  count(*) FILTER (WHERE tipo = 'F')::numeric AS v4,
  NULL::numeric AS v5, NULL::numeric AS v6, NULL::numeric AS v7, NULL::numeric AS v8, NULL::numeric AS v9, NULL::numeric AS v10
FROM cli GROUP BY GROUPING SETS ((periodo, canal), (periodo))
UNION ALL
-- 2) por CAIXA (setor = nome da caixa, k = canal)
SELECT 'caixa', periodo, caixa, canal, count(*)::numeric,
  count(*) FILTER (WHERE mad1), count(*) FILTER (WHERE mad1 AND w <= 60),
  count(*) FILTER (WHERE mad24), count(*) FILTER (WHERE mad24 AND w <= 1440),
  count(w), count(*) FILTER (WHERE w IS NULL),
  round((percentile_cont(0.5) WITHIN GROUP (ORDER BY w))::numeric, 0),
  round((percentile_cont(0.9) WITHIN GROUP (ORDER BY w))::numeric, 0),
  count(*) FILTER (WHERE mad2), count(*) FILTER (WHERE mad2 AND w <= 120)
FROM c GROUP BY periodo, caixa, canal
UNION ALL
-- 3) por PERÍODO DO DIA (7-8 · 9-15 · 16-19 · 20-23 · 0-6) — por canal e Geral
SELECT 'periododia', periodo, coalesce(canal, 'Geral'), faixa,
  count(*)::numeric, count(*) FILTER (WHERE mad1), count(*) FILTER (WHERE mad1 AND w <= 60),
  count(*) FILTER (WHERE mad24), count(*) FILTER (WHERE mad24 AND w <= 1440),
  count(w), count(*) FILTER (WHERE w IS NULL), NULL, NULL, count(*) FILTER (WHERE mad2), count(*) FILTER (WHERE mad2 AND w <= 120)
FROM (SELECT periodo, canal, mad1, mad2, mad24, w,
        CASE WHEN ha BETWEEN 7 AND 8 THEN '1 07h-08h' WHEN ha BETWEEN 9 AND 15 THEN '2 09h-15h' WHEN ha BETWEEN 16 AND 19 THEN '3 16h-19h' WHEN ha BETWEEN 20 AND 23 THEN '4 20h-23h' ELSE '5 00h-06h' END AS faixa
      FROM c) pc
GROUP BY GROUPING SETS ((periodo, canal, faixa), (periodo, faixa))
UNION ALL
-- 4) por HORA DE CHEGADA (0-23), período atual, por canal e Geral — faixa de % em até 1h
SELECT 'horachegada', 'atual', coalesce(canal, 'Geral'), lpad(ha::text, 2, '0'),
  count(*)::numeric, count(*) FILTER (WHERE mad1), count(*) FILTER (WHERE mad1 AND w <= 60),
  count(*) FILTER (WHERE mad24), count(*) FILTER (WHERE mad24 AND w <= 1440),
  count(w), count(*) FILTER (WHERE w IS NULL), NULL, NULL, count(*) FILTER (WHERE mad2), count(*) FILTER (WHERE mad2 AND w <= 120)
FROM c WHERE periodo = 'atual' GROUP BY GROUPING SETS ((canal, ha), (ha))
UNION ALL
-- 5) ESPERANDO POR HORA (matriz hora-da-abertura × hora-do-1º-contato), período atual, por canal e Geral.
--    hc: hora do contato no MESMO dia (0-23) · 99 = contato só no dia seguinte · NULL(k ...|-1) = nunca teve contato. O Node faz a foto por hora.
SELECT 'esperando', 'atual', coalesce(canal, 'Geral'), ha::text || '|' || coalesce(hc, -1)::text,
  count(*)::numeric, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
FROM c WHERE periodo = 'atual' GROUP BY GROUPING SETS ((canal, ha, hc), (ha, hc))
UNION ALL
-- 6) por DIA (atual, Geral) — para o Excel
SELECT 'dia', 'atual', 'Geral', to_char(tb, 'YYYY-MM-DD'),
  count(*)::numeric, count(*) FILTER (WHERE mad1), count(*) FILTER (WHERE mad1 AND w <= 60),
  count(*) FILTER (WHERE mad24), count(*) FILTER (WHERE mad24 AND w <= 1440),
  count(w), count(*) FILTER (WHERE w IS NULL), NULL, NULL, count(*) FILTER (WHERE mad2), count(*) FILTER (WHERE mad2 AND w <= 120)
FROM c WHERE periodo = 'atual' GROUP BY to_char(tb, 'YYYY-MM-DD')
UNION ALL
-- 7) AGORA: casos abertos com o cliente esperando, por time e agente (independe do período)
SELECT 'agora', 'agora', ag.setor, coalesce(u.name, '(sem agente)'), count(*)::numeric,
  count(*) FILTER (WHERE ag.espera <= interval '24 hours'),
  count(*) FILTER (WHERE ag.espera > interval '24 hours' AND ag.espera <= interval '48 hours'),
  count(*) FILTER (WHERE ag.espera > interval '48 hours'),
  NULL, NULL, NULL, NULL, NULL, NULL, NULL
FROM (
  SELECT c2.assignee_id,
    CASE WHEN COALESCE(c2.cached_label_list,'') ILIKE '%time-48h%' OR COALESCE(c2.cached_label_list,'') ILIKE '%painel-do-pedido%' THEN '48H'
      WHEN i.name = '[GEX] SMS Support' THEN 'SMS' WHEN t.name ILIKE '%reten%' THEN 'RET' WHEN t.name ILIKE '%sac%' THEN 'SAC'
      WHEN t.name ILIKE '%back office%' OR t.name ILIKE '%backoffice%' OR t.name ILIKE '%bko%' THEN 'BKO'
      WHEN t.name ILIKE '%sms%' THEN 'SMS' ELSE 'OUTROS' END AS setor,
    lm.message_type AS ult_tipo, (now() AT TIME ZONE 'UTC') - lm.created_at AS espera
  FROM conversations c2
  LEFT JOIN teams t ON t.id = c2.team_id LEFT JOIN inboxes i ON i.id = c2.inbox_id
  LEFT JOIN LATERAL (SELECT m.message_type, m.created_at FROM messages m
     WHERE m.conversation_id = c2.id AND m.private = FALSE AND m.message_type IN (0, 1)
       AND (m.message_type = 0 OR (m.sender_type = 'User' AND m.sender_id IS NOT NULL AND m.sender_id <> 2))
     ORDER BY m.created_at DESC LIMIT 1) lm ON TRUE
  WHERE c2.account_id = 1 AND c2.status = 0
    AND COALESCE(c2.cached_label_list, '') NOT ILIKE '%duplicado%'
    AND (i.name IS NULL OR i.name NOT IN ('Atendimento | Brasil', 'Pitaco Teste'))
) ag LEFT JOIN users u ON u.id = ag.assignee_id
WHERE ag.ult_tipo = 0
GROUP BY ag.setor, u.name
UNION ALL
-- 8) FILA ABERTA em 3 (como o Cockpit): nunca respondida / cliente esperando / follow-up nosso
SELECT 'fila', 'agora', fa.setor, NULL::text, count(*)::numeric,
  count(*) FILTER (WHERE NOT fa.tem_resp)::numeric,
  count(*) FILTER (WHERE fa.tem_resp AND fa.ult = 0)::numeric,
  count(*) FILTER (WHERE fa.ult = 1)::numeric,
  NULL, NULL, NULL, NULL, NULL, NULL, NULL
FROM (
  SELECT
    CASE WHEN COALESCE(c2.cached_label_list,'') ILIKE '%time-48h%' OR COALESCE(c2.cached_label_list,'') ILIKE '%painel-do-pedido%' THEN '48H'
      WHEN i.name = '[GEX] SMS Support' THEN 'SMS' WHEN t.name ILIKE '%reten%' THEN 'RET' WHEN t.name ILIKE '%sac%' THEN 'SAC'
      WHEN t.name ILIKE '%back office%' OR t.name ILIKE '%backoffice%' OR t.name ILIKE '%bko%' THEN 'BKO'
      WHEN t.name ILIKE '%sms%' THEN 'SMS' ELSE 'OUTROS' END AS setor,
    lm.message_type AS ult,
    EXISTS (SELECT 1 FROM messages mr WHERE mr.conversation_id = c2.id AND mr.private = FALSE AND mr.message_type = 1 AND mr.sender_type = 'User' AND mr.sender_id <> 2) AS tem_resp
  FROM conversations c2
  LEFT JOIN teams t ON t.id = c2.team_id LEFT JOIN inboxes i ON i.id = c2.inbox_id
  LEFT JOIN LATERAL (SELECT m.message_type FROM messages m
     WHERE m.conversation_id = c2.id AND m.private = FALSE AND m.message_type IN (0, 1)
       AND (m.message_type = 0 OR (m.sender_type = 'User' AND m.sender_id IS NOT NULL AND m.sender_id <> 2))
     ORDER BY m.created_at DESC LIMIT 1) lm ON TRUE
  WHERE c2.account_id = 1 AND c2.status = 0
    AND COALESCE(c2.cached_label_list, '') NOT ILIKE '%duplicado%'
    AND (i.name IS NULL OR i.name NOT IN ('Atendimento | Brasil', 'Pitaco Teste'))
) fa
GROUP BY fa.setor
`;
app.get('/api/recebimento-sla', async (req, res) => {
    if (!ehAdminReq(req)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
    try {
        let ini, fim;
        if (req.query.since && req.query.until) {
            ini = unixParaYYYYMMDD(req.query.since);
            fim = unixParaYYYYMMDD(req.query.until);
        } else {   // padrão: do dia 1º do mês até hoje (igual ao Recebimento)
            const agora = new Date(new Date().toLocaleString("en-US", { timeZone: "America/Sao_Paulo" }));
            ini = formatarDataSQL(new Date(agora.getFullYear(), agora.getMonth(), 1));
            fim = formatarDataSQL(agora);
        }
        const DIA_MS = 86400000, ymd = d => d.toISOString().slice(0, 10);
        const dIni = new Date(ini + 'T00:00:00Z'), dFim = new Date(fim + 'T00:00:00Z');
        const dias = Math.round((dFim - dIni) / DIA_MS) + 1;
        if (!(dias >= 1)) return res.status(400).json({ success: false, error: 'Período inválido.' });
        if (dias > SLA_MAX_DIAS) return res.status(400).json({ success: false, error: `Período máximo de ${SLA_MAX_DIAS} dias (o escolhido tem ${dias}).` });
        const comparar = dias <= SLA_MAX_DIAS_COMPARACAO;
        const antIni = new Date(dIni.getTime() - dias * DIA_MS), antFim = new Date(dIni.getTime() - DIA_MS);
        const t0 = Date.now();
        const { rows } = await pool.query(SLA_SQL, [ini, comparar ? ymd(antIni) : ini, ymd(new Date(dFim.getTime() + DIA_MS))]);
        const ms = Date.now() - t0;
        console.log(`⏱️ SLA do Recebimento ${ini} a ${fim}${comparar ? ' (+ período anterior)' : ''}: ${rows.length} linhas em ${ms} ms`);
        const num = (v) => (v === null || v === undefined) ? null : Number(v);
        res.json({
            success: true,
            periodo: { inicio: ini, fim: fim, dias: dias },
            anterior: comparar ? { inicio: ymd(antIni), fim: ymd(antFim), dias: dias } : null,
            comparacao: comparar, max_dias: SLA_MAX_DIAS, max_dias_comparacao: SLA_MAX_DIAS_COMPARACAO,
            gerado_em: new Date().toISOString(), ms: ms,
            linhas: rows.map(r => ({ bloco: r.bloco, periodo: r.periodo, setor: r.setor, k: r.k, n: num(r.n), v1: num(r.v1), v2: num(r.v2), v3: num(r.v3), v4: num(r.v4), v5: num(r.v5), v6: num(r.v6), v7: num(r.v7), v8: num(r.v8), v9: num(r.v9), v10: num(r.v10) }))
        });
    } catch (error) {
        console.error("Erro SLA do Recebimento:", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==========================================
// 15.5C 👥 AGENTES do Recebimento (17/10/2026) — produção por HORÁRIO, por MENSAGENS ENVIADAS · SOMENTE ADMIN
// Liderança fora (LIDERANCA_IDS e " - LD" no nome). Ticket atendido = conversa distinta com >= 1 mensagem do agente na hora.
// Uma consulta por carga; período máximo 31 dias, compara com o anterior do mesmo tamanho. Só leitura.
// ==========================================
const AG_MAX_DIAS = 31, AG_MAX_DIAS_COMPARACAO = 31;
const AGENTES_SQL = `-- 👥 AGENTES do Recebimento (17/10/2026) — produção por HORÁRIO, contando MENSAGENS ENVIADAS. Uma consulta por carga, só leitura.
-- Mensagem = message_type 1, pública, sender_type 'User', sender_id <> 2, não apagada, content não nulo; caixa fora de Atendimento | Brasil e Pitaco Teste.
-- Liderança fora: LIDERANCA_IDS (9,22,37,51,54) e quem tem " - LD" no nome. Ticket atendido = conversa distinta em que o agente mandou >= 1 mensagem.
-- $1 = início do período (split atual/anterior) · $2 = início da leitura (período anterior; = $1 sem comparação) · $3 = dia seguinte ao fim.
-- Saída: uma linha por (periodo, agente, dia, hora) + o rollup (periodo, agente, dia) com hora NULL (tickets/dia distintos). O Node faz as médias.
WITH msgs AS (
    SELECT m.sender_id, m.conversation_id,
      (m.created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo') AS tb
    FROM messages m
    LEFT JOIN inboxes i ON i.id = m.inbox_id
    WHERE m.account_id = 1 AND m.message_type = 1 AND m.private = FALSE AND m.sender_type = 'User'
      AND m.sender_id IS NOT NULL
      AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE
      AND m.content IS NOT NULL
      AND (i.name IS NULL OR i.name NOT IN ('Atendimento | Brasil', 'Pitaco Teste'))
      AND m.created_at >= ($2 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
      AND m.created_at <  ($3 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
),
base AS (
    SELECT ms.sender_id, u.name, u.created_at,
      CASE WHEN ms.tb >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo' THEN 'atual' ELSE 'anterior' END AS periodo,
      TO_CHAR(ms.tb, 'YYYY-MM-DD') AS dia, extract(hour from ms.tb)::int AS hora, ms.conversation_id,
      (ms.sender_id = 2 OR u.name ILIKE '%sarah williams%' OR u.name ILIKE '%copilot%') AS ia
    FROM msgs ms JOIN users u ON u.id = ms.sender_id
    WHERE u.id NOT IN (9, 22, 37, 51, 54) AND u.name NOT ILIKE '% - LD%'
)
SELECT periodo, sender_id, name, created_at,
  dia, hora,
  count(*)::int AS msgs,
  count(DISTINCT conversation_id)::int AS convs,
  bool_or(ia) AS ia
FROM base
GROUP BY GROUPING SETS ((periodo, sender_id, name, created_at, dia, hora), (periodo, sender_id, name, created_at, dia))`;
app.get('/api/recebimento-agentes', async (req, res) => {
    if (!ehAdminReq(req)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
    try {
        let ini, fim;
        if (req.query.since && req.query.until) {
            ini = unixParaYYYYMMDD(req.query.since);
            fim = unixParaYYYYMMDD(req.query.until);
        } else {
            const agora = new Date(new Date().toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' }));
            ini = formatarDataSQL(new Date(agora.getFullYear(), agora.getMonth(), 1));
            fim = formatarDataSQL(agora);
        }
        const DIA_MS = 86400000, ymd = d => d.toISOString().slice(0, 10);
        const dIni = new Date(ini + 'T00:00:00Z'), dFim = new Date(fim + 'T00:00:00Z');
        const dias = Math.round((dFim - dIni) / DIA_MS) + 1;
        if (!(dias >= 1)) return res.status(400).json({ success: false, error: 'Período inválido.' });
        if (dias > AG_MAX_DIAS) return res.status(400).json({ success: false, error: `Período máximo de ${AG_MAX_DIAS} dias (o escolhido tem ${dias}).` });
        const comparar = dias <= AG_MAX_DIAS_COMPARACAO;
        const antIni = new Date(dIni.getTime() - dias * DIA_MS), antFim = new Date(dIni.getTime() - DIA_MS);
        const t0 = Date.now();
        const { rows } = await pool.query(AGENTES_SQL, [ini, comparar ? ymd(antIni) : ini, ymd(new Date(dFim.getTime() + DIA_MS))]);
        const ms = Date.now() - t0;
        console.log(`👥 Agentes do Recebimento ${ini} a ${fim}: ${rows.length} linhas em ${ms} ms`);
        res.json({
            success: true,
            periodo: { inicio: ini, fim: fim, dias: dias },
            anterior: comparar ? { inicio: ymd(antIni), fim: ymd(antFim), dias: dias } : null,
            comparacao: comparar, max_dias: AG_MAX_DIAS, max_dias_comparacao: AG_MAX_DIAS_COMPARACAO,
            gerado_em: new Date().toISOString(), ms: ms,
            linhas: rows.map(r => ({ periodo: r.periodo, id: r.sender_id, nome: r.name, criado_em: r.created_at, dia: r.dia, hora: r.hora === null ? null : Number(r.hora), msgs: Number(r.msgs), convs: Number(r.convs), ia: !!r.ia }))
        });
    } catch (error) {
        console.error('Erro Agentes do Recebimento:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==========================================
// 15.5B 📥 RECEBIMENTO — ABERTURAS (17/10/2026) — base reutilizável (Tarefa 1 tela · Tarefa 2 SLA · Tarefa 3 Agentes) · SOMENTE ADMIN
// Abertura = o momento em que a conversa passa a esperar atendimento: criação, reabertura pelo cliente (automação) ou conversation_opened.
// Eventos da mesma conversa a < 2 min contam como 1 abertura. Tipo: N (novo pelo cliente) · R (retorno/reabertura do cliente) · F (à parte: aberta/reaberta por nós).
// N + R = CLIENTES (o que conta). w = 1º contato humano − abertura (robô sender_id 2 não conta); guardado em faixas de minutos para a Tarefa 2.
// Escopo CS de produtos: todas as caixas da conta 1 menos "Atendimento | Brasil" e "Pitaco Teste"; fora: etiqueta duplicado/spam/compra_teste e os contatos automáticos.
// Cache próprio por período (10 min quando inclui hoje · 60 min fechado) para o SLA e o Agentes não repetirem a consulta. SÓ LEITURA no banco.
// ==========================================
const CONTATOS_AUTOMATICOS = [279944, 244572, 9950, 272736, 244905, 4133, 271799];   // contatos que não são cliente real (automação) — ficam fora
const LIDERANCA_IDS = [9, 22, 37, 51, 54];   // liderança não conta como agente (além de quem tem " - LD" no nome) — a Tarefa 3 (Agentes) usa
const AB_MAX_DIAS = 62, AB_MAX_DIAS_COMPARACAO = 31;   // teto do período; compara com o período anterior só até 31 dias
const AB_SQL = `WITH conv AS (
    SELECT c.id, c.inbox_id
    FROM conversations c
    JOIN inboxes i ON i.id = c.inbox_id
    WHERE c.account_id = 1
      AND i.name NOT IN ('Atendimento | Brasil', 'Pitaco Teste')
      AND COALESCE(c.cached_label_list, '') NOT ILIKE '%duplicado%'
      AND COALESCE(c.cached_label_list, '') NOT ILIKE '%spam%'
      AND COALESCE(c.cached_label_list, '') NOT ILIKE '%compra_teste%'
      AND c.contact_id NOT IN (${CONTATOS_AUTOMATICOS.join(', ')})
      AND c.last_activity_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
),
ev AS (
    SELECT c.id AS cid, c.created_at AS t, 1 AS pri, 'criacao' AS src
    FROM conversations c
    WHERE c.account_id = 1
      AND c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
      AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
    UNION ALL
    SELECT m.conversation_id, m.created_at, 2,
           CASE WHEN m.content ILIKE '%Sarah Williams%' OR m.content ILIKE 'O sistema reabriu%' THEN 'reab_cli' ELSE 'reab_ag' END
    FROM messages m
    WHERE m.account_id = 1 AND m.message_type = 2
      AND (m.content ILIKE 'Conversa foi reaberta%' OR m.content ILIKE 'O sistema reabriu%' OR m.content ILIKE 'Conversation was reopened%')
      AND m.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
      AND m.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
    UNION ALL
    SELECT re.conversation_id, re.created_at, 3, 'evt'
    FROM reporting_events re
    WHERE re.account_id = 1 AND re.name = 'conversation_opened'
      AND re.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
      AND re.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
),
ev2 AS (
    SELECT ev.*, lag(t) OVER (PARTITION BY cid ORDER BY t, pri) AS tprev
    FROM ev WHERE cid IN (SELECT id FROM conv)
),
grp AS (
    SELECT *, sum(CASE WHEN tprev IS NULL OR t - tprev > interval '2 minutes' THEN 1 ELSE 0 END) OVER (PARTITION BY cid ORDER BY t, pri) AS g
    FROM ev2
),
ab AS (
    SELECT cid, g, min(t) AS t, bool_or(src = 'criacao') AS criacao, bool_or(src = 'reab_cli') AS rcli, bool_or(src = 'reab_ag') AS rag
    FROM grp GROUP BY cid, g
),
cl AS (
    SELECT ab.cid, conv.inbox_id, ab.t,
       (ab.t AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo') AS tb,
       CASE
         WHEN ab.criacao THEN CASE WHEN (SELECT m.message_type FROM messages m WHERE m.conversation_id = ab.cid AND m.private = false AND m.message_type IN (0, 1, 3) ORDER BY m.created_at, m.id LIMIT 1) = 0 THEN 'N' ELSE 'F' END
         WHEN EXISTS (SELECT 1 FROM messages x WHERE x.conversation_id = ab.cid AND x.message_type = 0 AND x.created_at BETWEEN ab.t - interval '2 minutes' AND ab.t + interval '2 minutes') THEN 'R'
         ELSE 'S'
       END AS tipo,
       (SELECT CASE WHEN min(m.created_at) IS NULL THEN NULL ELSE GREATEST(0, EXTRACT(EPOCH FROM (min(m.created_at) - ab.t))) END
          FROM messages m WHERE m.conversation_id = ab.cid AND m.message_type = 1 AND m.private = false AND m.sender_type = 'User' AND m.sender_id <> 2 AND m.created_at >= ab.t - interval '2 minutes') AS w_seg
    FROM ab JOIN conv ON conv.id = ab.cid
)
SELECT
    TO_CHAR(cl.tb, 'YYYY-MM-DD') AS dia,
    cl.inbox_id,
    i.name AS caixa,
    CASE WHEN i.channel_type = 'Channel::Email' THEN 'E-mail'
         WHEN i.name = '[GEX] SMS Support' THEN 'SMS'
         WHEN i.channel_type = 'Channel::WebWidget' THEN 'Chat web'
         ELSE 'Outros' END AS canal,
    EXTRACT(HOUR FROM cl.tb)::int AS hora,
    cl.tipo,
    COUNT(*)::int AS aberturas,
    COUNT(DISTINCT cl.cid)::int AS conversas,
    COUNT(cl.w_seg)::int AS com_contato,
    COUNT(*) FILTER (WHERE cl.w_seg IS NULL)::int AS sem_contato,
    COALESCE(SUM(cl.w_seg), 0)::bigint AS w_soma_seg,
    COUNT(*) FILTER (WHERE cl.w_seg <= 300)::int AS w_ate5,
    COUNT(*) FILTER (WHERE cl.w_seg > 300 AND cl.w_seg <= 900)::int AS w_5_15,
    COUNT(*) FILTER (WHERE cl.w_seg > 900 AND cl.w_seg <= 1800)::int AS w_15_30,
    COUNT(*) FILTER (WHERE cl.w_seg > 1800 AND cl.w_seg <= 3600)::int AS w_30_60,
    COUNT(*) FILTER (WHERE cl.w_seg > 3600 AND cl.w_seg <= 14400)::int AS w_1_4h,
    COUNT(*) FILTER (WHERE cl.w_seg > 14400 AND cl.w_seg <= 86400)::int AS w_4_24h,
    COUNT(*) FILTER (WHERE cl.w_seg > 86400)::int AS w_24h_mais
FROM cl JOIN inboxes i ON i.id = cl.inbox_id
GROUP BY 1, 2, 3, 4, 5, 6`;
const abCache = new Map();   // cache próprio do helper: chave "ini|fim" → { t, dados }
// Base das aberturas agregada por dia × caixa × hora × tipo (+ faixas de w para o SLA). Guarda em cache por período.
async function abAberturas(ini, fim, forcar) {
    const chave = ini + '|' + fim;
    const hojeBR = formatarDataSQL(new Date(new Date().toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' })));
    const ttl = (fim >= hojeBR ? 10 : 60) * 60 * 1000;   // período que inclui hoje muda sozinho → 10 min; período fechado → 60 min
    const guardado = abCache.get(chave);
    if (!forcar && guardado && Date.now() - guardado.t < ttl) return guardado.dados;
    const t0 = Date.now();
    const { rows } = await pool.query(AB_SQL, [ini, fim]);
    const num = (v) => (v === null || v === undefined) ? 0 : Number(v);
    const dados = rows.map(r => ({
        dia: r.dia, inbox_id: num(r.inbox_id), caixa: r.caixa, canal: r.canal, hora: num(r.hora), tipo: r.tipo,
        aberturas: num(r.aberturas), conversas: num(r.conversas), com_contato: num(r.com_contato), sem_contato: num(r.sem_contato),
        w_soma_seg: num(r.w_soma_seg),
        w: [num(r.w_ate5), num(r.w_5_15), num(r.w_15_30), num(r.w_30_60), num(r.w_1_4h), num(r.w_4_24h), num(r.w_24h_mais)]   // ≤5min · 5–15 · 15–30 · 30–60 · 1–4h · 4–24h · >24h (para a Tarefa 2)
    }));
    abCache.set(chave, { t: Date.now(), dados });
    if (abCache.size > 40) for (const [k, v] of abCache) if (Date.now() - v.t > 60 * 60 * 1000) abCache.delete(k);   // trava simples: limpa os velhos
    console.log(`📥 abAberturas ${ini}..${fim}: ${rows.length} linhas em ${Date.now() - t0} ms`);
    return dados;
}
// Rota da Tarefa 1: período atual + período anterior do mesmo tamanho (até 31 dias). O cacheMiddleware guarda a resposta 30 min; fresh=1 (🔄 Atualizar) fura os dois caches.
app.get('/api/recebimento-aberturas', async (req, res) => {
    if (!ehAdminReq(req)) return res.status(403).json({ success: false, error: 'Acesso restrito para Administradores.' });
    try {
        let ini, fim;
        if (req.query.since && req.query.until) {
            ini = unixParaYYYYMMDD(req.query.since);
            fim = unixParaYYYYMMDD(req.query.until);
        } else {   // padrão: do dia 1º do mês até hoje
            const agora = new Date(new Date().toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' }));
            ini = formatarDataSQL(new Date(agora.getFullYear(), agora.getMonth(), 1));
            fim = formatarDataSQL(agora);
        }
        const DIA_MS = 86400000, ymd = d => d.toISOString().slice(0, 10);
        const dIni = new Date(ini + 'T00:00:00Z'), dFim = new Date(fim + 'T00:00:00Z');
        const dias = Math.round((dFim - dIni) / DIA_MS) + 1;
        if (!(dias >= 1)) return res.status(400).json({ success: false, error: 'Período inválido.' });
        if (dias > AB_MAX_DIAS) return res.status(400).json({ success: false, error: `Período máximo de ${AB_MAX_DIAS} dias (o escolhido tem ${dias}).` });
        const comparar = dias <= AB_MAX_DIAS_COMPARACAO;
        const antIni = new Date(dIni.getTime() - dias * DIA_MS), antFim = new Date(dIni.getTime() - DIA_MS);
        const forcar = req.query.fresh === '1';   // 🔄 Atualizar: pede dado fresco também no cache do helper
        const t0 = Date.now();
        const atual = await abAberturas(ini, fim, forcar);
        const anterior = comparar ? await abAberturas(ymd(antIni), ymd(antFim), forcar) : null;
        res.json({
            success: true,
            periodo: { inicio: ini, fim: fim, dias: dias },
            anterior: comparar ? { inicio: ymd(antIni), fim: ymd(antFim), dias: dias } : null,
            comparacao: comparar, max_dias: AB_MAX_DIAS, max_dias_comparacao: AB_MAX_DIAS_COMPARACAO,
            gerado_em: new Date().toISOString(), ms: Date.now() - t0,
            linhas: atual, linhas_anterior: anterior
        });
    } catch (error) {
        console.error('Erro Recebimento aberturas:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});


// ==========================================
// 15.6 🤖 PERGUNTE AO DASH (14/10/2026) — Fase 1 · SOMENTE ADMIN
// O gestor pergunta em português. O Claude (API da Anthropic) só ESCOLHE uma consulta pronta deste catálogo e escreve
// a leitura do resultado: quem calcula é o banco (só leitura, consultas fixas daqui) ou as próprias rotas do Dash
// (mesmos números das telas, aproveitando o cache de 30 min). Para a API vão só totais e nomes de caixa e de time;
// nome de agente vai como "Agente N" e volta trocado na resposta. Nenhum dado de cliente sai do Dash.
// Catálogo: recebimento · etiquetas 48H/Painel · TMC/TMR justos por agente · espera do cliente (só quando perguntarem)
// Precisa da variável ANTHROPIC_API_KEY (sem ela a tela avisa e nada mais muda). Abrir um gráfico fixado não usa a API.
// Responde com "ok" (e não "success") de propósito: o cache do Dash não guarda resposta de pergunta.
// ==========================================
const PD_MODELO = 'claude-haiku-5-5';   // 14/10/2026: o Sonnet 5.5 recusa tool_choice "any"/"tool" (erro 400) e o robô usa os dois; o Haiku 5.5 aceita e, com a ferramenta forçada, responde direto pela ferramenta
const PD_API_URL = 'https://api.anthropic.com/v1/messages';
const PD_LIMITE_HORA = 40;   // perguntas por admin por hora (só as que usam a API)
const PD_MAX_DIAS = { recebimento: 92, etiquetas_48h_painel: 92, tmc_tmr_agentes: 62, espera_cliente: 31 };
const PD_TIMES = ['RET', 'SAC', 'BKO', 'SMS', '48H', 'OUTROS'];
const PD_NOME_TIME = { TODOS: 'Todos', RET: 'Retenção', SAC: 'SAC', BKO: 'BackOffice', SMS: 'SMS', '48H': '48H', OUTROS: 'Sem time' };
const PD_DIAS = ['domingo', 'segunda', 'terça', 'quarta', 'quinta', 'sexta', 'sábado'];
const PD_COR = { a: '#22a7f0', b: '#fb923c', azul: '#1b52af', cinza: '#64748b' };
const pdUso = {}, pdRodando = {}, pdCache = {};

const pdD = (s) => new Date(s + 'T00:00:00Z');
const pdS = (d) => d.toISOString().slice(0, 10);
const pdSoma = (s, n) => pdS(new Date(pdD(s).getTime() + n * 86400000));
const pdBR = (s) => `${s.slice(8, 10)}/${s.slice(5, 7)}/${s.slice(0, 4)}`;
const pdUnix = (s, fim) => Date.UTC(+s.slice(0, 4), +s.slice(5, 7) - 1, +s.slice(8, 10), 3) / 1000 + (fim ? 86399 : 0);   // dia de Brasília → unix, igual ao calendário das telas
const pdDataOk = (s) => (/^\d{4}-\d{2}-\d{2}$/.test(String(s || '')) && !isNaN(pdD(String(s)).getTime())) ? String(s) : null;
const pdHoje = () => formatarDataSQL(new Date(new Date().toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' })));
const pdDias = (ini, fim) => Math.round((pdD(fim) - pdD(ini)) / 86400000) + 1;
const pdPeriodoTxt = (per) => per.ini === per.fim ? `${pdBR(per.ini)} (${PD_DIAS[pdD(per.ini).getUTCDay()]})` : `${pdBR(per.ini).slice(0, 5)} a ${pdBR(per.fim)}`;
const pdNum = (v, casas) => (Number(v) || 0).toLocaleString('pt-BR', { minimumFractionDigits: casas || 0, maximumFractionDigits: casas || 0 });
const pdPct = (v) => (v > 0 ? '+' : '') + pdNum(v, 1) + '%';
const pdPl = (n, um, varios) => `${pdNum(n)} ${Number(n) === 1 ? um : varios}`;
const pdMin = (seg) => (seg === null || seg === undefined || !isFinite(seg)) ? null : Math.round(Number(seg) / 6) / 10;   // segundos → minutos (1 casa)
function pdTempo(min) {
    if (min === null || min === undefined || !isFinite(min)) return '—';
    if (min < 1) return Math.round(min * 60) + 's';
    if (min < 60) return Math.round(min) + ' min';
    const h = Math.floor(min / 60), m = Math.round(min % 60);
    return h < 24 ? `${h}h ${String(m).padStart(2, '0')}m` : `${Math.floor(h / 24)}d ${h % 24}h`;
}

// período pedido → datas de Brasília (prefere os relativos: o gráfico fixado se atualiza sozinho)
function pdPeriodo(p, hoje, maxDias) {
    const ontem = pdSoma(hoje, -1), dow = pdD(hoje).getUTCDay(), segunda = pdSoma(hoje, -((dow + 6) % 7));
    const mesIni = hoje.slice(0, 8) + '01', mesPassFim = pdSoma(mesIni, -1);
    const P = {
        hoje: [hoje, hoje], ontem: [ontem, ontem], esta_semana: [segunda, hoje], semana_passada: [pdSoma(segunda, -7), pdSoma(segunda, -1)],
        este_mes: [mesIni, hoje], mes_passado: [mesPassFim.slice(0, 8) + '01', mesPassFim], ultimos_7_dias: [pdSoma(hoje, -7), ontem], ultimos_30_dias: [pdSoma(hoje, -30), ontem]
    };
    let tipo = String((p && p.periodo) || 'ultimos_7_dias'), ini, fim;
    if (tipo === 'personalizado' && pdDataOk(p.inicio)) { ini = pdDataOk(p.inicio); fim = pdDataOk(p.fim) || ini; }
    else { if (!P[tipo]) tipo = 'ultimos_7_dias'; [ini, fim] = P[tipo]; }
    if (fim > hoje) fim = hoje;
    if (ini > hoje) ini = hoje;
    if (ini > fim) [ini, fim] = [fim, ini];
    const avisos = [];
    let dias = pdDias(ini, fim);
    if (maxDias && dias > maxDias) { ini = pdSoma(fim, -(maxDias - 1)); dias = maxDias; avisos.push(`Período limitado aos últimos ${maxDias} dias para não pesar no banco.`); }
    return { ini, fim, dias, avisos };
}
function pdPeriodoComparar(p, per, hoje) {
    const c = String((p && p.comparar) || 'nao');
    let ini, fim;
    if (c === 'periodo_anterior') { fim = pdSoma(per.ini, -1); ini = pdSoma(fim, -(per.dias - 1)); }
    else if (c === 'semana_anterior') { ini = pdSoma(per.ini, -7); fim = pdSoma(per.fim, -7); }
    else if (c === 'personalizado' && pdDataOk(p.comparar_inicio)) {
        ini = pdDataOk(p.comparar_inicio); fim = pdDataOk(p.comparar_fim) || ini;
        if (fim > hoje) fim = hoje;
        if (ini > hoje) ini = hoje;
        if (ini > fim) [ini, fim] = [fim, ini];
    } else return null;
    const dias = pdDias(ini, fim);
    return dias > PD_MAX_DIAS.recebimento ? null : { ini, fim, dias };
}

// rotas do próprio Dash, SEM fresh=1: usa o cache de 30 min das telas (o tgGetInterno sempre busca de novo)
function pdGetInterno(caminho, timeoutMs) {
    return new Promise((resolve) => {
        const rq = http.get({ host: '127.0.0.1', port: PORT, path: caminho, headers: { 'x-warm-token': WARM_TOKEN } }, (r) => {
            let b = ''; r.setEncoding('utf8'); r.on('data', c => { b += c; });
            r.on('end', () => { try { resolve(JSON.parse(b)); } catch (e) { resolve(null); } });
        });
        rq.on('error', () => resolve(null));
        rq.setTimeout(timeoutMs || 150000, () => { try { rq.destroy(); } catch (e) {} resolve(null); });
    });
}
async function pdRota(caminho, avisos) {
    const j = await pdGetInterno(caminho, 150000);
    if (!j || !j.success) throw new Error((j && j.error) || 'a tela de origem não respondeu');
    if (j.dados_guardados && avisos) avisos.push(`O banco falhou agora: números guardados de ${j.dados_guardados_min} min atrás.`);
    return j;
}
// consultas próprias do robô: guardadas 10 min (período com hoje) ou 60 min (período fechado)
async function pdCacheado(chave, hoje, fim, fn) {
    const ttl = (fim >= hoje ? 10 : 60) * 60000, c = pdCache[chave];
    if (c && Date.now() - c.em < ttl) return c.dados;
    const dados = await fn();
    const ks = Object.keys(pdCache);
    if (ks.length >= 60) ks.forEach(k => { delete pdCache[k]; });
    pdCache[chave] = { em: Date.now(), dados };
    return dados;
}

// mesma regra do 📥 Recebimento (15.5): time da conversa e se ela conta ou fica à parte · $1/$2 = período (AAAA-MM-DD, Brasília)
const PD_SQL_BASE = `
    WITH Conv48 AS (
        SELECT tg.taggable_id AS conv_id, MIN(tg.created_at) AS etiquetada_em
        FROM taggings tg
        JOIN tags t2 ON t2.id = tg.tag_id
        WHERE tg.taggable_type = 'Conversation' AND (t2.name ILIKE '%time-48h%' OR t2.name ILIKE 'painel-do-pedido%')
        GROUP BY tg.taggable_id
    ),
    Rb AS (
        SELECT c.id AS conv_id, c.created_at, COALESCE(i.name, 'Sem caixa') AS caixa,
            (c.created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo') AS criado_br,
            CASE
                WHEN c48.etiquetada_em <= c.created_at + interval '10 minutes' THEN '48H'
                WHEN i.name = '[GEX] SMS Support' THEN 'SMS'
                WHEN t.name ILIKE '%reten%' THEN 'RET'
                WHEN t.name ILIKE '%sac%' THEN 'SAC'
                WHEN t.name ILIKE '%back office%' OR t.name ILIKE '%backoffice%' OR t.name ILIKE '%bko%' THEN 'BKO'
                WHEN t.name ILIKE '%sms%' THEN 'SMS'
                WHEN c48.conv_id IS NOT NULL THEN '48H'
                ELSE 'OUTROS'
            END AS setor,
            CASE
                WHEN COALESCE(c.cached_label_list, '') ILIKE '%duplicado%' THEN 'duplicado'
                WHEN pm.message_type IS NULL THEN 'sem_mensagem'
                WHEN pm.message_type IN (1, 3) THEN 'aberto_por_nos'
                ELSE 'valido'
            END AS tipo
        FROM conversations c
        LEFT JOIN teams t ON t.id = c.team_id
        LEFT JOIN inboxes i ON i.id = c.inbox_id
        LEFT JOIN Conv48 c48 ON c48.conv_id = c.id
        LEFT JOIN LATERAL (
            SELECT m.message_type FROM messages m
            WHERE m.conversation_id = c.id AND m.private = FALSE AND m.message_type IN (0, 1, 3)
            ORDER BY m.created_at, m.id LIMIT 1
        ) pm ON TRUE
        WHERE c.account_id = 1
          AND c.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
          AND c.created_at <= ($2 || ' 23:59:59')::timestamp AT TIME ZONE 'America/Sao_Paulo'
          AND (i.name IS NULL OR i.name NOT IN ('Atendimento | Brasil', 'Pitaco Teste'))
    )`;
const PD_REGRAS_REC = [
    'Conversas novas abertas pelo cliente (a 1ª mensagem pública é dele), no horário de Brasília',
    'Duplicadas (etiqueta "duplicado"), abertas por nós e sem mensagem ficam à parte',
    'Caixas Atendimento | Brasil e Pitaco Teste ficam fora',
    'Time pela regra da tela: etiqueta 48H/Painel colocada na chegada (até 10 min) → 48H · caixa de SMS → SMS · senão, o time do Chatwoot'
];

// ---------- 1) RECEBIMENTO ----------
// 14/10/2026: período com hoje (o dia ainda não acabou). Antes a % comparava o dia incompleto com dias inteiros e mostrava queda falsa
// (ex.: hoje às 10h × ontem inteiro = -60%). Agora: 1 dia × 1 dia compara só as horas já fechadas dos dois dias; com mais dias, a média dos dias completos;
// sem base justa (por caixa não há a hora de cada ticket aqui, ou ainda é 0h), fica sem a % e avisa.
function pdAjustarHoje(out, a, b, per, cmp, K, nomeB, avisos) {
    const kpi = out.kpis.find(x => x.rot === 'Comparação');
    if (!kpi) return;
    const h = parseInt(new Intl.DateTimeFormat('en-GB', { timeZone: 'America/Sao_Paulo', hour: '2-digit', hourCycle: 'h23' }).format(new Date()), 10) % 24;
    const ateHora = (r) => (r.por_hora || []).slice(0, h).reduce((s, x) => s + (x[K] || 0), 0);
    const mediaCompletos = (r) => { const ds = (r.por_dia || []).filter(d => !d.parcial); return ds.length ? ds.reduce((s, d) => s + (d[K] || 0), 0) / ds.length : null; };
    const umDia = !!(a && b && per.dias === 1 && cmp.dias === 1);
    let vr = null, base = '';
    if (umDia) { if (h > 0) { const sa = ateHora(a), sb = ateHora(b); vr = sb > 0 ? ((sa - sb) / sb) * 100 : null; base = `até as ${h}h`; } }
    else if (a && b) { const ma = mediaCompletos(a), mb = mediaCompletos(b); vr = (ma !== null && mb) ? ((ma - mb) / mb) * 100 : null; base = 'na média/dia dos dias completos'; }
    kpi.sub = nomeB + (vr === null ? ' · sem % (hoje ainda não acabou)' : ` · ${pdPct(vr)} ${base}`);
    out.destaques.variacao_media_dia_pct = vr === null ? null : Math.round(vr * 10) / 10;
    out.destaques.comparacao_base = vr === null ? 'sem comparação: hoje ainda não acabou' : base;
    avisos.push(vr === null ? 'Hoje ainda não acabou: a % da comparação ficou de fora para não mostrar queda falsa.'
        : (umDia ? `Hoje ainda não acabou: a % compara só as horas fechadas dos dois dias (0h às ${h}h).` : 'Hoje ainda não acabou: a % compara só a média dos dias completos.'));
}
async function pdExecRecebimento(p, hoje) {
    const per = pdPeriodo(p, hoje, PD_MAX_DIAS.recebimento), cmp = pdPeriodoComparar(p, per, hoje), avisos = per.avisos.slice();
    const ag = ['time', 'caixa', 'dia', 'hora', 'dia_da_semana'].includes(p.agrupar_por) ? p.agrupar_por : 'time';
    const time = PD_TIMES.includes(String(p.time || '').toUpperCase()) ? String(p.time).toUpperCase() : 'TODOS';
    const K = time === 'TODOS' ? 'total' : time;
    const regras = PD_REGRAS_REC.slice();
    if (time !== 'TODOS' && ag !== 'time') regras.push(`Só o time ${PD_NOME_TIME[time]}`);
    const nomeA = pdPeriodoTxt(per), nomeB = cmp ? pdPeriodoTxt(cmp) : '';
    const out = { fonte: 'Chatwoot · conversas novas', periodo_txt: nomeA + (cmp ? ` × ${nomeB}` : ''), regras, avisos, kpis: [], destaques: {}, nomes: {} };
    const variacao = (a, b, da, db) => { const ma = a / da, mb = b / db; return mb > 0 ? ((ma - mb) / mb) * 100 : null; };

    if (ag === 'caixa') {
        const sqlFinal = `
    SELECT caixa, tipo, COUNT(*)::int AS qtd
    FROM Rb
    WHERE ($3 = 'TODOS' OR setor = $3)
    GROUP BY 1, 2`;
        const buscar = (x) => pdCacheado(`rec-caixa|${x.ini}|${x.fim}|${time}`, hoje, x.fim, async () => (await pool.query(PD_SQL_BASE + sqlFinal, [x.ini, x.fim, time])).rows);
        const somar = (linhas) => { const C = {}; linhas.forEach(r => { const c = C[r.caixa] = C[r.caixa] || { v: 0, d: 0, n: 0 }; const q = parseInt(r.qtd) || 0; if (r.tipo === 'valido') c.v += q; else if (r.tipo === 'duplicado') c.d += q; else c.n += q; }); return C; };
        const A = somar(await buscar(per)), B = cmp ? somar(await buscar(cmp)) : null;
        let caixas = Object.keys(A).concat(B ? Object.keys(B) : []).filter((c, i, l) => l.indexOf(c) === i);
        const tot = (c) => (A[c] ? A[c].v + A[c].d + A[c].n : 0);
        caixas.sort((x, y) => (B ? ((A[y] ? A[y].v : 0) - (A[x] ? A[x].v : 0)) : (tot(y) - tot(x))) || x.localeCompare(y));
        caixas = caixas.slice(0, 20);
        const v = (M, c, k) => (M && M[c] ? M[c][k] : 0);
        const totV = Object.values(A).reduce((s, c) => s + c.v, 0), totD = Object.values(A).reduce((s, c) => s + c.d, 0), totN = Object.values(A).reduce((s, c) => s + c.n, 0);
        out.titulo = 'Tickets recebidos por caixa';
        out.grafico = B
            ? { tipo: 'barras_h', eixo: 'Caixa', formato: 'num', empilhado: false, rotulos: caixas, series: [{ nome: nomeA, cor: PD_COR.a, valores: caixas.map(c => v(A, c, 'v')) }, { nome: nomeB, cor: PD_COR.b, valores: caixas.map(c => v(B, c, 'v')) }] }
            : { tipo: 'barras_h', eixo: 'Caixa', formato: 'num', empilhado: true, rotulos: caixas, series: [{ nome: 'Recebidos (contam)', cor: PD_COR.a, valores: caixas.map(c => v(A, c, 'v')) }, { nome: 'Duplicadas', cor: PD_COR.cinza, valores: caixas.map(c => v(A, c, 'd')) }, { nome: 'Abertas por nós ou sem mensagem', cor: PD_COR.b, valores: caixas.map(c => v(A, c, 'n')) }] };
        out.kpis.push({ rot: 'Recebidos', val: pdNum(totV), sub: nomeA }, { rot: 'À parte', val: pdNum(totD + totN), sub: `${pdPl(totD, 'duplicada', 'duplicadas')} · ${pdPl(totN, 'aberta por nós', 'abertas por nós')}` });
        if (B) { const totVB = Object.values(B).reduce((s, c) => s + c.v, 0), vr = variacao(totV, totVB, per.dias, cmp.dias); out.kpis.push({ rot: 'Comparação', val: pdNum(totVB), sub: nomeB + (vr === null ? '' : ` · ${pdPct(vr)} na média/dia`) }); out.destaques.variacao_media_dia_pct = vr === null ? null : Math.round(vr * 10) / 10; }
        if (B && (per.fim === hoje || cmp.fim === hoje)) pdAjustarHoje(out, null, null, per, cmp, K, nomeB, avisos);   // 14/10/2026: hoje no período: por caixa fica sem a % (evita queda falsa)
        out.kpis.push({ rot: 'Caixas', val: pdNum(caixas.length), sub: 'com ticket no período' });
        out.sql = `-- recebidos = conversas novas do período pela regra do Recebimento (CTE "Rb")\nSELECT caixa, tipo, COUNT(*) AS qtd\nFROM recebidos\nWHERE (:time = 'TODOS' OR setor = :time)   -- time: ${time}\nGROUP BY caixa, tipo;   -- tipo: valido · duplicado · aberto_por_nos · sem_mensagem`;
        out.resumo = { agrupado_por: 'caixa', periodo: nomeA, comparacao: nomeB || null, time: PD_NOME_TIME[time], itens: caixas.map(c => ({ caixa: c, recebidos: v(A, c, 'v'), duplicadas: v(A, c, 'd'), abertas_por_nos_ou_sem_mensagem: v(A, c, 'n'), recebidos_comparacao: B ? v(B, c, 'v') : undefined })), total_recebidos: totV, total_a_parte: totD + totN };
        if (caixas.length) { const top = caixas.slice().sort((x, y) => v(A, y, 'v') - v(A, x, 'v'))[0]; out.destaques.maior = { caixa: top, recebidos: v(A, top, 'v'), pct_do_total: totV ? Math.round(v(A, top, 'v') / totV * 1000) / 10 : 0 }; }
        return out;
    }

    // time · dia · hora · dia da semana: a própria rota da tela (mesmos números, cache de 30 min)
    const rota = (x) => pdRota(`/api/recebimento-tickets?since=${pdUnix(x.ini)}&until=${pdUnix(x.fim, true)}`, avisos);
    const a = await rota(per), b = cmp ? await rota(cmp) : null;
    const completos = (r) => (r.por_dia || []).filter(d => !d.parcial);
    const mediaDia = (r, k) => { const ds = completos(r).length ? completos(r) : (r.por_dia || []); return ds.length ? ds.reduce((s, d) => s + (d[k] || 0), 0) / ds.length : 0; };
    const totA = (a.por_time && a.por_time[K]) || 0, totB = b ? ((b.por_time && b.por_time[K]) || 0) : 0;
    const fo = (a.fora && a.fora[time]) || { duplicados: 0, abertos_por_nos: 0, sem_mensagem: 0 };
    out.kpis.push({ rot: 'Recebidos', val: pdNum(totA), sub: nomeA + (time !== 'TODOS' ? ` · ${PD_NOME_TIME[time]}` : '') });
    out.kpis.push({ rot: 'Média por dia', val: pdNum(mediaDia(a, K), 1), sub: (a.por_dia || []).some(d => d.parcial) ? 'hoje fora da média (dia parcial)' : 'dias completos' });
    if (b) { const vr = variacao(totA, totB, per.dias, cmp.dias); out.kpis.push({ rot: 'Comparação', val: pdNum(totB), sub: nomeB + (vr === null ? '' : ` · ${pdPct(vr)} na média/dia`) }); out.destaques.variacao_media_dia_pct = vr === null ? null : Math.round(vr * 10) / 10; }
    if (b && (per.fim === hoje || cmp.fim === hoje)) pdAjustarHoje(out, a, b, per, cmp, K, nomeB, avisos);   // 14/10/2026: hoje ainda não acabou: compara até a mesma hora (ou só os dias completos)
    out.kpis.push({ rot: 'À parte', val: pdNum(fo.duplicados + fo.abertos_por_nos + fo.sem_mensagem), sub: `${pdPl(fo.duplicados, 'duplicada', 'duplicadas')} · ${pdPl(fo.abertos_por_nos + fo.sem_mensagem, 'aberta por nós', 'abertas por nós')}` });
    out.sql = `-- mesma consulta da tela Recebimento de Tickets (/api/recebimento-tickets), período ${nomeA}${b ? ' e ' + nomeB : ''}\nSELECT setor, dia, hora, COUNT(*) AS qtd\nFROM recebidos   -- conversas novas do período pela regra do Recebimento\nWHERE tipo = 'valido'\nGROUP BY setor, dia, hora;`;
    let rot = [], sA = [], sB = [], tipo = 'colunas', eixo = '';
    if (ag === 'time') {
        rot = PD_TIMES.map(t => PD_NOME_TIME[t]); sA = PD_TIMES.map(t => (a.por_time && a.por_time[t]) || 0); sB = b ? PD_TIMES.map(t => (b.por_time && b.por_time[t]) || 0) : [];
        tipo = 'barras_h'; eixo = 'Time'; out.titulo = 'Tickets recebidos por time';
        if (time !== 'TODOS') avisos.push('No gráfico por time aparecem todos os times.');
    } else if (ag === 'dia') {
        rot = (a.por_dia || []).map(d => pdBR(d.dia).slice(0, 5) + (d.parcial ? ' (parcial)' : '')); sA = (a.por_dia || []).map(d => d[K] || 0);
        sB = b ? (a.por_dia || []).map((_, i) => (b.por_dia && b.por_dia[i]) ? (b.por_dia[i][K] || 0) : null) : [];
        tipo = b ? 'linhas' : 'colunas'; eixo = 'Dia'; out.titulo = 'Tickets recebidos por dia';
        if (b) regras.push('Comparação dia a dia na ordem dos períodos (1º dia com 1º dia)');
    } else if (ag === 'hora') {
        rot = Array.from({ length: 24 }, (_, h) => h + 'h'); sA = (a.por_hora || []).map(h => h[K] || 0); sB = b ? (b.por_hora || []).map(h => h[K] || 0) : [];
        tipo = 'linhas'; eixo = 'Hora'; out.titulo = 'Tickets recebidos por hora';
        regras.push(per.dias > 1 ? 'Por hora: soma do período' : 'Por hora: o dia inteiro, de 0h às 23h59');
    } else {
        const ordem = [1, 2, 3, 4, 5, 6, 0];
        const porDow = (r) => ordem.map(w => { const ds = completos(r).filter(d => d.dow === w); return ds.length ? Math.round(ds.reduce((s, d) => s + (d[K] || 0), 0) / ds.length * 10) / 10 : null; });
        rot = ordem.map(w => PD_DIAS[w].slice(0, 3)); sA = porDow(a); sB = b ? porDow(b) : [];
        tipo = b ? 'linhas' : 'colunas'; eixo = 'Dia da semana'; out.titulo = 'Média de tickets por dia da semana';
        regras.push('Dia da semana: média dos dias completos do período');
    }
    out.grafico = { tipo, eixo, formato: 'num', empilhado: false, rotulos: rot, series: [{ nome: nomeA, cor: PD_COR.a, valores: sA }].concat(b ? [{ nome: nomeB, cor: PD_COR.b, valores: sB }] : []) };
    const idx = sA.reduce((m, v, i) => ((v || 0) > (sA[m] || 0) ? i : m), 0);
    out.destaques.maior = { rotulo: rot[idx], valor: sA[idx] };
    if (ag === 'time') out.destaques.maior.pct_do_total = totA ? Math.round((sA[idx] || 0) / totA * 1000) / 10 : 0;
    out.resumo = { agrupado_por: ag, periodo: nomeA, comparacao: nomeB || null, time: PD_NOME_TIME[time], itens: rot.map((r, i) => ({ rotulo: r, valor: sA[i], comparacao: b ? sB[i] : undefined })), total: totA, total_comparacao: b ? totB : undefined, a_parte: fo };
    return out;
}

// ---------- 2) ETIQUETAS 48H E PAINEL ----------
async function pdExecEtiquetas(p, hoje) {
    const per = pdPeriodo(p, hoje, PD_MAX_DIAS.etiquetas_48h_painel), avisos = per.avisos.slice();
    const et = ['ambos', '48h', 'painel'].includes(p.etiqueta) ? p.etiqueta : 'ambos';
    const ag = p.agrupar_por === 'dia' ? 'dia' : 'caixa';
    const grupo = ag === 'dia' ? `TO_CHAR(e.criado_br, 'YYYY-MM-DD')` : 'e.caixa';
    const sqlFinal = `,
    Etq AS (   -- 1 linha por conversa recebida com etiqueta: quando cada etiqueta foi colocada
        SELECT rb.conv_id, rb.created_at, rb.caixa, rb.criado_br,
               MIN(tg.created_at) FILTER (WHERE t.name ILIKE '%time-48h%') AS em_48h,
               MIN(tg.created_at) FILTER (WHERE t.name ILIKE 'painel-do-pedido%') AS em_painel
        FROM Rb rb
        JOIN taggings tg ON tg.taggable_type = 'Conversation' AND tg.taggable_id = rb.conv_id
        JOIN tags t ON t.id = tg.tag_id AND (t.name ILIKE '%time-48h%' OR t.name ILIKE 'painel-do-pedido%')
        WHERE rb.tipo = 'valido'
        GROUP BY 1, 2, 3, 4
    )
    SELECT ${grupo} AS grupo,
           COUNT(*) FILTER (WHERE e.em_48h <= e.created_at + interval '10 minutes')::int AS h_cheg,
           COUNT(*) FILTER (WHERE e.em_48h > e.created_at + interval '10 minutes')::int AS h_dep,
           COUNT(*) FILTER (WHERE e.em_painel <= e.created_at + interval '10 minutes')::int AS p_cheg,
           COUNT(*) FILTER (WHERE e.em_painel > e.created_at + interval '10 minutes')::int AS p_dep,
           COUNT(*) FILTER (WHERE e.em_painel <= e.created_at + interval '10 minutes' AND NOT COALESCE(e.em_48h <= e.created_at + interval '10 minutes', FALSE))::int AS a_p,
           COUNT(*) FILTER (WHERE LEAST(e.em_48h, e.em_painel) > e.created_at + interval '10 minutes')::int AS a_dep
    FROM Etq e
    GROUP BY 1`;
    const linhas = await pdCacheado(`etq|${ag}|${per.ini}|${per.fim}`, hoje, per.fim, async () => (await pool.query(PD_SQL_BASE + sqlFinal, [per.ini, per.fim])).rows);
    const G = {};
    linhas.forEach(r => { G[r.grupo] = r; });
    const val = (g) => { const r = G[g] || {}; if (et === '48h') return [r.h_cheg || 0, r.h_dep || 0]; if (et === 'painel') return [r.p_cheg || 0, r.p_dep || 0]; return [r.h_cheg || 0, r.a_p || 0, r.a_dep || 0]; };
    let rot;
    if (ag === 'dia') { rot = []; for (let d = per.ini; d <= per.fim; d = pdSoma(d, 1)) rot.push(d); }
    else rot = Object.keys(G).filter(g => val(g).some(x => x > 0)).sort((x, y) => val(y).reduce((s, n) => s + n, 0) - val(x).reduce((s, n) => s + n, 0) || x.localeCompare(y)).slice(0, 20);
    const nomes = et === 'ambos' ? [['48H na chegada', PD_COR.azul], ['Painel na chegada', PD_COR.a], ['Etiqueta colocada depois', PD_COR.b]] : [['Na chegada (até 10 min)', et === '48h' ? PD_COR.azul : PD_COR.a], ['Colocada depois', PD_COR.b]];
    const series = nomes.map(([nome, cor], k) => ({ nome, cor, valores: rot.map(g => val(g)[k]) }));
    const tot = series.reduce((s, x) => s + x.valores.reduce((a, n) => a + n, 0), 0), dep = series[series.length - 1].valores.reduce((a, n) => a + n, 0);
    const NOME_ET = { ambos: '48H e Painel', '48h': '48H', painel: 'Painel' };
    return {
        titulo: `Tickets com etiqueta ${NOME_ET[et]} por ${ag === 'dia' ? 'dia' : 'caixa'}`,
        fonte: 'Chatwoot · etiquetas time-48h e painel-do-pedido', periodo_txt: pdPeriodoTxt(per), avisos,
        grafico: { tipo: ag === 'dia' ? 'colunas' : 'barras_h', eixo: ag === 'dia' ? 'Dia' : 'Caixa', formato: 'num', empilhado: true, rotulos: ag === 'dia' ? rot.map(d => pdBR(d).slice(0, 5)) : rot, series },
        kpis: [
            { rot: 'Com etiqueta', val: pdNum(tot), sub: `tickets recebidos · ${NOME_ET[et]}` },
            { rot: 'Na chegada', val: tot ? pdNum((tot - dep) / tot * 100, 1) + '%' : '—', sub: 'etiqueta até 10 min da abertura' },
            { rot: 'Colocada depois', val: pdNum(dep), sub: 'contam no time que recebeu' }
        ],
        regras: PD_REGRAS_REC.slice(0, 3).concat([`Etiqueta: ${et === '48h' ? 'time-48h' : (et === 'painel' ? 'painel-do-pedido' : 'time-48h ou painel-do-pedido (a que veio primeiro)')}`, 'Na chegada = etiqueta colocada até 10 min depois da abertura · colocada depois: o ticket conta no time que recebeu']),
        sql: `-- recebidos = conversas novas do período pela regra do Recebimento (CTE "Rb")\nSELECT ${ag === 'dia' ? 'dia' : 'caixa'},\n       COUNT(*) FILTER (WHERE etiqueta - abertura <= interval '10 minutes') AS na_chegada,\n       COUNT(*) FILTER (WHERE etiqueta - abertura >  interval '10 minutes') AS depois\nFROM recebidos JOIN etiquetas_48h_painel USING (conversa)   -- ${NOME_ET[et]}\nGROUP BY ${ag === 'dia' ? 'dia' : 'caixa'};`,
        destaques: { total: tot, na_chegada_pct: tot ? Math.round((tot - dep) / tot * 1000) / 10 : null, colocada_depois: dep },
        resumo: { etiqueta: NOME_ET[et], agrupado_por: ag, periodo: pdPeriodoTxt(per), itens: rot.map((g, i) => { const o = { rotulo: ag === 'dia' ? pdBR(g).slice(0, 5) : g }; series.forEach(s => { o[s.nome] = s.valores[i]; }); return o; }), total: tot, colocada_depois: dep },
        nomes: {}
    };
}

// ---------- 3) TMC E TMR JUSTOS POR AGENTE (a mesma conta da tela de Atendimento por Agente) ----------
async function pdExecAgentes(p, hoje) {
    const per = pdPeriodo(p, hoje, PD_MAX_DIAS.tmc_tmr_agentes), avisos = per.avisos.slice();
    const time = PD_TIMES.includes(String(p.time || '').toUpperCase()) && String(p.time).toUpperCase() !== 'OUTROS' ? String(p.time).toUpperCase() : 'TODOS';
    const medida = ['tmc', 'tmr', 'ambos'].includes(p.medida) ? p.medida : 'ambos';
    const j = await pdRota(`/api/atendimento-agentes?since=${pdUnix(per.ini)}&until=${pdUnix(per.fim, true)}`, avisos);
    const ord = medida === 'tmr' ? 'tmr' : 'tmc';
    let ags = (j.dados || []).filter(d => (time === 'TODOS' || d.time === time) && (d[ord + '_qtd'] || 0) > 0);
    ags.sort((x, y) => (x[ord + '_medio_minutos'] - y[ord + '_medio_minutos']) || String(x.agente).localeCompare(String(y.agente)));   // menor tempo primeiro
    const totalAg = ags.length;
    if (ags.length > 25) { avisos.push(`Mostrando os 25 agentes com menor ${ord.toUpperCase()} de ${totalAg}.`); ags = ags.slice(0, 25); }
    const media = (k) => { const base = (j.dados || []).filter(d => (time === 'TODOS' || d.time === time) && (d[k + '_qtd'] || 0) > 0); const n = base.reduce((s, d) => s + d[k + '_qtd'], 0); return n ? base.reduce((s, d) => s + d[k + '_medio_minutos'] * d[k + '_qtd'], 0) / n : null; };
    const mTmc = media('tmc'), mTmr = media('tmr');
    const val = (d, k) => (d[k + '_qtd'] || 0) > 0 ? Math.round(d[k + '_medio_minutos'] * 10) / 10 : null;
    const series = [];
    if (medida !== 'tmr') series.push({ nome: 'TMC (1º contato)', cor: PD_COR.a, valores: ags.map(d => val(d, 'tmc')) });
    if (medida !== 'tmc') series.push({ nome: 'TMR (resposta)', cor: PD_COR.b, valores: ags.map(d => val(d, 'tmr')) });
    const nomes = {}; ags.forEach((d, i) => { nomes[`Agente ${i + 1}`] = d.agente; });
    const kpis = [];
    if (medida !== 'tmr') kpis.push({ rot: 'TMC do time', val: pdTempo(mTmc), sub: 'média de todas as 1ªs respostas' });
    if (medida !== 'tmc') kpis.push({ rot: 'TMR do time', val: pdTempo(mTmr), sub: 'média de todas as respostas' });
    kpis.push({ rot: 'Agentes', val: pdNum(totalAg), sub: time === 'TODOS' ? 'todos os times' : PD_NOME_TIME[time] });
    const melhor = ags[0], pior = ags[ags.length - 1];
    return {
        titulo: `${medida === 'ambos' ? 'TMC e TMR' : ord.toUpperCase()} justos por agente`,
        fonte: 'Chatwoot · mensagens e atribuições (conta justa)', periodo_txt: pdPeriodoTxt(per), avisos,
        grafico: { tipo: 'barras_h', eixo: 'Agente', formato: 'min', empilhado: false, rotulos: ags.map(d => d.agente), series },
        kpis,
        regras: ['Mesma conta da tela Atendimento por Agente (TMC/TMR justos)', 'Só conta o tempo em que o caso estava com o agente: fila e tempo com outro agente não contam', 'TMC = da atribuição (ou da mensagem do cliente, se chegou depois) até a 1ª resposta na vez · TMR = as demais respostas na vez', 'Tempo corrido · ordem: menor tempo primeiro'],
        sql: `-- mesma rota da tela de Atendimento por Agente (/api/atendimento-agentes), período ${pdPeriodoTxt(per)}\n-- TMC/TMR justos: calculados em Node sobre as mensagens públicas e as atribuições de cada ticket (15.3.2)`,
        destaques: { tmc_time_min: mTmc === null ? null : Math.round(mTmc * 10) / 10, tmr_time_min: mTmr === null ? null : Math.round(mTmr * 10) / 10, melhor: melhor ? 'Agente 1' : null, pior: pior ? `Agente ${ags.length}` : null, ordenado_por: ord.toUpperCase() + ' (menor primeiro)' },
        resumo: { periodo: pdPeriodoTxt(per), time: PD_NOME_TIME[time], itens: ags.map((d, i) => ({ agente: `Agente ${i + 1}`, time: d.time, tmc_min: val(d, 'tmc'), base_tmc: d.tmc_qtd || 0, tmr_min: val(d, 'tmr'), base_tmr: d.tmr_qtd || 0 })), tmc_time_min: mTmc, tmr_time_min: mTmr },
        nomes
    };
}

// ---------- 4) ESPERA DO CLIENTE (o lado do cliente: só quando perguntarem) ----------
async function pdExecEspera(p, hoje) {
    const per = pdPeriodo(p, hoje, PD_MAX_DIAS.espera_cliente), avisos = per.avisos.slice();
    const ag = ['caixa', 'time', 'dia', 'hora'].includes(p.agrupar_por) ? p.agrupar_por : 'caixa';
    const medida = ['primeiro_contato', 'resposta', 'ambos'].includes(p.medida) ? p.medida : 'ambos';
    const grupo = { caixa: 'e.caixa', time: 'e.setor', dia: `TO_CHAR(e.criado_br, 'YYYY-MM-DD')`, hora: `EXTRACT(HOUR FROM (e.inicio AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo'))::int::text` }[ag];
    const sqlFinal = `,
    Seq AS (   -- mensagens públicas do cliente e de agente (pessoa); robô e automação não contam como contato · caixa/time/dia vêm junto (sem juntar com Rb de novo)
        SELECT m.conversation_id AS conv_id, m.id, m.created_at, (m.message_type = 0) AS cli, rb.caixa, rb.setor, rb.criado_br
        FROM Rb rb
        JOIN messages m ON m.conversation_id = rb.conv_id
        WHERE rb.tipo = 'valido' AND m.private = FALSE
          AND m.created_at >= ($1 || ' 00:00:00')::timestamp AT TIME ZONE 'America/Sao_Paulo'
          AND (m.message_type = 0 OR (m.message_type = 1 AND m.sender_type = 'User' AND m.sender_id IS NOT NULL AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE))
    ),
    Marc AS (
        SELECT conv_id, created_at, cli, caixa, setor, criado_br,
               LAG(cli) OVER (PARTITION BY conv_id ORDER BY created_at, id) AS antes,
               MIN(created_at) FILTER (WHERE NOT cli) OVER (PARTITION BY conv_id ORDER BY created_at DESC, id DESC ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS resposta
        FROM Seq
    ),
    Esperas AS (   -- cada espera começa na 1ª mensagem do cliente depois de uma resposta (ou na 1ª da conversa)
        SELECT conv_id, caixa, setor, criado_br, created_at AS inicio, (antes IS NULL) AS primeira, resposta, EXTRACT(EPOCH FROM resposta - created_at) AS seg
        FROM Marc
        WHERE cli AND (antes IS NULL OR antes = FALSE)
    )
    SELECT ${grupo} AS grupo,
           COUNT(*) FILTER (WHERE e.primeira AND e.resposta IS NOT NULL)::int AS n1,
           AVG(e.seg) FILTER (WHERE e.primeira AND e.resposta IS NOT NULL) AS media1,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY e.seg) FILTER (WHERE e.primeira AND e.resposta IS NOT NULL) AS mediana1,
           COUNT(*) FILTER (WHERE e.primeira AND e.resposta IS NULL)::int AS sem1,
           COUNT(*) FILTER (WHERE NOT e.primeira AND e.resposta IS NOT NULL)::int AS n2,
           AVG(e.seg) FILTER (WHERE NOT e.primeira AND e.resposta IS NOT NULL) AS media2,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY e.seg) FILTER (WHERE NOT e.primeira AND e.resposta IS NOT NULL) AS mediana2
    FROM Esperas e
    GROUP BY GROUPING SETS ((${grupo}), ())`;
    const linhas = await pdCacheado(`espera|${ag}|${per.ini}|${per.fim}`, hoje, per.fim, async () => (await pool.query(PD_SQL_BASE + sqlFinal, [per.ini, per.fim])).rows);
    const geral = linhas.find(r => r.grupo === null) || {}, G = {};
    linhas.filter(r => r.grupo !== null).forEach(r => { G[r.grupo] = r; });
    let rot;
    if (ag === 'hora') rot = Array.from({ length: 24 }, (_, h) => String(h));
    else if (ag === 'dia') { rot = []; for (let d = per.ini; d <= per.fim; d = pdSoma(d, 1)) rot.push(d); }
    else if (ag === 'time') rot = PD_TIMES.filter(t => G[t]);
    else rot = Object.keys(G).sort((x, y) => ((G[y].n1 || 0) + (G[y].n2 || 0)) - ((G[x].n1 || 0) + (G[x].n2 || 0)) || x.localeCompare(y)).slice(0, 20);
    const nomeRot = (g) => ag === 'hora' ? g + 'h' : (ag === 'dia' ? pdBR(g).slice(0, 5) : (ag === 'time' ? PD_NOME_TIME[g] : g));
    const series = [];
    if (medida !== 'resposta') series.push({ nome: '1º contato (média)', cor: PD_COR.a, valores: rot.map(g => G[g] && G[g].n1 ? pdMin(G[g].media1) : null) });
    if (medida !== 'primeiro_contato') series.push({ nome: 'Resposta (média)', cor: PD_COR.b, valores: rot.map(g => G[g] && G[g].n2 ? pdMin(G[g].media2) : null) });
    const kpis = [];
    if (medida !== 'resposta') kpis.push({ rot: 'Espera até o 1º contato', val: pdTempo(pdMin(geral.media1)), sub: `média · metade em até ${pdTempo(pdMin(geral.mediana1))}` });
    if (medida !== 'primeiro_contato') kpis.push({ rot: 'Espera por resposta', val: pdTempo(pdMin(geral.media2)), sub: `média · metade em até ${pdTempo(pdMin(geral.mediana2))}` });
    kpis.push({ rot: 'Conversas medidas', val: pdNum(geral.n1 || 0), sub: pdPl(geral.n2 || 0, 'espera por resposta', 'esperas por resposta') });
    kpis.push({ rot: 'Sem contato de agente', val: pdNum(geral.sem1 || 0), sub: 'até agora · fora da média' });
    const s0 = series[0], idxPior = s0 ? s0.valores.reduce((m, v, i) => (v !== null && (s0.valores[m] === null || v > s0.valores[m]) ? i : m), 0) : 0;
    return {
        titulo: `Espera do cliente por ${{ caixa: 'caixa', time: 'time', dia: 'dia', hora: 'hora' }[ag]}`,
        fonte: 'Chatwoot · mensagens (lado do cliente)', periodo_txt: pdPeriodoTxt(per), avisos,
        grafico: { tipo: (ag === 'dia' || ag === 'hora') ? 'linhas' : 'barras_h', eixo: { caixa: 'Caixa', time: 'Time', dia: 'Dia', hora: 'Hora' }[ag], formato: 'min', empilhado: false, rotulos: rot.map(nomeRot), series },
        kpis,
        regras: ['Lado do cliente: quanto ele esperou, com qualquer agente ou fila (tempo corrido)', '1º contato = da 1ª mensagem do cliente até a 1ª resposta de um agente (pessoa) · robô e automação não contam', 'Resposta = de cada nova mensagem do cliente (depois de uma resposta) até a próxima resposta de agente', 'Conversas abertas pelo cliente no período, pela regra do Recebimento (sem duplicadas, sem Brasil e Pitaco Teste)', 'Quem ainda não teve contato fica fora da média e aparece à parte'],
        sql: `-- recebidos = conversas novas do período pela regra do Recebimento (CTE "Rb")\n-- esperas = cada mensagem do cliente que abre uma espera → próxima resposta de agente (pessoa)\nSELECT ${ag},\n       AVG(resposta - inicio) FILTER (WHERE primeira)     AS espera_1o_contato,\n       AVG(resposta - inicio) FILTER (WHERE NOT primeira) AS espera_resposta\nFROM esperas JOIN recebidos USING (conversa)\nGROUP BY ${ag};`,
        destaques: { primeiro_contato_media_min: pdMin(geral.media1), primeiro_contato_mediana_min: pdMin(geral.mediana1), resposta_media_min: pdMin(geral.media2), resposta_mediana_min: pdMin(geral.mediana2), sem_contato: geral.sem1 || 0, maior_espera: s0 && rot.length ? { rotulo: nomeRot(rot[idxPior]), minutos: s0.valores[idxPior], medida: s0.nome } : null },
        resumo: { agrupado_por: ag, periodo: pdPeriodoTxt(per), itens: rot.map(g => ({ rotulo: nomeRot(g), primeiro_contato_min: G[g] && G[g].n1 ? pdMin(G[g].media1) : null, base_1o_contato: G[g] ? G[g].n1 : 0, resposta_min: G[g] && G[g].n2 ? pdMin(G[g].media2) : null, base_resposta: G[g] ? G[g].n2 : 0 })), geral: { primeiro_contato_min: pdMin(geral.media1), resposta_min: pdMin(geral.media2), sem_contato: geral.sem1 || 0 } },
        nomes: {}
    };
}

const PD_EXEC = { recebimento: pdExecRecebimento, etiquetas_48h_painel: pdExecEtiquetas, tmc_tmr_agentes: pdExecAgentes, espera_cliente: pdExecEspera };

// ---------- catálogo que o Claude enxerga (ferramentas) ----------
const PD_PERIODO_PROPS = {
    periodo: { type: 'string', enum: ['hoje', 'ontem', 'esta_semana', 'semana_passada', 'este_mes', 'mes_passado', 'ultimos_7_dias', 'ultimos_30_dias', 'personalizado'], description: 'Período. Prefira os relativos; personalizado só para datas citadas.' },
    inicio: { type: 'string', description: 'Só com periodo=personalizado: AAAA-MM-DD' },
    fim: { type: 'string', description: 'Só com periodo=personalizado: AAAA-MM-DD (igual ao início para 1 dia)' },
    titulo: { type: 'string', description: 'Título curto do gráfico, em português, até 60 caracteres' }
};
const PD_FERRAMENTAS = [
    { name: 'recebimento', description: 'Tickets recebidos: conversas novas abertas pelo cliente (duplicadas, abertas por nós e sem mensagem ficam à parte; caixas Atendimento | Brasil e Pitaco Teste fora; spam fora da conta). Mesma regra da tela Recebimento de Tickets. Serve para volume, entrada, chegada de tickets, por time, caixa, dia, hora ou dia da semana, e para comparar dois períodos (ex.: dia X × dia Y por hora).',
        input_schema: { type: 'object', properties: Object.assign({}, PD_PERIODO_PROPS, {
            agrupar_por: { type: 'string', enum: ['time', 'caixa', 'dia', 'hora', 'dia_da_semana'] },
            time: { type: 'string', enum: ['TODOS'].concat(PD_TIMES), description: 'Filtra um time (não vale para agrupar_por=time)' },
            comparar: { type: 'string', enum: ['nao', 'periodo_anterior', 'semana_anterior', 'personalizado'], description: 'semana_anterior = mesmos dias 7 dias antes; personalizado usa comparar_inicio/comparar_fim' },
            comparar_inicio: { type: 'string', description: 'AAAA-MM-DD' }, comparar_fim: { type: 'string', description: 'AAAA-MM-DD' }
        }), required: ['periodo', 'agrupar_por', 'titulo'] } },
    { name: 'etiquetas_48h_painel', description: 'Tickets recebidos com etiqueta 48H (time-48h) e/ou Painel (painel-do-pedido), separando a etiqueta colocada na chegada (até 10 min da abertura) da colocada depois. Por caixa ou por dia.',
        input_schema: { type: 'object', properties: Object.assign({}, PD_PERIODO_PROPS, {
            etiqueta: { type: 'string', enum: ['ambos', '48h', 'painel'], description: 'ambos = 48H e Painel; "só 48h" = 48h; "só painel" = painel' },
            agrupar_por: { type: 'string', enum: ['caixa', 'dia'] }
        }), required: ['periodo', 'etiqueta', 'agrupar_por', 'titulo'] } },
    { name: 'tmc_tmr_agentes', description: 'TMC (1º contato) e TMR (resposta) de cada agente pela conta justa do Dash: só conta o tempo em que o caso estava com o agente; tempo corrido. É a resposta padrão para TMC, TMR e tempo de resposta dos agentes.',
        input_schema: { type: 'object', properties: Object.assign({}, PD_PERIODO_PROPS, {
            time: { type: 'string', enum: ['TODOS', 'RET', 'SAC', 'BKO', 'SMS', '48H'] },
            medida: { type: 'string', enum: ['tmc', 'tmr', 'ambos'] }
        }), required: ['periodo', 'medida', 'titulo'] } },
    { name: 'espera_cliente', description: 'Quanto o cliente esperou, do lado dele: até o 1º contato de um agente (pessoa) e entre a mensagem dele e a próxima resposta, com qualquer agente ou fila; tempo corrido. Use SÓ quando a pergunta falar do cliente: "quanto tempo o cliente esperou", "espera do cliente", "TMC/TMR do cliente".',
        input_schema: { type: 'object', properties: Object.assign({}, PD_PERIODO_PROPS, {
            agrupar_por: { type: 'string', enum: ['caixa', 'time', 'dia', 'hora'] },
            medida: { type: 'string', enum: ['primeiro_contato', 'resposta', 'ambos'] }
        }), required: ['periodo', 'agrupar_por', 'medida', 'titulo'] } },
    { name: 'fora_do_escopo', description: 'Use quando a pergunta não couber nas outras ferramentas (ex.: reembolso, produto, retenção, procedimento, motivo de contato: chegam na próxima fase).',
        input_schema: { type: 'object', properties: {
            motivo: { type: 'string', description: 'Explicação curta para o gestor, em português' },
            sugestoes: { type: 'array', items: { type: 'string' }, description: 'Até 3 perguntas parecidas que o catálogo responde' }
        }, required: ['motivo'] } }
];
const PD_FERRAMENTA_RESPONDER = { name: 'responder', description: 'Entrega a leitura do gráfico.',
    input_schema: { type: 'object', properties: {
        insight: { type: 'string', description: 'Até 2 frases curtas (máximo 280 caracteres) com o achado principal, só com os números enviados' },
        seguir: { type: 'array', items: { type: 'string' }, description: '2 ou 3 perguntas curtas de continuação (até 60 caracteres cada)' }
    }, required: ['insight', 'seguir'] } };
function pdSistemaEscolher(hoje) {
    return `Você é o robô do Dash GEX, o painel de atendimento ao cliente da empresa. Seu trabalho: escolher UMA consulta do catálogo (ferramentas) que responde à pergunta do gestor, com os parâmetros certos. Você não calcula números.
Hoje é ${pdBR(hoje)} (${PD_DIAS[pdD(hoje).getUTCDay()]}), horário de Brasília. Semana = segunda a domingo. Datas sem ano são de ${hoje.slice(0, 4)}.
Período: prefira os relativos (hoje, ontem, esta_semana, semana_passada, este_mes, mes_passado, ultimos_7_dias, ultimos_30_dias), porque o gráfico pode ser fixado e se atualizar depois. Use personalizado (inicio e fim em AAAA-MM-DD) só para datas citadas. Sem período na pergunta: ultimos_7_dias.
Times: RET = Retenção, SAC, BKO = BackOffice, SMS, 48H, OUTROS = sem time.
Como escolher:
- Tickets recebidos, volume, entrada, chegada → recebimento. "Dia X e dia Y", "hoje x ontem", "ontem x semana passada" → recebimento com agrupar_por=hora e comparar.
- Etiqueta 48H, Painel, "48h e painel", "só 48h", "só painel" → etiquetas_48h_painel.
- TMC, TMR, tempo de 1ª resposta ou de resposta dos agentes → tmc_tmr_agentes (conta justa).
- Só quando a pergunta falar do lado do cliente ("quanto tempo o cliente esperou", "espera do cliente", "TMC/TMR do cliente") → espera_cliente.
- Reembolso, produto, retenção, procedimento, motivo de contato ou qualquer outra coisa → fora_do_escopo.
Se vier uma pergunta anterior e a nova for continuação dela ("e só o SAC?", "e ontem?", "agora por hora"), repita a consulta anterior mudando só o que foi pedido.
Título: curto, em português, sem ponto final.`;
}
const PD_SISTEMA_LER = `Você escreve a leitura de um gráfico do Dash GEX para gestores de atendimento. Português do Brasil, frases curtas, tom direto.
Use só os números enviados em "dados" e "destaques": não faça contas novas e não invente causas. Agentes aparecem como "Agente N": escreva exatamente assim, sem artigo antes (ex.: "Agente 3 tem o menor TMC").
insight: até 2 frases (máximo 280 caracteres) com o achado principal.
seguir: 2 ou 3 perguntas curtas de continuação que caibam no catálogo: recebimento (por time, caixa, dia, hora, dia da semana, comparando períodos), etiquetas 48H e Painel, TMC/TMR justos por agente e espera do cliente.`;

async function pdClaude(corpo) {
    const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), 45000);
    try {
        const r = await fetch(PD_API_URL, { method: 'POST', signal: ctl.signal,
            headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
            body: JSON.stringify(Object.assign({ model: PD_MODELO }, corpo)) });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw Object.assign(new Error((j && j.error && j.error.message) || ('HTTP ' + r.status)), { api: true });
        return j;
    } catch (e) {
        if (e.api) throw e;
        throw Object.assign(new Error(e.name === 'AbortError' ? 'demorou mais de 45 s' : (e.message || 'falha de conexão')), { api: true });
    } finally { clearTimeout(timer); }
}
const pdTrocarNomes = (txt, nomes) => String(txt || '').replace(/\bAgente (\d+)\b/g, (m) => nomes[m] || m);
function pdResposta(pergunta, consulta, r, insight, seguir, t0, semRobo) {
    const tit = String((consulta.parametros && consulta.parametros.titulo) || '').trim().slice(0, 80) || r.titulo;
    return { ok: true, pergunta, consulta, titulo: tit, periodo_txt: r.periodo_txt, fonte: r.fonte, grafico: r.grafico, kpis: r.kpis, insight, seguir, regras: r.regras, sql: r.sql, avisos: r.avisos, sem_robo: !!semRobo, modelo: semRobo ? '' : PD_MODELO, ms: Date.now() - t0 };
}

app.post('/api/pergunte-dash', express.json({ limit: '64kb' }), async (req, res) => {
    if (!ehAdminReq(req)) return res.status(403).json({ ok: false, erro: 'Acesso restrito para Administradores.' });
    const email = ((req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value : '').toLowerCase();
    const b = req.body || {}, hoje = pdHoje(), t0 = Date.now();
    let segurando = false;
    try {
        // a) abrir um gráfico fixado: roda a mesma consulta de novo, sem usar a API
        if (b.consulta && typeof b.consulta === 'object' && PD_EXEC[b.consulta.ferramenta]) {
            const consulta = { ferramenta: b.consulta.ferramenta, parametros: (b.consulta.parametros && typeof b.consulta.parametros === 'object') ? b.consulta.parametros : {} };
            const r = await PD_EXEC[consulta.ferramenta](consulta.parametros, hoje);
            return res.json(pdResposta(String(b.pergunta || '').slice(0, 300), consulta, r, '', [], t0, true));
        }
        const pergunta = String(b.pergunta || '').replace(/\s+/g, ' ').trim().slice(0, 300);
        if (pergunta.length < 3) return res.status(400).json({ ok: false, erro: 'Escreva a pergunta.' });
        if (!process.env.ANTHROPIC_API_KEY) return res.status(503).json({ ok: false, sem_chave: true, erro: 'O robô ainda não está ligado: falta a variável ANTHROPIC_API_KEY no servidor. Os gráficos fixados continuam abrindo.' });
        if (pdRodando[email]) return res.status(429).json({ ok: false, erro: 'Espere a pergunta anterior terminar.' });
        const uso = (pdUso[email] || []).filter(t => Date.now() - t < 3600000);
        if (uso.length >= PD_LIMITE_HORA) return res.status(429).json({ ok: false, erro: `Limite de ${PD_LIMITE_HORA} perguntas por hora atingido. Tente de novo em alguns minutos.` });
        uso.push(Date.now()); pdUso[email] = uso; pdRodando[email] = true; segurando = true;

        // b) o robô escolhe a consulta (com a pergunta anterior, para continuações)
        const ant = (b.anterior && b.anterior.consulta && PD_EXEC[b.anterior.consulta.ferramenta]) ? b.anterior : null;
        const texto = (ant ? `Pergunta anterior: "${String(ant.pergunta || '').slice(0, 300)}" → consulta usada: ${JSON.stringify(ant.consulta).slice(0, 900)}\n` : '') + `Pergunta: "${pergunta}"`;
        const r1 = await pdClaude({ max_tokens: 800, system: pdSistemaEscolher(hoje), tools: PD_FERRAMENTAS, tool_choice: { type: 'any' }, messages: [{ role: 'user', content: texto }] });
        const escolha = (r1.content || []).find(x => x && x.type === 'tool_use');
        if (!escolha) throw Object.assign(new Error('o robô não escolheu uma consulta'), { api: true });
        if (!PD_EXEC[escolha.name]) {
            const inp = escolha.input || {};
            console.log(`🤖 Pergunte ao Dash: fora do catálogo em ${Date.now() - t0} ms`);
            return res.json({ ok: true, fora_do_escopo: true, pergunta, motivo: String(inp.motivo || 'Essa pergunta ainda não está no catálogo do robô.').slice(0, 400), seguir: (Array.isArray(inp.sugestoes) ? inp.sugestoes : []).slice(0, 3).map(s => String(s).slice(0, 90)), ms: Date.now() - t0 });
        }
        const consulta = { ferramenta: escolha.name, parametros: escolha.input || {} };

        // c) o banco calcula (consulta pronta, só leitura)
        const r = await PD_EXEC[consulta.ferramenta](consulta.parametros, hoje);

        // d) o robô lê o resultado: só totais; agente vai como "Agente N"
        let insight = '', seguir = [];
        try {
            const r2 = await pdClaude({ max_tokens: 500, system: PD_SISTEMA_LER, tools: [PD_FERRAMENTA_RESPONDER], tool_choice: { type: 'tool', name: 'responder' },
                messages: [{ role: 'user', content: JSON.stringify({ pergunta, titulo: r.titulo, periodo: r.periodo_txt, dados: r.resumo, destaques: r.destaques }) }] });
            const lido = (r2.content || []).find(x => x && x.type === 'tool_use');
            if (lido && lido.input) {
                insight = pdTrocarNomes(String(lido.input.insight || '').slice(0, 400), r.nomes);
                seguir = (Array.isArray(lido.input.seguir) ? lido.input.seguir : []).slice(0, 3).map(s => pdTrocarNomes(String(s).slice(0, 90), r.nomes));
            }
        } catch (e) { r.avisos.push('A leitura do robô não veio agora; o gráfico e os números estão certos.'); }
        console.log(`🤖 Pergunte ao Dash: ${consulta.ferramenta} em ${Date.now() - t0} ms`);
        res.json(pdResposta(pergunta, consulta, r, insight, seguir, t0, false));
    } catch (e) {
        console.error('Erro Pergunte ao Dash:', e.message);
        res.status(e.api ? 502 : 500).json({ ok: false, erro: e.api ? `O robô não respondeu agora (${e.message}). Tente de novo em instantes.` : `Não consegui buscar os números agora (${e.message}).` });
    } finally {
        if (segurando) delete pdRodando[email];
    }
});

// ==========================================
// 16.1 ROTA DE URGÊNCIA: REEMBOLSOS BUYGOODS (COM GOOGLE SHEETS)
// ==========================================
// 14/10/2026: chamada externa com tempo limite (AbortController, como no pdClaude/trChatwoot): Apps Script ou Chatwoot travado não segura a rota por minutos
function fetchComLimite(url, opcoes, ms) {
    const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), ms);
    return fetch(url, Object.assign({}, opcoes, { signal: ctl.signal }))
        .catch(e => { throw (e && e.name === 'AbortError') ? new Error(`sem resposta em ${Math.round(ms / 1000)} s`) : e; })
        .finally(() => clearTimeout(timer));
}
app.get('/api/reembolsos-buygoods', async (req, res) => {
    const fetch = (url, opcoes) => fetchComLimite(url, opcoes, 30000);   // 14/10/2026: o log de reembolso (Apps Script) tem 30 s para responder
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
            dInicio = new Date(Date.UTC(agora.getFullYear(), agora.getMonth(), 1, 3));        // 14/10/2026: dia 1 às 00:00 de Brasília (03:00 UTC), com o servidor em qualquer fuso
            dFim = new Date(Date.UTC(agora.getFullYear(), agora.getMonth() + 1, 1, 3) - 1);   // 14/10/2026: fim do mês 23:59:59 de Brasília (antes "agora" ficava 3 h atrasado com o servidor em UTC)
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

        const pendentesLog = await rbPendentesDoLog(logMap, new Set(result.rows.map(x => String(x.display_id))), dInicio, dFim, 'buygoods');   // 27/10/2026
        res.json({ success: true, dados: arrayFinal, pendentes_log: pendentesLog });
    } catch (error) { 
        console.error("Erro BuyGoods:", error);
        res.status(500).json({ success: false, error: "Erro interno no servidor." }); 
    }
});

app.get('/api/reembolsos-cartpanda', async (req, res) => {
    const fetch = (url, opcoes) => fetchComLimite(url, opcoes, 30000);   // 14/10/2026: o log de reembolso (Apps Script) tem 30 s para responder
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
            dInicio = new Date(Date.UTC(agora.getFullYear(), agora.getMonth(), 1, 3));        // 14/10/2026: dia 1 às 00:00 de Brasília (03:00 UTC), com o servidor em qualquer fuso
            dFim = new Date(Date.UTC(agora.getFullYear(), agora.getMonth() + 1, 1, 3) - 1);   // 14/10/2026: fim do mês 23:59:59 de Brasília (antes "agora" ficava 3 h atrasado com o servidor em UTC)
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

        const pendentesLog = await rbPendentesDoLog(logMap, new Set(result.rows.map(x => String(x.display_id))), dInicio, dFim, 'cartpanda');   // 27/10/2026
        res.json({ success: true, dados: arrayFinal, pendentes_log: pendentesLog });
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
            // 🛡️ 16/10/2026: coluna de senha, token, chave ou segredo aparece mascarada (ex.: access_tokens, users, canais do Chatwoot) — o Raio-X mostra a estrutura, não as credenciais
            const COL_SENSIVEL = /pass|senha|token|secret|segredo|key|chave|otp|salt|hash|crypt|credential|cert|private|hmac|signature|cookie|session|webhook|provider_config|serialized_value|settings/i;
            const valorRaioX = (col, v) => (v !== null && v !== undefined && v !== '' && (COL_SENSIVEL.test(col) || tabela === 'access_tokens')) ? '<i style="color:#fbbf24">•••• oculto</i>' : esc(v);

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
                for (const row of amostra.rows) html += '<tr>' + ck.map(c => `<td>${valorRaioX(c, row[c])}</td>`).join('') + '</tr>';   // 16/10/2026: valorRaioX (mascara as colunas sensíveis)
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

        if ([cont, sla, porDia, fila, entre, prod, heat].some(x => x === null)) return res.status(500).json({ success: false, error: 'O banco não respondeu a todas as consultas do resumo agora. Tente de novo em instantes.' });   // 14/10/2026: consulta que falhou não vira zero com success (o cache guardava os zeros por 30 min); com 500 o Dash entrega o último dado bom, marcado
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
        const _errPer = tkPeriodoValido(ini, fim);   // 26/10/2026: teto de período
        if (_errPer) return res.status(400).json({ success: false, error: _errPer });
        const result = await pool.query(queryTickets, [ini, fim]);
        const dias = [];
        let d = new Date(ini + 'T12:00:00Z'); const dEnd = new Date(fim + 'T12:00:00Z');
        while (d <= dEnd) { dias.push(d.toISOString().split('T')[0]); d.setUTCDate(d.getUTCDate() + 1); }
        const mapa = {};
        result.rows.forEach(r => {
            const nome = r.agente || 'SEM ATRIBUIR';
            const diaStr = r.dia instanceof Date ? r.dia.toISOString().split('T')[0] : String(r.dia).split('T')[0];
            if (!mapa[nome]) mapa[nome] = { nome, lider: tkLiderDe(nome), porDia: {}, total: 0 };
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
        const horasFaixa = Math.round(diffHoras);   // 14/10/2026: a faixa usa as mesmas horas arredondadas que aparecem ("parado há Xh") e que o filtro do adiamento (detalhePassaFaixa) usa
        let statusLabel, ordem;
        if (horasFaixa > 48) { mapa[nome].fora_sla += 1; statusLabel = '\u{1F534} +48h'; ordem = 1; }   // 14/10/2026: horasFaixa
        else if (horasFaixa >= 24) { mapa[nome].aguardando += 1; statusLabel = '\u{1F7E1} 24-48h'; ordem = 2; }   // 14/10/2026: horasFaixa
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
    const fetch = (url, opcoes) => fetchComLimite(url, opcoes, 30000);   // 14/10/2026: o Chatwoot tem 30 s para responder (antes um toggle_status travado segurava o Adiar por minutos)
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
// 20.5 🔀 TRANSFERIR E ATRIBUIR TICKETS (14/10/2026) — SÓ O DONO (mesma trava do Adiar Casos)
// Transfere casos de agente(s) ou da fila para 1 ou mais agentes, ou atribui qualquer ticket pelo número.
// 2+ agentes = distribui: cada ticket vai para quem tem MENOS casos abertos no momento (equilibra a carga).
// O time do ticket muda junto para o time do agente que recebe (só para um time do qual ele é membro).
// Só manda para quem tem acesso à caixa do ticket (membro da caixa ou administrador no Chatwoot).
// Escreve SÓ pela API REST do Chatwoot (como o Adiar); no banco o Dash só lê: monta a lista, a prévia e confere o resultado.
// Responde com "ok" (e não "success") de propósito: o cache do Dash não guarda estas respostas (casos e cargas mudam a cada transferência).
// ==========================================
const TR_MAX_ITENS = 300;              // tickets por transferência
const TR_SETORES = [['RET', /reten/i], ['SAC', /sac/i], ['BKO', /back ?office|bko/i], ['SMS', /sms/i], ['48H', /48/]];
const trHistorico = [];                // últimas transferências (memória do servidor; zera quando o Dash reinicia)
let trRodando = false;
const trSetorDe = (nome) => { const s = TR_SETORES.find(([, re]) => re.test(String(nome || ''))); return s ? s[0] : ''; };
const trSiglaNome = (nome) => { const m = String(nome || '').toUpperCase().match(/[\s\-]+(RET|SAC|BKO|SMS|48H)\b/); return m ? m[1] : ''; };   // 14/10/2026: sigla do time no nome, a mesma regra do resto do Dash ("Ana - RET", "ANA RET 2")
const trIds = (v) => [...new Set((Array.isArray(v) ? v : String(v || '').split(/[^0-9]+/)).map(x => parseInt(x, 10)).filter(x => Number.isInteger(x) && x > 0))];

async function trTabelaExiste(nome) {
    try { return (await pool.query(`SELECT to_regclass($1) IS NOT NULL AS ok`, ['public.' + nome])).rows[0].ok; } catch (e) { return false; }
}
// agentes da conta, times, caixas e a carga de cada um (casos abertos agora)
async function trBase() {
    const [agentes, times, caixas, membrosTime, carga, fila] = await Promise.all([
        pool.query(`SELECT u.id, u.name AS nome, au.role FROM account_users au JOIN users u ON u.id = au.user_id WHERE au.account_id = 1 ORDER BY u.name`),
        pool.query(`SELECT id, name AS nome FROM teams WHERE account_id = 1 ORDER BY name`),
        pool.query(`SELECT id, name AS nome FROM inboxes WHERE account_id = 1 ORDER BY name`),
        pool.query(`SELECT team_id, user_id FROM team_members`),
        pool.query(`SELECT assignee_id, status, COUNT(*)::int AS qtd FROM conversations WHERE account_id = 1 AND status IN (0, 2, 3) AND assignee_id IS NOT NULL GROUP BY 1, 2`),
        pool.query(`SELECT team_id, COUNT(*)::int AS qtd FROM conversations WHERE account_id = 1 AND status = 0 AND assignee_id IS NULL GROUP BY 1`)   // fila por time do caso (14/10/2026)
    ]);
    const temCaixas = await trTabelaExiste('inbox_members');
    const membrosCaixa = temCaixas ? (await pool.query(`SELECT inbox_id, user_id FROM inbox_members`)).rows : [];
    const nomeTime = {}; times.rows.forEach(t => { nomeTime[t.id] = t.nome; });
    const porAgente = {};
    agentes.rows.forEach(a => {
        porAgente[a.id] = { id: Number(a.id), nome: a.nome, admin: Number(a.role) === 1, times: [], caixas: [], abertos: 0, pendentes: 0, adiados: 0 };
    });
    membrosTime.rows.forEach(m => { const a = porAgente[m.user_id]; if (a && nomeTime[m.team_id] !== undefined) a.times.push(Number(m.team_id)); });
    membrosCaixa.forEach(m => { const a = porAgente[m.user_id]; if (a) a.caixas.push(Number(m.inbox_id)); });
    carga.rows.forEach(r => { const a = porAgente[r.assignee_id]; if (!a) return; const st = Number(r.status); if (st === 0) a.abertos += r.qtd; else if (st === 2) a.pendentes += r.qtd; else a.adiados += r.qtd; });
    Object.values(porAgente).forEach(a => {   // time do agente para os filtros (14/10/2026): a sigla do nome, como no resto do Dash ("Ana - RET"); sem sigla no nome, o 1º time dele no Chatwoot
        const doTime = a.times.map(id => trSetorDe(nomeTime[id])).filter(Boolean);
        a.setor = trSiglaNome(a.nome) || doTime[0] || '';
    });
    const filaSetor = {};   // fila (abertos sem agente) por time, pelo time do caso no Chatwoot (14/10/2026)
    fila.rows.forEach(r => { const s = r.team_id !== null && nomeTime[r.team_id] !== undefined ? trSetorDe(nomeTime[r.team_id]) : ''; if (s) filaSetor[s] = (filaSetor[s] || 0) + r.qtd; });
    return {
        agentes: Object.values(porAgente),
        times: times.rows.map(t => ({ id: Number(t.id), nome: t.nome, setor: trSetorDe(t.nome) })),
        caixas: caixas.rows.map(c => ({ id: Number(c.id), nome: c.nome })),
        fila: fila.rows.reduce((s, r) => s + r.qtd, 0),
        fila_setor: filaSetor,
        controle_de_caixa: temCaixas
    };
}
// tickets com o que a tela e a prévia precisam (sem conteúdo de mensagem)
const TR_SQL_TICKETS = `
    SELECT c.id AS conv_id, c.display_id, c.status, c.assignee_id, c.team_id, c.inbox_id,
           TO_CHAR(c.created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo', 'YYYY-MM-DD HH24:MI') AS criado_br,
           i.name AS caixa, t.name AS time_nome, u.name AS agente, ct.name AS cliente, COALESCE(c.cached_label_list, '') AS etiquetas,
           CASE WHEN lm.message_type = 0 THEN FLOOR(EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'UTC') - lm.created_at)) / 60)::int END AS esperando_min
    FROM conversations c
    LEFT JOIN inboxes i ON i.id = c.inbox_id
    LEFT JOIN teams t ON t.id = c.team_id
    LEFT JOIN users u ON u.id = c.assignee_id
    LEFT JOIN contacts ct ON ct.id = c.contact_id
    LEFT JOIN LATERAL (
        SELECT m.message_type, m.created_at FROM messages m
        WHERE m.conversation_id = c.id AND m.private = FALSE AND m.message_type IN (0, 1, 3)
          AND (m.content_attributes->>'deleted')::boolean IS NOT TRUE
        ORDER BY m.created_at DESC, m.id DESC LIMIT 1
    ) lm ON TRUE
    WHERE c.account_id = 1`;
function trTicket(r) {   // esperando_min: cliente esperando resposta há X min (a última mensagem pública é dele)
    return {
        display_id: Number(r.display_id), status: Number(r.status), assignee_id: r.assignee_id === null ? null : Number(r.assignee_id), agente: r.agente || '',
        team_id: r.team_id === null ? null : Number(r.team_id), time: r.time_nome || '', inbox_id: Number(r.inbox_id), caixa: r.caixa || '',
        cliente: r.cliente || 'Cliente sem nome', etiquetas: r.etiquetas || '', criado_em: r.criado_br, esperando_min: r.esperando_min === null || r.esperando_min === undefined ? null : Math.max(0, Number(r.esperando_min))
    };
}
const trTemAcesso = (agente, inboxId, controle) => !controle || agente.admin || agente.caixas.includes(Number(inboxId));
// time que o ticket ganha com o agente: o time atual se ele já é membro; senão o único time dele; com 2+ times, o do sufixo do nome ("Ana - SAC")
function trTimeDestino(agente, ticket, times) {
    if (ticket.team_id !== null && agente.times.includes(ticket.team_id)) return { team_id: ticket.team_id, aviso: '' };
    if (agente.times.length === 1) return { team_id: agente.times[0], aviso: '' };
    if (agente.times.length > 1) {
        const suf = trSiglaNome(agente.nome);   // 14/10/2026: a sigla do nome (antes a sigla RET não era reconhecida)
        const certo = agente.times.filter(id => { const t = times.find(x => x.id === id); return t && suf && t.setor === suf; });
        if (certo.length === 1) return { team_id: certo[0], aviso: '' };
        return { team_id: ticket.team_id, aviso: 'agente em mais de 1 time: o time do ticket não mudou' };
    }
    return { team_id: ticket.team_id, aviso: 'agente sem time no Chatwoot: o time do ticket não mudou' };
}
// prévia: distribui pela carga (quem tem menos abertos recebe o próximo ticket), respeitando o acesso à caixa
function trPlanejar(tickets, destinos, base) {
    const carga = {}; destinos.forEach(a => { carga[a.id] = a.abertos; });
    const recebe = {}; destinos.forEach(a => { recebe[a.id] = 0; });
    const nomeTime = {}; base.times.forEach(t => { nomeTime[t.id] = t.nome; });
    const itens = tickets.slice().sort((x, y) => String(x.criado_em).localeCompare(String(y.criado_em)) || x.display_id - y.display_id).map(tk => {   // o mais antigo primeiro
        const item = { display_id: tk.display_id, cliente: tk.cliente, caixa: tk.caixa, status: tk.status, de_id: tk.assignee_id, de: tk.agente || 'Sem agente', time_de_id: tk.team_id, time_de: tk.time || 'Sem time' };
        if (tk.assignee_id !== null && destinos.some(a => a.id === tk.assignee_id)) return Object.assign(item, { acao: 'ja_esta', para_id: tk.assignee_id, para: tk.agente, time_para_id: tk.team_id, time_para: item.time_de, aviso: 'já está com este agente' });
        const pode = destinos.filter(a => trTemAcesso(a, tk.inbox_id, base.controle_de_caixa));
        if (!pode.length) return Object.assign(item, { acao: 'sem_acesso', aviso: 'nenhum agente escolhido tem acesso à caixa ' + tk.caixa });
        pode.sort((x, y) => (carga[x.id] - carga[y.id]) || (recebe[x.id] - recebe[y.id]) || String(x.nome).localeCompare(String(y.nome)));
        const ag = pode[0]; carga[ag.id] += 1; recebe[ag.id] += 1;
        const tm = trTimeDestino(ag, tk, base.times);
        return Object.assign(item, { acao: 'transferir', para_id: ag.id, para: ag.nome, time_para_id: tm.team_id, time_para: tm.team_id === null ? 'Sem time' : (nomeTime[tm.team_id] || ''), aviso: tm.aviso });
    });
    return {
        itens,
        destinos: destinos.map(a => ({ id: a.id, nome: a.nome, setor: a.setor, carga_antes: a.abertos, recebe: recebe[a.id], carga_depois: a.abertos + recebe[a.id] })),
        resumo: { total: itens.length, transferir: itens.filter(i => i.acao === 'transferir').length, ja_esta: itens.filter(i => i.acao === 'ja_esta').length, sem_acesso: itens.filter(i => i.acao === 'sem_acesso').length, time_muda: itens.filter(i => i.acao === 'transferir' && i.time_para_id !== i.time_de_id).length }
    };
}
async function trChatwoot(displayId, corpo) {   // POST .../conversations/{display_id}/assignments  { assignee_id } ou { team_id } (0 = tira)
    const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), 15000);
    try {
        const resp = await fetch(`${CHATWOOT_URL}/api/v1/accounts/${CHATWOOT_ACCOUNT_ID}/conversations/${displayId}/assignments`, {
            method: 'POST', signal: ctl.signal,
            headers: { 'Content-Type': 'application/json', 'api_access_token': CHATWOOT_API_TOKEN },
            body: JSON.stringify(corpo)
        });
        if (!resp.ok) { let txt = ''; try { txt = await resp.text(); } catch (e) {} throw new Error(`HTTP ${resp.status} ${String(txt).slice(0, 120)}`); }
        return true;
    } catch (e) { throw new Error(e.name === 'AbortError' ? 'o Chatwoot não respondeu em 15 s' : e.message); }
    finally { clearTimeout(timer); }
}

// tela: agentes, times, caixas, carga e a fila
app.get('/api/transferir/base', async (req, res) => {
    if (!ehDonoAdiar(req)) return res.status(403).json({ ok: false, erro: 'Acesso restrito.' });
    try {
        const b = await trBase();
        res.json(Object.assign({ ok: true, token_ok: !!CHATWOOT_API_TOKEN, chatwoot_url: CHATWOOT_URL, conta: CHATWOOT_ACCOUNT_ID, historico: trHistorico.map(h => ({ id: h.id, em: h.em, origem: h.origem, total: h.total, feitos: h.feitos, falhas: h.falhas, desfeito: h.desfeito, detalhe: h.detalhe || '' })) }, b));
    } catch (e) { console.error('[transferir/base]', e.message); res.status(500).json({ ok: false, erro: e.message }); }
});
// tela: casos de 1 ou mais agentes e/ou da fila (sem agente), por status e caixa
app.get('/api/transferir/casos', async (req, res) => {
    if (!ehDonoAdiar(req)) return res.status(403).json({ ok: false, erro: 'Acesso restrito.' });
    try {
        const agentes = trIds(req.query.agentes), fila = req.query.fila === '1';
        if (!agentes.length && !fila) return res.json({ ok: true, tickets: [], cortado: false });
        const ST = { abertos: [0], pendentes: [2], adiados: [3], todos: [0, 2, 3] };
        const status = ST[String(req.query.status || 'abertos')] || ST.abertos;
        const caixa = /^\d+$/.test(String(req.query.caixa || '')) ? parseInt(req.query.caixa, 10) : null;
        const setorFila = String(req.query.time || '').toUpperCase(), timesFila = ['RET', 'SAC', 'BKO', 'SMS', '48H'].includes(setorFila)   // 14/10/2026: com time no filtro, a fila é só a daquele time
            ? (await pool.query(`SELECT id, name FROM teams WHERE account_id = 1`)).rows.filter(t => trSetorDe(t.name) === setorFila).map(t => Number(t.id)) : null;
        const r = await pool.query(`${TR_SQL_TICKETS}
      AND c.status = ANY($1::int[])
      AND (c.assignee_id = ANY($2::bigint[]) OR ($3::boolean AND c.assignee_id IS NULL AND ($5::bigint[] IS NULL OR c.team_id = ANY($5::bigint[]))))
      AND ($4::int IS NULL OR c.inbox_id = $4::int)
    ORDER BY c.created_at
    LIMIT 1001`, [status, agentes, fila, caixa, timesFila]);
        res.json({ ok: true, tickets: r.rows.slice(0, 1000).map(trTicket), cortado: r.rows.length > 1000 });
    } catch (e) { console.error('[transferir/casos]', e.message); res.status(500).json({ ok: false, erro: e.message }); }
});
// tela: qualquer ticket pelo número (qualquer status)
app.get('/api/transferir/tickets', async (req, res) => {
    if (!ehDonoAdiar(req)) return res.status(403).json({ ok: false, erro: 'Acesso restrito.' });
    try {
        const ids = trIds(req.query.ids);
        if (ids.length > TR_MAX_ITENS) return res.status(400).json({ ok: false, erro: `No máximo ${TR_MAX_ITENS} tickets por vez.` });
        if (!ids.length) return res.json({ ok: true, tickets: [], nao_achados: [] });
        const r = await pool.query(`${TR_SQL_TICKETS}
      AND c.display_id = ANY($1::int[])
    ORDER BY c.display_id`, [ids]);
        const achados = r.rows.map(trTicket);
        res.json({ ok: true, tickets: achados, nao_achados: ids.filter(id => !achados.some(t => t.display_id === id)) });
    } catch (e) { console.error('[transferir/tickets]', e.message); res.status(500).json({ ok: false, erro: e.message }); }
});
// prévia: quem recebe cada ticket (não muda nada)
app.post('/api/transferir/previa', express.json({ limit: '256kb' }), async (req, res) => {
    if (!ehDonoAdiar(req)) return res.status(403).json({ ok: false, erro: 'Acesso restrito.' });
    try {
        const b = req.body || {}, ids = trIds(b.ids), destIds = trIds(b.destinos);
        if (!ids.length) return res.status(400).json({ ok: false, erro: 'Escolha pelo menos 1 ticket.' });
        if (ids.length > TR_MAX_ITENS) return res.status(400).json({ ok: false, erro: `No máximo ${TR_MAX_ITENS} tickets por vez.` });
        if (b.desatribuir === true) {   // 🚫 Desatribuir (14/10/2026): o caso fica sem agente e volta para a fila do time dele (o time não muda)
            const rd = await pool.query(`${TR_SQL_TICKETS}
      AND c.display_id = ANY($1::int[])`, [ids]);
            const tks = rd.rows.map(trTicket);
            const itens = tks.slice().sort((x, y) => String(x.criado_em).localeCompare(String(y.criado_em)) || x.display_id - y.display_id).map(tk => ({
                display_id: tk.display_id, cliente: tk.cliente, caixa: tk.caixa, status: tk.status, de_id: tk.assignee_id, de: tk.agente || 'Sem agente', time_de_id: tk.team_id, time_de: tk.time || 'Sem time',
                acao: tk.assignee_id === null ? 'ja_esta' : 'desatribuir', para_id: 0, para: 'Fila (sem agente)', time_para_id: tk.team_id, time_para: tk.time || 'Sem time', aviso: tk.assignee_id === null ? 'já está sem agente' : '' }));
            return res.json({ ok: true, desatribuir: true, itens, destinos: [], nao_achados: ids.filter(id => !tks.some(t => t.display_id === id)), token_ok: !!CHATWOOT_API_TOKEN,
                resumo: { total: itens.length, desatribuir: itens.filter(i => i.acao === 'desatribuir').length, ja_esta: itens.filter(i => i.acao === 'ja_esta').length, transferir: 0, sem_acesso: 0, time_muda: 0 } });
        }
        if (!destIds.length) return res.status(400).json({ ok: false, erro: 'Escolha pelo menos 1 agente para receber.' });
        const base = await trBase();
        const destinos = base.agentes.filter(a => destIds.includes(a.id));
        if (destinos.length !== destIds.length) return res.status(400).json({ ok: false, erro: 'Algum agente escolhido não está mais na conta do Chatwoot. Atualize a tela.' });
        const r = await pool.query(`${TR_SQL_TICKETS}
      AND c.display_id = ANY($1::int[])`, [ids]);
        const tickets = r.rows.map(trTicket);
        const plano = trPlanejar(tickets, destinos, base);
        const nao = ids.filter(id => !tickets.some(t => t.display_id === id));
        res.json(Object.assign({ ok: true, nao_achados: nao, controle_de_caixa: base.controle_de_caixa, token_ok: !!CHATWOOT_API_TOKEN }, plano));
    } catch (e) { console.error('[transferir/previa]', e.message); res.status(500).json({ ok: false, erro: e.message }); }
});
// executa: cada item = { display_id, assignee_id, team_id } (team_id null = não mexe no time · 0 = tira; assignee_id 0 = sem agente, só no Desfazer)
app.post('/api/transferir/executar', express.json({ limit: '256kb' }), async (req, res) => {
    if (!ehDonoAdiar(req)) return res.status(403).json({ ok: false, erro: 'Acesso restrito.' });
    if (!CHATWOOT_API_TOKEN) return res.status(400).json({ ok: false, erro: 'CHATWOOT_API_TOKEN não configurado no servidor.' });
    if (trRodando) return res.status(429).json({ ok: false, erro: 'Já tem uma transferência rodando. Espere ela terminar.' });
    const email = ((req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value : '').toLowerCase();
    const b = req.body || {}, origem = ['transferir', 'atribuir', 'desfazer', 'desatribuir'].includes(b.origem) ? b.origem : 'transferir';
    const lista = Array.isArray(b.itens) ? b.itens : [];
    if (!lista.length) return res.status(400).json({ ok: false, erro: 'Nada para transferir.' });
    if (lista.length > TR_MAX_ITENS) return res.status(400).json({ ok: false, erro: `No máximo ${TR_MAX_ITENS} tickets por vez.` });
    trRodando = true;
    const t0 = Date.now();
    try {
        const base = await trBase(), ag = {}; base.agentes.forEach(a => { ag[a.id] = a; });
        const timesOk = new Set(base.times.map(t => t.id));
        const itens = [], erros = [];
        lista.forEach(x => {
            const d = parseInt(x && x.display_id, 10), a = parseInt(x && x.assignee_id, 10);
            const t = (x && x.team_id !== null && x.team_id !== undefined && x.team_id !== '') ? parseInt(x.team_id, 10) : null;
            if (!(d > 0)) return erros.push({ id: x && x.display_id, erro: 'número de ticket inválido' });
            if (!(Number.isInteger(a) && (a > 0 ? (!!ag[a] && origem !== 'desatribuir') : (a === 0 && (origem === 'desfazer' || origem === 'desatribuir'))))) return erros.push({ id: d, erro: 'agente inválido ou fora da conta' });
            if (t !== null && (origem === 'desatribuir' || !(Number.isInteger(t) && (t === 0 ? origem === 'desfazer' : timesOk.has(t))))) return erros.push({ id: d, erro: 'time inválido' });
            itens.push({ display_id: d, assignee_id: a, team_id: t });
        });
        const ids = [...new Set(itens.map(i => i.display_id))];
        const antes = {};
        if (ids.length) (await pool.query(`${TR_SQL_TICKETS}
      AND c.display_id = ANY($1::int[])`, [ids])).rows.map(trTicket).forEach(tk => { antes[tk.display_id] = tk; });
        const fazer = [];
        itens.forEach(i => {
            const tk = antes[i.display_id];
            if (!tk) return erros.push({ id: i.display_id, erro: 'ticket não existe no Chatwoot' });
            if (i.assignee_id > 0 && origem !== 'desfazer' && !trTemAcesso(ag[i.assignee_id], tk.inbox_id, base.controle_de_caixa)) return erros.push({ id: i.display_id, erro: `${ag[i.assignee_id].nome} não tem acesso à caixa ${tk.caixa}` });
            fazer.push(Object.assign({ tk }, i));
        });
        // ordem das chamadas: agente e depois time quando o agente é membro do time novo (o Chatwoot mantém o agente);
        // senão time e depois agente (ao trocar o time o Chatwoot tira o agente que não é do time — o agente vem por último)
        let feitos = 0;
        const desfazer = [];
        const CONC = 4;
        for (let k = 0; k < fazer.length; k += CONC) {
            await Promise.all(fazer.slice(k, k + CONC).map(async (i) => {
                const tk = i.tk, mudaAg = i.assignee_id !== (tk.assignee_id || 0), mudaTime = i.team_id !== null && i.team_id !== (tk.team_id || 0);
                try {
                    const agDoTime = i.team_id > 0 && i.assignee_id > 0 && ag[i.assignee_id].times.includes(i.team_id);
                    const passos = [];
                    if (mudaAg) passos.push({ assignee_id: i.assignee_id });
                    if (mudaTime) { if (agDoTime || !mudaAg) passos.push({ team_id: i.team_id }); else passos.unshift({ team_id: i.team_id }); }
                    if (mudaTime && !mudaAg && !(tk.assignee_id && ag[tk.assignee_id] && ag[tk.assignee_id].times.includes(i.team_id))) passos.push({ assignee_id: tk.assignee_id || 0 });   // o Chatwoot tiraria o agente: põe de volta
                    for (const p of passos) await trChatwoot(i.display_id, p);
                    feitos++;
                    desfazer.push({ display_id: i.display_id, assignee_id: tk.assignee_id || 0, team_id: tk.team_id || 0 });
                } catch (e) { erros.push({ id: i.display_id, erro: e.message }); }
            }));
            if (k + CONC < fazer.length) await new Promise(rs => setTimeout(rs, 150));
        }
        // confere no banco: cada ticket ficou com o agente e o time pedidos?
        await new Promise(rs => setTimeout(rs, 800));
        const depois = {};
        if (ids.length) (await pool.query(`SELECT display_id, assignee_id, team_id FROM conversations WHERE account_id = 1 AND display_id = ANY($1::int[])`, [ids])).rows.forEach(r => { depois[Number(r.display_id)] = r; });
        const divergentes = [];
        let conferidos = 0;
        fazer.filter(i => !erros.some(e => e.id === i.display_id)).forEach(i => {
            const d = depois[i.display_id] || {}, agOk = Number(d.assignee_id || 0) === i.assignee_id, timeOk = i.team_id === null || Number(d.team_id || 0) === i.team_id;
            if (agOk && timeOk) conferidos++;
            else divergentes.push({ id: i.display_id, agente: d.assignee_id && ag[d.assignee_id] ? ag[d.assignee_id].nome : 'Sem agente', time: d.team_id ? (base.times.find(t => t.id === Number(d.team_id)) || {}).nome || '' : 'Sem time' });
        });
        const lote = { id: Date.now().toString(36), em: new Date().toISOString(), por: email, origem, total: lista.length, feitos, falhas: erros.length, desfazer, desfeito: false };
        if (origem === 'desfazer' && b.lote) { const h = trHistorico.find(x => x.id === String(b.lote)); if (h) h.desfeito = true; }
        if (feitos > 0) { trHistorico.unshift(lote); if (trHistorico.length > 20) trHistorico.length = 20; }
        console.log(`🔀 Transferir (${origem}) por ${email}: ${feitos} de ${lista.length} em ${Date.now() - t0} ms · ${erros.length} falha(s) · conferidos ${conferidos}`);
        res.json({ ok: true, lote: feitos > 0 ? lote.id : null, origem, total: lista.length, feitos, falhas: erros.length, erros: erros.slice(0, 100), conferidos, divergentes: divergentes.slice(0, 100), desfazer, ms: Date.now() - t0 });
    } catch (e) {
        console.error('[transferir/executar]', e.message);
        res.status(500).json({ ok: false, erro: e.message });
    } finally { trRodando = false; }
});
// histórico: a lista para desfazer uma transferência (fica na memória do servidor)
app.get('/api/transferir/desfazer', async (req, res) => {
    if (!ehDonoAdiar(req)) return res.status(403).json({ ok: false, erro: 'Acesso restrito.' });
    const h = trHistorico.find(x => x.id === String(req.query.lote || ''));
    if (!h) return res.status(404).json({ ok: false, erro: 'Transferência não encontrada (o Dash pode ter reiniciado).' });
    res.json({ ok: true, lote: h.id, desfeito: h.desfeito, itens: h.desfazer, tipo: h.tipo || 'transferir' });
});

// 🏷️ ETIQUETAS (14/10/2026): coloca ou tira 1 ou mais etiquetas dos casos marcados (dos agentes escolhidos ou da fila) — SÓ O DONO
// Escreve SÓ pela API do Chatwoot. O POST de etiquetas troca a lista inteira do caso: o Dash lê a lista atual na API na hora e manda a lista nova.
// No banco o Dash só lê (etiquetas da conta, prévia e conferência). Desfazer = cada caso volta para as etiquetas de antes.
const trEtqNorm = (s) => String(s || '').trim().toLowerCase();
const trEtqDoCaso = (txt) => String(txt || '').split(',').map(s => s.trim()).filter(Boolean);
function trEtqNova(atuais, escolhidas, acao) {   // lista nova do caso: sem repetir e sem diferenciar maiúscula de minúscula
    if (acao === 'remover') { const tirar = new Set(escolhidas.map(trEtqNorm)); return atuais.filter(e => !tirar.has(trEtqNorm(e))); }
    const tem = new Set(atuais.map(trEtqNorm));
    return atuais.concat(escolhidas.filter(e => !tem.has(trEtqNorm(e))));
}
function trEtqIguais(a, b) { const x = [...new Set(a.map(trEtqNorm))].sort(), y = [...new Set(b.map(trEtqNorm))].sort(); return x.length === y.length && x.every((v, i) => v === y[i]); }
async function trEtqChatwoot(displayId, novas) {   // novas = null: GET (lista atual) · novas = [...]: POST (troca a lista) — .../conversations/{display_id}/labels
    const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), 15000);
    try {
        const resp = await fetch(`${CHATWOOT_URL}/api/v1/accounts/${CHATWOOT_ACCOUNT_ID}/conversations/${displayId}/labels`, {
            method: novas ? 'POST' : 'GET', signal: ctl.signal,
            headers: { 'Content-Type': 'application/json', 'api_access_token': CHATWOOT_API_TOKEN },
            body: novas ? JSON.stringify({ labels: novas }) : undefined
        });
        if (!resp.ok) { let txt = ''; try { txt = await resp.text(); } catch (e) {} throw new Error(`HTTP ${resp.status} ${String(txt).slice(0, 120)}`); }
        const j = await resp.json().catch(() => null);
        if (!j || !Array.isArray(j.payload)) throw new Error('o Chatwoot não devolveu a lista de etiquetas');
        return j.payload.map(String);
    } catch (e) { throw new Error(e.name === 'AbortError' ? 'o Chatwoot não respondeu em 15 s' : e.message); }
    finally { clearTimeout(timer); }
}
async function trEtqDaConta() {   // etiquetas cadastradas na conta do Chatwoot
    return (await pool.query(`SELECT title, color, description FROM labels WHERE account_id = 1 ORDER BY title`)).rows
        .map(l => ({ titulo: String(l.title || '').trim(), cor: l.color || '', descricao: l.description || '' })).filter(l => l.titulo);
}
async function trEtqValidar(pedidas) {   // só vale etiqueta que existe na conta, com o nome como está no Chatwoot
    const mapa = {}; (await trEtqDaConta()).forEach(l => { mapa[trEtqNorm(l.titulo)] = l.titulo; });
    const lista = [...new Set((Array.isArray(pedidas) ? pedidas : []).map(trEtqNorm).filter(Boolean))].slice(0, 30);
    return { ok: lista.filter(e => mapa[e]).map(e => mapa[e]), nao: lista.filter(e => !mapa[e]) };
}
// tela: etiquetas da conta (a busca pelo nome é feita na tela, como no Chatwoot)
app.get('/api/transferir/etiquetas', async (req, res) => {
    if (!ehDonoAdiar(req)) return res.status(403).json({ ok: false, erro: 'Acesso restrito.' });
    try { res.json({ ok: true, etiquetas: await trEtqDaConta() }); }
    catch (e) { console.error('[transferir/etiquetas]', e.message); res.status(500).json({ ok: false, erro: e.message }); }
});
// prévia: o que muda em cada caso (não muda nada)
app.post('/api/transferir/etiquetas/previa', express.json({ limit: '256kb' }), async (req, res) => {
    if (!ehDonoAdiar(req)) return res.status(403).json({ ok: false, erro: 'Acesso restrito.' });
    try {
        const b = req.body || {}, ids = trIds(b.ids), acao = b.acao === 'remover' ? 'remover' : 'adicionar';
        if (!ids.length) return res.status(400).json({ ok: false, erro: 'Marque pelo menos 1 caso na lista.' });
        if (ids.length > TR_MAX_ITENS) return res.status(400).json({ ok: false, erro: `No máximo ${TR_MAX_ITENS} casos por vez.` });
        const v = await trEtqValidar(b.etiquetas);
        if (v.nao.length) return res.status(400).json({ ok: false, erro: `Etiqueta que não existe no Chatwoot: ${v.nao.join(', ')}` });
        if (!v.ok.length) return res.status(400).json({ ok: false, erro: 'Escolha pelo menos 1 etiqueta.' });
        const r = await pool.query(`${TR_SQL_TICKETS}
      AND c.display_id = ANY($1::int[])`, [ids]);
        const tks = r.rows.map(trTicket);
        const itens = tks.slice().sort((x, y) => String(x.criado_em).localeCompare(String(y.criado_em)) || x.display_id - y.display_id).map(tk => {
            const antes = trEtqDoCaso(tk.etiquetas), depois = trEtqNova(antes, v.ok, acao);
            return { display_id: tk.display_id, cliente: tk.cliente, caixa: tk.caixa, agente: tk.agente || 'Sem agente', antes, depois, acao: trEtqIguais(antes, depois) ? 'igual' : 'muda' };
        });
        res.json({ ok: true, etiquetas: true, acao, escolhidas: v.ok, itens, token_ok: !!CHATWOOT_API_TOKEN, nao_achados: ids.filter(id => !tks.some(t => t.display_id === id)),
            resumo: { total: itens.length, muda: itens.filter(i => i.acao === 'muda').length, igual: itens.filter(i => i.acao === 'igual').length } });
    } catch (e) { console.error('[transferir/etiquetas/previa]', e.message); res.status(500).json({ ok: false, erro: e.message }); }
});
// executa: { ids, etiquetas, acao: 'adicionar' | 'remover' } · Desfazer: { itens: [{ display_id, etiquetas }], acao: 'restaurar', lote }
app.post('/api/transferir/etiquetas/executar', express.json({ limit: '512kb' }), async (req, res) => {
    if (!ehDonoAdiar(req)) return res.status(403).json({ ok: false, erro: 'Acesso restrito.' });
    if (!CHATWOOT_API_TOKEN) return res.status(400).json({ ok: false, erro: 'CHATWOOT_API_TOKEN não configurado no servidor.' });
    if (trRodando) return res.status(429).json({ ok: false, erro: 'Já tem uma ação rodando. Espere ela terminar.' });
    const email = ((req.user && req.user.emails && req.user.emails[0]) ? req.user.emails[0].value : '').toLowerCase();
    const b = req.body || {}, acao = ['adicionar', 'remover', 'restaurar'].includes(b.acao) ? b.acao : '';
    if (!acao) return res.status(400).json({ ok: false, erro: 'Ação inválida.' });
    let alvos = [], escolhidas = [];
    try {
        if (acao === 'restaurar') {
            const porId = new Map();
            (Array.isArray(b.itens) ? b.itens : []).forEach(x => {
                const d = parseInt(x && x.display_id, 10);
                if (d > 0) porId.set(d, { display_id: d, etiquetas: (Array.isArray(x.etiquetas) ? x.etiquetas : []).map(e => String(e).trim().slice(0, 100)).filter(Boolean).slice(0, 50) });
            });
            alvos = [...porId.values()];
        } else {
            const v = await trEtqValidar(b.etiquetas);
            if (v.nao.length) return res.status(400).json({ ok: false, erro: `Etiqueta que não existe no Chatwoot: ${v.nao.join(', ')}` });
            if (!v.ok.length) return res.status(400).json({ ok: false, erro: 'Escolha pelo menos 1 etiqueta.' });
            escolhidas = v.ok; alvos = trIds(b.ids).map(id => ({ display_id: id }));
        }
    } catch (e) { console.error('[transferir/etiquetas/executar]', e.message); return res.status(500).json({ ok: false, erro: e.message }); }
    if (!alvos.length) return res.status(400).json({ ok: false, erro: 'Nada para mudar.' });
    if (alvos.length > TR_MAX_ITENS) return res.status(400).json({ ok: false, erro: `No máximo ${TR_MAX_ITENS} casos por vez.` });
    trRodando = true;
    const t0 = Date.now();
    try {
        const ids = alvos.map(a => a.display_id);
        const existe = new Set((await pool.query(`SELECT display_id FROM conversations WHERE account_id = 1 AND display_id = ANY($1::int[])`, [ids])).rows.map(r => Number(r.display_id)));
        const erros = [], desfazer = [], esperado = {}, fazer = [];
        alvos.forEach(a => { if (existe.has(a.display_id)) fazer.push(a); else erros.push({ id: a.display_id, erro: 'ticket não existe no Chatwoot' }); });
        let feitos = 0, iguais = 0;
        const CONC = 4;
        for (let k = 0; k < fazer.length; k += CONC) {
            await Promise.all(fazer.slice(k, k + CONC).map(async (a) => {
                try {
                    const atuais = await trEtqChatwoot(a.display_id, null);   // a lista de agora, direto do Chatwoot (não apaga o que alguém pôs depois da prévia)
                    const novas = acao === 'restaurar' ? a.etiquetas : trEtqNova(atuais, escolhidas, acao);
                    if (trEtqIguais(atuais, novas)) { iguais++; return; }
                    await trEtqChatwoot(a.display_id, novas);
                    feitos++; esperado[a.display_id] = novas;
                    desfazer.push({ display_id: a.display_id, etiquetas: atuais });
                } catch (e) { erros.push({ id: a.display_id, erro: e.message }); }
            }));
            if (k + CONC < fazer.length) await new Promise(rs => setTimeout(rs, 150));
        }
        // confere no banco: cada caso ficou com as etiquetas pedidas?
        await new Promise(rs => setTimeout(rs, 800));
        const mudados = Object.keys(esperado).map(Number), divergentes = [];
        let conferidos = 0;
        if (mudados.length) (await pool.query(`SELECT display_id, COALESCE(cached_label_list, '') AS etiquetas FROM conversations WHERE account_id = 1 AND display_id = ANY($1::int[])`, [mudados])).rows.forEach(r => {
            const tem = trEtqDoCaso(r.etiquetas);
            if (trEtqIguais(tem, esperado[Number(r.display_id)])) conferidos++; else divergentes.push({ id: Number(r.display_id), etiquetas: tem.join(', ') || 'nenhuma' });
        });
        const origem = acao === 'restaurar' ? 'desfazer' : 'etiquetas';
        const detalhe = acao === 'restaurar' ? 'etiquetas de antes' : `${acao === 'remover' ? 'tirou' : 'colocou'}: ${escolhidas.join(', ')}`;
        const lote = { id: Date.now().toString(36), em: new Date().toISOString(), por: email, origem, tipo: 'etiquetas', detalhe, total: alvos.length, feitos, falhas: erros.length, desfazer, desfeito: false };
        if (acao === 'restaurar' && b.lote) { const h = trHistorico.find(x => x.id === String(b.lote)); if (h) h.desfeito = true; }
        if (feitos > 0) { trHistorico.unshift(lote); if (trHistorico.length > 20) trHistorico.length = 20; }
        console.log(`🏷️ Etiquetas (${acao}) por ${email}: ${feitos} de ${alvos.length} em ${Date.now() - t0} ms · ${iguais} já estavam assim · ${erros.length} falha(s) · conferidos ${conferidos}`);
        res.json({ ok: true, lote: feitos > 0 ? lote.id : null, origem, acao, detalhe, total: alvos.length, feitos, iguais, falhas: erros.length, erros: erros.slice(0, 100), conferidos, divergentes: divergentes.slice(0, 100), ms: Date.now() - t0 });
    } catch (e) {
        console.error('[transferir/etiquetas/executar]', e.message);
        res.status(500).json({ ok: false, erro: e.message });
    } finally { trRodando = false; }
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
        // 30/10/2026: cobertura e distribuição das notas por mês, contadas na BASE_MONITORIA (mesma planilha, só leitura).
        // Cada mês: monitorias, NCG (coluna NCG = Sim), notas por faixa, analistas monitorados e quantos tiveram os 4 ciclos.
        // Também: o time de quem não está na BASE DE MÉDIA (pela última monitoria fora da adaptação) e quem foi monitorado no mês mais recente (ativos).
        let monitorias = [], ativos = [], mesMaisRecente = '';
        try {
            const rb = await sheets.spreadsheets.values.get({ spreadsheetId: sheetId, range: `'BASE_MONITORIA'!A1:Z` });
            const porMes = {}, timeBase = {}, nomesPorMes = {};
            const normQ3 = s => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().trim().replace(/\s+/g, ' ');
            (rb.data.values || []).forEach((r, i) => {
                if (i < 4) return;
                const nome = String(r[2] || '').trim(), mes = String(r[8] || '').trim();
                if (!nome || !mes || mes.toUpperCase() === 'MES_REF') return;
                const sigla = qualSiglaDoSetor(String(r[1] || '').toUpperCase(), normalizeNome(nome));
                if (sigla !== 'ADAPTACAO') timeBase[normQ3(nome)] = sigla;   // a linha mais nova vence (a base está em ordem de data)
                const nm = nomesPorMes[mes] || (nomesPorMes[mes] = {});   // nome -> maior ciclo em que foi monitorado no mês
                nm[normQ3(nome)] = Math.max(nm[normQ3(nome)] || 0, parseInt(r[3]) || 0);
                const m = porMes[mes] || (porMes[mes] = { mes, monitorias: 0, ncg: 0, nota100: 0, de90a99: 0, de80a89: 0, abaixo80: 0, ciclosPorAnalista: {} });
                const nota = parseFloat(String(r[5] || '0').replace('%', '').replace(',', '.')) || 0;
                m.monitorias++;
                if (String(r[6] || '').trim().toUpperCase() === 'SIM') m.ncg++;
                if (nota >= 100) m.nota100++; else if (nota >= 90) m.de90a99++; else if (nota >= 80) m.de80a89++; else m.abaixo80++;
                const k = normalizeNome(nome);
                (m.ciclosPorAnalista[k] = m.ciclosPorAnalista[k] || new Set()).add(parseInt(r[3]) || 0);
            });
            monitorias = Object.values(porMes).map(m => {
                const ciclos = Object.values(m.ciclosPorAnalista);
                const { ciclosPorAnalista, ...resto } = m;
                return { ...resto, analistas: ciclos.length, analistasCom4: ciclos.filter(s => s.size >= 4).length };
            });
            Object.keys(timeBase).forEach(n => { if (!times[n] || times[n] === 'OUTROS') times[n] = timeBase[n]; });   // só completa: o time da BASE DE MÉDIA continua valendo
            mesMaisRecente = Object.keys(nomesPorMes).sort(qualMesesDoMaisNovo)[0] || '';
            if (mesMaisRecente) {   // ativo = monitorado em um dos 2 últimos ciclos do mês mais recente (quem saiu no meio do mês fica de fora)
                const nm = nomesPorMes[mesMaisRecente], ultimo = Math.max(...Object.values(nm));
                ativos = Object.keys(nm).filter(n => nm[n] >= ultimo - 1);
            }
        } catch (e) { console.log('[q3] BASE_MONITORIA indisponivel:', e.message); }
        res.json({ success: true, valores, times, monitorias, ativos, mesMaisRecente });
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
const ROTAS_WARM = ['/api/produtividade']; // 30/10/2026: /api/resumo-recorrencia saiu do aquecedor (a aba Cockpit foi retirada). /api/time48, Produtos e Menções saíram do aquecedor (01/10/2026): carregam 1x no acesso e depois só pelo 🔄 Atualizar
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
// 26/10/2026: BOT DESLIGADO a pedido — nenhum aviso, nenhuma rodada agendada e nenhum timer consultando dado
// enquanto ele não for reformulado. Para religar: TELEGRAM_ATIVO=1 no Render (nenhuma linha precisa ser mexida).
const TG_ATIVO = String(process.env.TELEGRAM_ATIVO || '').trim() === '1';
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
    if (!tgBot.carregado) return false;   // 14/10/2026: nunca regrava sem ter lido a planilha (a lista vazia de um boot com falha apagaria todos os vínculos)
    const sheets = tgSheets();
    if (!sheets) return false;
    try {
        await tgGarantirAbas(sheets);
        if (linhas.length) {
            await sheets.spreadsheets.values.update({ spreadsheetId: SNOOZE_SHEET_ID, range: `${aba}!A2`, valueInputOption: 'RAW', requestBody: { values: linhas.map(o => TG_CAB[aba].map(k => o[k] != null ? String(o[k]) : '')) } });
        }
        await sheets.spreadsheets.values.clear({ spreadsheetId: SNOOZE_SHEET_ID, range: `${aba}!A${linhas.length + 2}:K` });   // 14/10/2026: grava por cima primeiro e só depois limpa as linhas que sobraram (antes limpava a aba antes de gravar: falha no meio = aba vazia)
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
    } catch (e) { console.error('[telegram] não consegui ler a planilha de log:', e.message); tgBot.planilhaOk = false; return; }   // 14/10/2026: sem ler a planilha o bot não começa a atender (o tgTick tenta de novo a cada minuto)
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
// 14/10/2026: o limite do Telegram (4096) é do texto visível, sem as marcações. O corte antigo (4090 caracteres contando as marcações) caía no meio
// de <a href…> e o Telegram recusava a mensagem inteira (400). Agora só corta se o texto visível passar do limite, e sempre no fim de uma linha.
const tgVisivel = (s) => String(s == null ? '' : s).replace(/<[^>]*>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
function tgCortarHtml(texto, max) {
    const t = String(texto == null ? '' : texto), fim = '\n<i>… mensagem cortada</i>';
    if (tgVisivel(t).length <= max) return t;
    let out = '';
    for (const l of t.split('\n')) { const c = out ? out + '\n' + l : l; if (tgVisivel(c + fim).length > max) break; out = c; }
    return out + fim;
}
// 14/10/2026: se mesmo assim o Telegram recusar a formatação (400 "can't parse entities"), manda de novo sem formatação: a mensagem chega
async function tgMandarMensagem(corpo) {
    const r = await tgApi('sendMessage', corpo);
    if (r && !r.ok && r.error_code === 400 && /parse entities/i.test(String(r.description || ''))) {
        const simples = Object.assign({}, corpo, { text: tgVisivel(corpo.text).slice(0, 4096) });
        delete simples.parse_mode;
        return tgApi('sendMessage', simples);
    }
    return r;
}
// Envio "proativo" (aviso, resumo, relatório, teste): vai para a aba tg_envios — é o que a sub-aba Entregas & Leitura mostra
async function tgEnviar(destino, texto, meta) {
    meta = meta || {};
    const envioId = tgIdEnvio();
    const corpo = { chat_id: destino.chat_id, text: tgCortarHtml(texto, 4090), parse_mode: 'HTML', disable_web_page_preview: true };   // 14/10/2026: corta sem quebrar a marcação
    if (TG_TIPOS_CIENTE.includes(meta.tipo)) corpo.reply_markup = { inline_keyboard: [[{ text: '✅ Ciente', callback_data: `ok:${envioId}` }]] };
    const r = await tgMandarMensagem(corpo);   // 14/10/2026: reenvia sem formatação se o Telegram recusar o HTML
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
async function tgResponder(chatId, texto) { return tgMandarMensagem({ chat_id: chatId, text: tgCortarHtml(texto, 4090), parse_mode: 'HTML', disable_web_page_preview: true }); }   // 14/10/2026: corta sem quebrar a marcação e reenvia sem formatação se o Telegram recusar

// ---------- dados: Status de Casos (mesma rota do Dash) ----------
async function tgSnapshot(maxIdadeMs) {
    const idadeSnap = Date.now() - tgBot.snapEm;
    if (tgBot.snap && idadeSnap >= 0 && idadeSnap < (maxIdadeMs || 120000)) return tgBot.snap;
    if (tgBot.snapPromessa) return tgBot.snapPromessa;
    tgBot.snapPromessa = (async () => {
        const d = await tgGetInterno('/api/distribuicao', 90000);
        if (d && d.success && Array.isArray(d.casos)) { tgBot.snap = d; tgBot.snapEm = Date.now() - (d.dados_guardados ? (Number(d.dados_guardados_min) || 0) * 60000 : 0); }   // 14/10/2026: dado guardado (o banco falhou) fica com a idade real: "Atualizado às" certo e, com mais de 30 min, não é usado
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
          AND m.content IS NOT NULL   -- 14/10/2026: mesma regra do Tickets Atual e do /eu (anexo sozinho, sem texto, não conta)
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
    const mediaTj = (k) => { let s = 0, p = 0; (d.dados || []).forEach(x => { const v = parseFloat(x[k + '_medio_minutos']) || 0, q = x[k + '_qtd'], peso = q != null ? (parseInt(q) || 0) : (v > 0 ? (parseInt(x.tickets) || 0) : 0); if (peso > 0) { s += v * peso; p += peso; } }); return p ? s / p : 0; };   // 14/10/2026: TMC/TMR do time = média só de quem tem a medida, pesada pela base de respostas (tmc_qtd/tmr_qtd), como nos cards do Dash (antes o agente sem medida contava como zero)
    return { tickets: r.tickets != null ? r.tickets : tks, retornos: r.retornos != null ? r.retornos : rets, mensagens: r.mensagens != null ? r.mensagens : msgs, tmc: mediaTj('tmc'), tmr: mediaTj('tmr') };   // 14/10/2026: tmc/tmr pela mediaTj
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
    if (Date.now() < FREIO.ate) return;   // 14/10/2026: banco com freio: os envios agendados esperam o freio passar (as janelas são de 15 min) em vez de sair com dado guardado
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
            // 14/10/2026: só escala depois que o aviso do agente foi confirmado (falha passageira repete o aviso na rodada seguinte sem escalar o líder em dobro)
            for (const l of lideres.filter(x => x.turno === v.turno && tgNoTurno(x.turno, a) && (r.ok || tgFalhaDefinitiva(r)))) {   // escalonamento: líder do MESMO turno, só no horário dele
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
    if (tgBot.ligado && !tgBot.carregado && !tgBot.rodando) { tgBot.rodando = true; try { await tgCarregarPlanilha(); } finally { tgBot.rodando = false; } return; }   // 14/10/2026: a planilha não foi lida ao ligar: tenta de novo a cada minuto (sem ler, o bot não atende nem regrava a aba)
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
        if (!tgBot.carregado) { await tgEsperar(5000); continue; }   // 14/10/2026: só lê as mensagens depois de carregar os vínculos (antes, um agente já vinculado virava pedido novo e regravava a aba só com ele)
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
            bot: { configurado: !!TG_TOKEN, desativado: !TG_ATIVO, ligado: tgBot.ligado, usuario: tgBot.usuario, nome: tgBot.nome, ultimo_poll: tgBot.ultimoPoll, ultimo_erro: tgBot.ultimoErro, erro_em: tgBot.erroEm, planilha_ok: tgBot.planilhaOk, planilha_configurada: !!tgSheets(), iniciado_em: tgBot.iniciadoEm, agora: tgAgoraBR().texto, fila_planilha: Object.values(tgBot.fila).reduce((s, l) => s + l.length, 0) },
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
setTimeout(() => {
    if (!TG_ATIVO) { console.warn('[telegram] bot DESATIVADO: sem avisos, sem rodadas e sem consulta por tempo. Religar: TELEGRAM_ATIVO=1 no Render.'); return; }
    tgIniciar().catch(e => console.error('[telegram] falha ao iniciar:', e.message));
}, 5000);
// 🛡️ 16/10/2026: erro inesperado (URL malformada, JSON inválido, falha não tratada) não mostra pilha nem caminho de arquivo — o detalhe fica só no log
app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    const st = Number(err && (err.status || err.statusCode)) || 500;
    console.error('[erro]', req.method, req.originalUrl.slice(0, 120), '→', st, err && err.message);
    const msg = st >= 500 ? 'Erro interno do servidor.' : 'Pedido inválido.';
    if (req.originalUrl.startsWith('/api/')) return res.status(st).json({ success: false, ok: false, error: msg, erro: msg });
    res.status(st).type('text').send(msg);
});
