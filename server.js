const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
require('dotenv').config();
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { Pool } = require('pg');

const app = express();

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

// 🔥 OTIMIZAÇÃO EXTREMA: Query direta usando os índices do banco de dados
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
// 2. ROTA PARA O UPTIMEROBOT E AUTH GOOGLE
// ==========================================
app.get('/ping', (req, res) => res.status(200).send('Servidor GEX Ativo!'));

app.set('trust proxy', 1);

app.use(session({
    secret: process.env.SESSION_SECRET || 'chave_reserva_gex',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } 
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

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/erro-login' }), (req, res) => { res.redirect('/'); });

app.get('/erro-login', (req, res) => {
    res.send(`<div style="font-family: sans-serif; text-align: center; margin-top: 50px; background-color: #020617; color: white; height: 100vh; padding-top: 100px;"><h1 style="color: #ef4444;">Acesso Negado</h1><p>Você precisa utilizar um e-mail corporativo válido.</p><br><a href="/auth/google" style="padding: 12px 24px; background: #22a7f0; color: white; text-decoration: none; border-radius: 8px; font-weight: bold;">Tentar Novamente</a></div>`);
});

const verificarLogin = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.redirect('/auth/google');
};

// ==========================================
// 4.5. SISTEMA DE CACHE (ESCUDO DE PERFORMANCE)
// ==========================================
const cacheMemoria = {};
const TEMPO_CACHE_MINUTOS = 30; // Atualiza apenas 1 vez a cada 30 minutos

const cacheMiddleware = (req, res, next) => {
    const chaveUrl = req.originalUrl; 
    const agora = Date.now();

    // Se a informação já está na memória e tem menos de 30 min, devolve instantaneamente
    if (cacheMemoria[chaveUrl] && (agora - cacheMemoria[chaveUrl].tempo < TEMPO_CACHE_MINUTOS * 60 * 1000)) {
        console.log(`⚡ Retornando do Cache em 0s: ${chaveUrl}`);
        return res.json(cacheMemoria[chaveUrl].data);
    }

    // Se for novo ou venceu os 30 min, vai no banco buscar e salva na memória
    const sendJsonOriginal = res.json;
    res.json = function(dados) {
        if (dados && dados.success) {
            cacheMemoria[chaveUrl] = { tempo: agora, data: dados };
            console.log(`🔄 Banco Atualizado e Cache Salvo: ${chaveUrl}`);
        }
        sendJsonOriginal.call(this, dados);
    };
    next();
};

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
        const mesPlanilha = 7; 
        const diasNoMesPlanilha = new Date(anoPlanilha, mesPlanilha + 1, 0).getDate(); 
        const dInicioMes = new Date(anoPlanilha, mesPlanilha, 1);
        const dFimMes = new Date(anoPlanilha, mesPlanilha + 1, 0);

        let dInicioGraf, dFimGraf;
        if (req.query.since && req.query.until) {
            dInicioGraf = new Date(parseInt(req.query.since) * 1000);
            dFimGraf = new Date(parseInt(req.query.until) * 1000);
        } else {
            const qtdMeses = req.query.meses ? parseInt(req.query.meses) : 2;
            dInicioGraf = new Date(anoPlanilha, mesPlanilha - (qtdMeses - 1), 1);
            dFimGraf = new Date(anoPlanilha, mesPlanilha + 1, 0); 
        }

        const domingoBase = new Date(dInicioGraf.getTime());
        domingoBase.setUTCDate(dInicioGraf.getUTCDate() - dInicioGraf.getUTCDay());
        const diffMsTotal = dFimGraf.getTime() - domingoBase.getTime();
        const totalSemanas = Math.max(1, Math.floor((diffMsTotal / (1000 * 60 * 60 * 24)) / 7) + 1);

        const [resultTicketsMes, resultTicketsGraf] = await Promise.all([
            pool.query(queryTickets, [formatarDataSQL(dInicioMes), formatarDataSQL(dFimMes)]),
            pool.query(queryTickets, [formatarDataSQL(dInicioGraf), formatarDataSQL(dFimGraf)])
        ]);

        const ticketsMap = {};
        resultTicketsMes.rows.forEach(row => {
            const nomeBase = normalizeNome(row.agente);
            if (!ticketsMap[nomeBase]) ticketsMap[nomeBase] = { totalMes: 0, hist_tickets: new Array(totalSemanas).fill(0) };
            ticketsMap[nomeBase].totalMes += parseInt(row.tickets) || 0;
        });

        resultTicketsGraf.rows.forEach(row => {
            const nomeBase = normalizeNome(row.agente);
            if (!ticketsMap[nomeBase]) ticketsMap[nomeBase] = { totalMes: 0, hist_tickets: new Array(totalSemanas).fill(0) };
            const dataData = new Date(String(row.dia).split('T')[0] + 'T12:00:00Z');
            const diasAposDomingo = Math.floor((dataData.getTime() - domingoBase.getTime()) / (1000 * 60 * 60 * 24));
            const semanaIndex = Math.floor(diasAposDomingo / 7);
            if (semanaIndex >= 0 && semanaIndex < totalSemanas) {
                ticketsMap[nomeBase].hist_tickets[semanaIndex] += parseInt(row.tickets) || 0;
            }
        });

        let privateKey = (process.env.GOOGLE_PRIVATE_KEY || '').replace(/\\n/g, '\n').replace(/"/g, '').trim();
        const auth = new google.auth.GoogleAuth({
            credentials: { client_email: (process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || '').trim(), private_key: privateKey },
            scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
        });
        const sheets = google.sheets({ version: 'v4', auth });
        const sheetId = (process.env.GOOGLE_SHEET_ID || '').trim();
        const nomeAba = "📊 Análise | Metas | Agosto"; 

        const response = await sheets.spreadsheets.values.get({ spreadsheetId: sheetId, range: `'${nomeAba}'!A1:T300` });
        const rows = response.data.values || [];
        
        let metaTrvGlobal = 70.00, trvMedioGlobal = 0, metaMesGlobal = 0, recuperadoGlobal = 0, faltamGlobal = 0, metaMinCasosGlobal = 0;
        if (rows[5]) {
            metaTrvGlobal = parsePct(rows[5][3] || rows[5][2]);
            trvMedioGlobal = parsePct(rows[5][5] || rows[5][4]);
            metaMesGlobal = parseMoeda(rows[5][9] || rows[5][8]);
            recuperadoGlobal = parseMoeda(rows[5][11] || rows[5][10]);
            faltamGlobal = parseMoeda(rows[5][15] || rows[5][14]);
            metaMinCasosGlobal = parseMoeda(rows[5][17] || rows[5][16]);
        }
        
        let idCounter = 1;
        const agentes = rows.slice(10).filter(r => String(r[3] || r[2] || '').trim() !== '' && parseMoeda(r[6] || r[7]) > 0).map(row => {
            const nomePlanilha = String(row[3] || row[2] || '').trim(); 
            const meta_casos = parseMoeda(row[4] || row[3]);
            const casosAtual = parseMoeda(row[6] || row[7]);          
            const refund = parseMoeda(row[8] || row[9]);              
            const recuperado = parseMoeda(row[10] || row[11]); 
            const meta_trv_agente = parsePct(row[13] || row[12]);        
            const trv = parsePct(row[15] || row[14]);  
            const status_vol = String(row[17] || row[16] || '').trim();
            const status_trv = String(row[19] || row[18] || '').trim();               

            const ticketsAgente = vincularTickets(nomePlanilha, ticketsMap, totalSemanas);
            const hist_trv = new Array(diasNoMesPlanilha).fill(trv);

            return {
                id: idCounter++, nome: nomePlanilha, time: 'RET', 
                tickets: ticketsAgente.totalMes, 
                hist_tickets: ticketsAgente.hist_tickets, 
                meta_casos: meta_casos, casos_atual: casosAtual, refund: refund, recuperado: recuperado, meta_trv_agente: meta_trv_agente,
                trv: trv, status_vol: status_vol, status_trv: status_trv, qual: 0, score: trv, hist_trv: hist_trv
            };
        });

        agentes.sort((a, b) => b.score - a.score);
        const globais = { meta_trv: metaTrvGlobal, trv_medio: trvMedioGlobal, meta_mes: metaMesGlobal, recuperado_total: recuperadoGlobal, faltam: faltamGlobal, meta_minima_casos: metaMinCasosGlobal, dias_mes_atual: diasNoMesPlanilha };
        res.json({ success: true, globais, agentes });

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
        
        const response = await sheets.spreadsheets.values.get({ spreadsheetId: sheetIdQualidade, range: `'BASE_MONITORIA'!A1:Z5000` });
        const rows = response.data.values || [];

        if (rows.length < 4) return res.json({ success: true, meses: [], mesAtual: '', agentes: [] });

        // ---------------------------------------------------------
        // 🔧 MAPEAMENTO EXATO DA PLANILHA DE QUALIDADE
        // A=0, B=1, C=2, D=3, E=4, F=5, G=6, H=7, I=8
        // ---------------------------------------------------------
        const idxSetor = 1; // Coluna B (Ex: Retenção - Email)
        const idxNome  = 2; // Coluna C (Ex: Adevânia Silva)
        const idxNota  = 5; // Coluna F (Ex: 100)
        const idxMes   = 8; // Coluna I (Ex: setembro-2026)

        let mesesSet = new Set();
        let monitoriasGerais = [];

        // O loop começa em 4 porque os dados começam na Linha 5
        for (let i = 4; i < rows.length; i++) {
            const row = rows[i];
            const nomeRaw = String(row[idxNome] || '').trim();
            const mesRaw = String(row[idxMes] || '').trim();
            
            if (!nomeRaw || !mesRaw) continue;
            
            // Remove acentos para bater perfeitamente no sistema
            const nomeFormatado = normalizeNome(nomeRaw);

            mesesSet.add(mesRaw);

            let notaStr = String(row[idxNota] || '0').replace('%', '').replace(',', '.');
            let nota = parseFloat(notaStr) || 0;

            // Traduz setor para sigla oficial
            let setorRaw = String(row[idxSetor] || '').toUpperCase();
            let siglaSetor = 'RET'; // Padrão
            if (setorRaw.includes('SAC')) siglaSetor = 'SAC';
            else if (setorRaw.includes('BKO') || setorRaw.includes('BACKOFFICE')) siglaSetor = 'BKO';
            else if (setorRaw.includes('SMS')) siglaSetor = 'SMS';

            monitoriasGerais.push({ 
                mes: mesRaw, 
                nome: nomeFormatado, 
                time: siglaSetor, 
                qual: nota 
            });
        }

        const meses = Array.from(mesesSet).sort((a, b) => b.localeCompare(a)); 
        const mesSelecionado = req.query.mes || (meses.length > 0 ? meses[0] : '');

        const monitoriasDoMes = monitoriasGerais.filter(m => m.mes === mesSelecionado);

        const agentesAgrupados = {};
        monitoriasDoMes.forEach(m => {
            if (!agentesAgrupados[m.nome]) agentesAgrupados[m.nome] = { nome: m.nome, time: m.time, soma: 0, count: 0 };
            agentesAgrupados[m.nome].soma += m.qual;
            agentesAgrupados[m.nome].count++;
        });

        const resultados = Object.values(agentesAgrupados).map(a => ({ 
            nome: a.nome, 
            time: a.time, 
            qual: a.soma / a.count 
        }));
        
        res.json({ success: true, meses: meses, mesAtual: mesSelecionado, agentes: resultados });

    } catch (error) { 
        console.error("❌ Erro em Qualidade:", error.message);
        res.status(500).json({ success: false, error: error.message }); 
    }
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
            if (!nome.match(/- SAC|- RET|- BKO|- SMS/)) return;
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
            if (!nome.match(/- SAC|- RET|- BKO|- SMS/)) return;
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

const PORT = process.env.PORT || 3003;
app.listen(PORT, () => {
    console.log(`✅ Servidor rodando na porta ${PORT}`);
});
