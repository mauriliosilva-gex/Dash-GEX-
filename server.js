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
// 4.5. SISTEMA DE CACHE INTELIGENTE
// ==========================================
const cacheMemoria = {};

const cacheMiddleware = (req, res, next) => {
    const chaveUrl = req.originalUrl; 
    const agora = Date.now();

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
        
        // ⚠️ ATUALIZAÇÃO MANUAL MENSAL AQUI:
        const anoPlanilha = 2026;
        const mesPlanilha = 7; // 7 = Agosto (Lembrete: 0=Jan, 1=Fev ... 7=Ago, 8=Set)
        const nomeAba = "📊 Análise | Metas | Agosto"; // Nome exato da aba na planilha
        
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
                trv: trv, status_vol: status_vol, status_trv: status_trv, qual: 0, score: 0, hist_trv: hist_trv
            };
        });

        // 🌟 NOVO CÁLCULO DE RANKING PESADO (60% % TRV + 40% $ CASOS)
        const maxTrv = Math.max(...agentes.map(a => a.trv), 1);
        const maxCasos = Math.max(...agentes.map(a => a.casos_atual), 1);

        agentes.forEach(a => {
            const pctTrvRelativo = maxTrv > 0 ? (a.trv / maxTrv) : 0;
            const pctCasosRelativo = maxCasos > 0 ? (a.casos_atual / maxCasos) : 0;
            a.score = ((pctTrvRelativo * 0.60) + (pctCasosRelativo * 0.40)) * 100;
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
            if (setorRaw.includes('SAC')) siglaSetor = 'SAC';
            else if (setorRaw.includes('BKO') || setorRaw.includes('BACKOFFICE')) siglaSetor = 'BKO';
            else if (setorRaw.includes('SMS')) siglaSetor = 'SMS';

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
            if (setorRaw.includes('SAC')) siglaSetor = 'SAC';
            else if (setorRaw.includes('BKO') || setorRaw.includes('BACKOFFICE')) siglaSetor = 'BKO';
            else if (setorRaw.includes('SMS')) siglaSetor = 'SMS';

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
            WHERE c.status IN (0, 2) 
            GROUP BY u.name, i.name
        `;
        const resultDist = await pool.query(qDist);
        
        const distAgentes = {};
        const caixasSet = new Set();
        
        resultDist.rows.forEach(r => {
            let nome = (r.agente || 'SEM ATRIBUIR').toUpperCase();
            if(nome !== 'SEM ATRIBUIR' && !nome.match(/- SAC|- RET|- BKO|- SMS/)) return;
            
            let cx = r.caixa || '(Sem Time)';
            caixasSet.add(cx);
            
            if (!distAgentes[nome]) distAgentes[nome] = { nome, total: 0 };
            distAgentes[nome][cx] = parseInt(r.qtd) || 0;
            distAgentes[nome].total += parseInt(r.qtd) || 0;
        });

        // 2. Query Resumo Casos Agente (Ignorado / Aguardando / Parado / Andamento)
        const qCasos = `
            SELECT 
                u.name AS agente,
                c.status,
                c.last_activity_at,
                COUNT(c.id) AS qtd
            FROM conversations c
            LEFT JOIN users u ON u.id = c.assignee_id
            WHERE c.status IN (0, 2, 3)
            GROUP BY u.name, c.status, c.last_activity_at
        `;
        const resultCasos = await pool.query(qCasos);
        const resCasosMap = {};
        const agora = new Date();
        
        resultCasos.rows.forEach(r => {
            let nome = (r.agente || 'SEM ATRIBUIR').toUpperCase();
            if(nome !== 'SEM ATRIBUIR' && !nome.match(/- SAC|- RET|- BKO|- SMS/)) return;
            if (!resCasosMap[nome]) resCasosMap[nome] = { nome, ignorado: 0, aguardando: 0, parado: 0, andamento: 0, total: 0 };
            
            const qtd = parseInt(r.qtd) || 1;
            const status = parseInt(r.status); // 0=open, 2=pending, 3=snoozed no Chatwoot
            const dtAtividade = new Date(r.last_activity_at);
            const diffDias = (agora - dtAtividade) / (1000 * 60 * 60 * 24);
            
            if (diffDias > 3) {
                resCasosMap[nome].parado += qtd;
            } else if (status === 2) {
                resCasosMap[nome].aguardando += qtd;
            } else if (status === 3) {
                resCasosMap[nome].ignorado += qtd; 
            } else {
                resCasosMap[nome].andamento += qtd;
            }
            resCasosMap[nome].total += qtd;
        });

        res.json({ 
            success: true, 
            distribuicao: Object.values(distAgentes).sort((a,b) => b.total - a.total),
            caixas: Array.from(caixasSet).sort(),
            casos: Object.values(resCasosMap).sort((a,b) => b.total - a.total)
        });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

const PORT = process.env.PORT || 3003;
app.listen(PORT, () => {
    console.log(`✅ Servidor rodando na porta ${PORT}`);
});
