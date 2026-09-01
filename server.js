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

const app = express();

// ==========================================
// 1. BLINDAGEM DE SEGURANÇA BASE
// ==========================================
app.use(helmet({ contentSecurityPolicy: false })); // Protege os cabeçalhos HTTP
app.use(cors());

// Protege a API contra ataques de DDoS e estouro da cota do Google Sheets
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // Máximo de 100 requisições
    message: { success: false, error: "Muitas requisições. Aguarde alguns minutos." }
});
app.use('/api/', limiter);

// ==========================================
// 2. ROTA PARA O UPTIMEROBOT (Manter 24h grátis no Render)
// ==========================================
app.get('/ping', (req, res) => res.status(200).send('Servidor GEX Ativo!'));

// ==========================================
// 3. CONFIGURAÇÃO DO LOGIN COM GOOGLE
// ==========================================
app.set('trust proxy', 1); // Essencial para o Render funcionar com cookies de sessão

app.use(session({
    secret: process.env.SESSION_SECRET || 'chave_reserva_gex',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // Sessão dura 24 horas
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback',
    proxy: true // Importante para o Render não dar erro de HTTP vs HTTPS
},
function(accessToken, refreshToken, profile, cb) {
    const email = profile.emails && profile.emails[0] ? profile.emails[0].value : '';
    
    // AQUI FICA O BLOQUEIO DE DOMÍNIO
    if (email.endsWith('@institutoexperience.com.br')) {
        return cb(null, profile);
    } else {
        return cb(null, false, { message: 'Acesso negado.' });
    }
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Rotas do Fluxo de Login
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/erro-login' }),
    (req, res) => {
        res.redirect('/'); // Se der certo, joga pro Dashboard
    }
);

app.get('/erro-login', (req, res) => {
    res.send(`
        <div style="font-family: sans-serif; text-align: center; margin-top: 50px; background-color: #020617; color: white; height: 100vh; padding-top: 100px;">
            <h1 style="color: #ef4444;">Acesso Negado</h1>
            <p>Você precisa utilizar um e-mail corporativo válido (<b>@institutoexperience.com.br</b>).</p>
            <br>
            <a href="/auth/google" style="padding: 12px 24px; background: #22a7f0; color: white; text-decoration: none; border-radius: 8px; font-weight: bold;">Tentar Novamente</a>
        </div>
    `);
});

// ==========================================
// 4. PROTEÇÃO DAS PÁGINAS E APIS (Cadeado Final)
// ==========================================
const verificarLogin = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.redirect('/auth/google'); // Se não tiver logado, manda pro Google na hora
};

// Trava os dados confidenciais do Sheets
app.use('/api', verificarLogin);

// Trava o painel HTML em si (A pasta 'public' só carrega se passar pela verificação)
app.use(verificarLogin, express.static(path.join(__dirname, 'public')));


// ==========================================
// 5. LÓGICA DO GOOGLE SHEETS (Seu código original mantido intacto)
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

app.get('/api/retencao', async (req, res) => {
    try {
        let privateKey = (process.env.GOOGLE_PRIVATE_KEY || '').replace(/\\n/g, '\n').replace(/"/g, '').trim();

        const auth = new google.auth.GoogleAuth({
            credentials: {
                client_email: (process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || '').trim(),
                private_key: privateKey,
            },
            scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
        });
        
        const sheets = google.sheets({ version: 'v4', auth });
        const sheetId = (process.env.GOOGLE_SHEET_ID || '').trim();
        const nomeAba = "Ranking"; 

        const response = await sheets.spreadsheets.values.get({
            spreadsheetId: sheetId,
            range: `'${nomeAba}'!A2:J300`, 
        });

        const rows = response.data.values || [];
        
        let recuperadoTotal = 0;
        let somaTrv = 0;
        let countTrv = 0;
        let idCounter = 1;
        
        const agentes = rows
            .filter(row => String(row[1] || '').trim() !== '') 
            .map(row => {
                const nome = String(row[1] || '').trim();       
                const casosAtual = parseMoeda(row[3]);          
                const refund = parseMoeda(row[4]);              
                const recuperado = parseMoeda(row[5]);          
                const trv = parsePct(row[7]);                   
                
                recuperadoTotal += recuperado;
                if (trv > 0) {
                    somaTrv += trv;
                    countTrv++;
                }

                return {
                    id: idCounter++, nome: nome, time: 'RET', tickets: 0, 
                    casos_atual: casosAtual, refund: refund, recuperado: recuperado, trv: trv, qual: 0, score: trv,
                    hist_tickets: [0, 0, 0, 0, 0],
                    hist_trv: [trv > 2 ? trv-2 : 0, trv+1, trv-1, trv+2, trv] 
                };
            });

        agentes.sort((a, b) => b.score - a.score);
        const trvMedio = countTrv > 0 ? (somaTrv / countTrv) : 0;

        const globais = { meta_trv: 60.00, trv_medio: trvMedio, recuperado_total: recuperadoTotal, meta_mes: 42884.74 };

        res.json({ success: true, globais, agentes });

    } catch (error) {
        console.error("❌ Erro no Sheets:", error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

const PORT = process.env.PORT || 3003;
app.listen(PORT, () => {
    console.log(`✅ Servidor rodando na porta ${PORT}`);
});