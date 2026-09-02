require('dotenv').config();
const { google } = require('googleapis');

// 1. Configuração de Autenticação do Google
const auth = new google.auth.GoogleAuth({
  credentials: {
    client_email: process.env.GOOGLE_CLIENT_EMAIL,
    // O replace garante que as quebras de linha da chave privada sejam lidas corretamente
    private_key: process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  },
  scopes: ['https://www.googleapis.com/auth/spreadsheets'],
});

const sheets = google.sheets({ version: 'v4', auth });

// 2. Criação dos Dados Fictícios (Mock) - Foco na Retenção
const mockTicketsRetencao = [
  ['TCK-1001', '2026-08-29', 'RET', '150.00', 'Revertido', 'Insatisfação com o produto', '5'],
  ['TCK-1002', '2026-08-29', 'RET', '300.00', 'Falha', 'Problema financeiro', '4'],
  ['TCK-1003', '2026-08-29', 'RET', '50.00', 'Revertido', 'Atraso na entrega', '5'],
  ['TCK-1004', '2026-08-29', 'RET', '800.00', 'Revertido', 'Dúvida técnica', '5'],
  ['TCK-1005', '2026-08-29', 'RET', '120.00', 'Falha', 'Não utiliza mais', '3'],
  ['TCK-1006', '2026-08-29', 'RET', '450.00', 'Revertido', 'Problema financeiro', '4']
];

// 3. Função para Injetar os Dados na Planilha
async function popularPlanilhaFake() {
  try {
    const spreadsheetId = process.env.GOOGLE_SHEET_ID;
    
    // Ajuste "Página1" se o nome da aba da sua planilha for diferente
    const range = 'Página1!A2'; 

    console.log('🔄 Iniciando envio de dados para o Google Sheets...');

    const response = await sheets.spreadsheets.values.append({
      spreadsheetId,
      range,
      valueInputOption: 'USER_ENTERED', // Interpreta os números e datas corretamente
      requestBody: {
        values: mockTicketsRetencao,
      },
    });

    console.log('✅ Dados fictícios inseridos com sucesso!');
    console.log(`📊 ${response.data.updates.updatedCells} células foram atualizadas no seu "banco de dados".`);
    
  } catch (error) {
    console.error('❌ Erro ao inserir dados no Sheets:', error.message);
  }
}

// Executa a função
popularPlanilhaFake();