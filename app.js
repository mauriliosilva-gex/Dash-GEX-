// =============================================
// ANALYST DASHBOARD 2.0 — app.js
// =============================================

document.addEventListener('DOMContentLoaded', () => {
    iniciarRelogio();
    inicializarGrafico();
});

// ============ TABS (Tailwind Toggle) ============
function setTab(tabNome) {
    // Esconde todas
    document.getElementById('tab-ranking').classList.add('hidden');
    document.getElementById('tab-tickets').classList.add('hidden');
    
    // Reseta botões
    document.getElementById('tab-btn-ranking').className = "px-5 py-2.5 text-sm font-semibold border-b-2 border-transparent text-texto2 hover:text-texto1 transition-colors";
    document.getElementById('tab-btn-tickets').className = "px-5 py-2.5 text-sm font-semibold border-b-2 border-transparent text-texto2 hover:text-texto1 transition-colors";

    // Mostra a selecionada
    document.getElementById(`tab-${tabNome}`).classList.remove('hidden');
    document.getElementById(`tab-btn-${tabNome}`).className = "px-5 py-2.5 text-sm font-semibold border-b-2 border-iePurple text-iePurple transition-colors";
}

// ============ RELÓGIO ============
function iniciarRelogio() {
    const el = document.getElementById('relogio');
    setInterval(() => el.textContent = new Date().toLocaleTimeString('pt-BR'), 1000);
}

// ============ CHART.JS (Visualização da Meta) ============
function inicializarGrafico() {
    const ctx = document.getElementById('metaChart').getContext('2d');
    
    // Configuração de cores para combinar com o Dark Mode
    Chart.defaults.color = '#555e7a';
    Chart.defaults.borderColor = '#252a38';

    new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta'],
            datasets: [
                {
                    label: 'Ritmo Ideal (Meta 400)',
                    data: [80, 160, 240, 320, 400], // Linha reta até 400
                    borderColor: '#555e7a',
                    borderDash: [5, 5],
                    borderWidth: 2,
                    fill: false,
                    tension: 0
                },
                {
                    label: 'Média da Equipe Atual',
                    data: [85, 150, 260], // Exemplo: Dados até quarta-feira
                    borderColor: '#34d399', // Verde Emerald do Tailwind
                    backgroundColor: 'rgba(52, 211, 153, 0.1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.3
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom' }
            },
            scales: {
                y: { beginAtZero: true, max: 450 }
            }
        }
    });
}