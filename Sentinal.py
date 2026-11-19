import time
import random
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
from collections import defaultdict

# ==============================================================================
# 1. REGRAS DE CIBERSEGURANÇA (MITRE ATT&CK + PLAYBOOK SOAR)
# ==============================================================================
REGRAS_ATAQUE = {
    "BRUTE_FORCE": {
        "mitre": "T1110.001 - Brute Force",
        "severidade": "ALTA",
        "acao": "IP bloqueado automaticamente no Firewall de borda e MFA exigido."
    },
    "SQL_INJECTION": {
        "mitre": "T1190 - Exploit Public App (SQLi)",
        "severidade": "CRÍTICA",
        "acao": "Sessão encerrada, payload bloqueado no WAF e alerta enviado ao SOC."
    },
    "PRIV_ESCALATION": {
        "mitre": "T1068 - Privilege Escalation",
        "severidade": "CRÍTICA",
        "acao": "Conta suspensa imediatamente e chaves SSH revogadas."
    }
}

TRAFEGO_REDE = [
    ("192.168.1.15", "ana.silva", "LOGIN_OK", "Acesso corporativo via SSO"),
    ("192.168.1.22", "joao.ti", "ARQUIVO_LIDO", "auditoria_iso27001.pdf"),
    ("185.220.101.4", "desconhecido", "WEB_REQUEST", "/login?user=admin' OR 1=1--"),
    ("10.0.0.48", "estagiario.dev", "SUDO_EXEC", "chmod 777 /etc/shadow"),
    ("45.33.22.11", "admin", "LOGIN_FALHA", "Senha incorreta"),
    ("192.168.1.30", "maria.rh", "LOGIN_OK", "Acesso ao portal interno"),
]

# Estado global compartilhado entre o motor de segurança e o painel frontend
ESTADO_SOC = {
    "eventos_analisados": 0,
    "ataques_bloqueados": 0,
    "criticos": 0,
    "altos": 0,
    "alertas": [],
    "logs_recentes": []
}

# ==============================================================================
# 2. FRONTEND HTML/CSS/JS EMBUTIDO (DASHBOARD SOC EM TEMPO REAL)
# ==============================================================================
HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fluxus Sentinel — SOC Dashboard</title>
    <style>
        :root {
            --bg: #0b0f19;
            --card: #131a2a;
            --border: #1e293b;
            --text: #e2e8f0;
            --muted: #94a3b8;
            --cyan: #38bdf8;
            --red: #ef4444;
            --yellow: #f59e0b;
            --green: #10b981;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, sans-serif; }
        body { background: var(--bg); color: var(--text); padding: 24px; }
        header {
            display: flex; justify-content: space-between; align-items: center;
            border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px;
        }
        .title { font-size: 1.5rem; font-weight: 700; color: var(--cyan); display: flex; align-items: center; gap: 10px; }
        .live-badge {
            background: rgba(16, 185, 129, 0.15); color: var(--green); border: 1px solid var(--green);
            padding: 4px 12px; border-radius: 20px; font-size: 0.85rem; font-weight: 600;
            animation: pulse 2s infinite;
        }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .grid-cards {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px; margin-bottom: 24px;
        }
        .card {
            background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px;
        }
        .card-label { color: var(--muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }
        .card-value { font-size: 2rem; font-weight: 700; margin-top: 8px; }
        .val-cyan { color: var(--cyan); }
        .val-red { color: var(--red); }
        .val-yellow { color: var(--yellow); }
        .val-green { color: var(--green); }
        .layout-main { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
        @media (max-width: 900px) { .layout-main { grid-template-columns: 1fr; } }
        .panel {
            background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px;
            max-height: 550px; overflow-y: auto;
        }
        .panel h2 { font-size: 1.1rem; margin-bottom: 16px; color: var(--text); border-bottom: 1px solid var(--border); padding-bottom: 10px; }
        .alert-item {
            background: rgba(15, 23, 42, 0.8); border-left: 4px solid var(--red);
            padding: 14px; border-radius: 6px; margin-bottom: 12px;
        }
        .alert-item.ALTA { border-left-color: var(--yellow); }
        .alert-header { display: flex; justify-content: space-between; font-weight: 700; margin-bottom: 6px; }
        .badge-sev { padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; }
        .sev-CRÍTICA { background: rgba(239, 68, 68, 0.2); color: var(--red); }
        .sev-ALTA { background: rgba(245, 158, 11, 0.2); color: var(--yellow); }
        .alert-meta { font-size: 0.85rem; color: var(--muted); margin-bottom: 6px; }
        .alert-soar { font-size: 0.85rem; color: var(--green); background: rgba(16, 185, 129, 0.08); padding: 6px 10px; border-radius: 4px; }
        .log-line {
            font-family: 'Consolas', monospace; font-size: 0.82rem; padding: 8px 0;
            border-bottom: 1px solid rgba(30, 41, 59, 0.6); color: var(--muted);
        }
        .log-ok { color: var(--green); }
        .log-warn { color: var(--yellow); }
        .log-crit { color: var(--red); font-weight: bold; }
    </style>
</head>
<body>
    <header>
        <div class="title">🛡️ FLUXUS SENTINEL — SOC & SOAR MONITOR</div>
        <div class="live-badge">● MONITORAMENTO ATIVO</div>
    </header>

    <div class="grid-cards">
        <div class="card">
            <div class="card-label">Eventos Analisados</div>
            <div class="card-value val-cyan" id="kpi-eventos">0</div>
        </div>
        <div class="card">
            <div class="card-label">Ataques Bloqueados</div>
            <div class="card-value val-green" id="kpi-bloqueados">0</div>
        </div>
        <div class="card">
            <div class="card-label">Incidentes Críticos</div>
            <div class="card-value val-red" id="kpi-criticos">0</div>
        </div>
        <div class="card">
            <div class="card-label">Incidentes Severidade Alta</div>
            <div class="card-value val-yellow" id="kpi-altos">0</div>
        </div>
    </div>

    <div class="layout-main">
        <div class="panel">
            <h2>🚨 Incidentes Detectados & Resposta Automática (MITRE ATT&CK)</h2>
            <div id="lista-alertas">Aguardando detecção de ameaças...</div>
        </div>
        <div class="panel">
            <h2>📡 Telemetria de Rede ao Vivo</h2>
            <div id="lista-logs"></div>
        </div>
    </div>

    <script>
        async function atualizarPainel() {
            try {
                const res = await fetch('/api/dados');
                const dados = await res.json();

                document.getElementById('kpi-eventos').innerText = dados.eventos_analisados;
                document.getElementById('kpi-bloqueados').innerText = dados.ataques_bloqueados;
                document.getElementById('kpi-criticos').innerText = dados.criticos;
                document.getElementById('kpi-altos').innerText = dados.altos;

                const containerAlertas = document.getElementById('lista-alertas');
                if (dados.alertas.length > 0) {
                    containerAlertas.innerHTML = dados.alertas.slice().reverse().map(a => `
                        <div class="alert-item ${a.severidade}">
                            <div class="alert-header">
                                <span>${a.mitre_attack}</span>
                                <span class="badge-sev sev-${a.severidade}">${a.severidade} • ${a.hora}</span>
                            </div>
                            <div class="alert-meta">
                                <strong>IP Origem:</strong> ${a.ip_origem} | <strong>Alvo:</strong> ${a.usuario}<br>
                                <strong>Detalhe:</strong> ${a.detalhe}
                            </div>
                            <div class="alert-soar">⚡ <strong>Ação SOAR:</strong> ${a.resposta_automatica}</div>
                        </div>
                    `).join('');
                }

                const containerLogs = document.getElementById('lista-logs');
                containerLogs.innerHTML = dados.logs_recentes.slice().reverse().map(l => `
                    <div class="log-line ${l.classe}">${l.texto}</div>
                `).join('');
            } catch (e) {
                console.error("Erro ao sincronizar telemetria:", e);
            }
        }
        setInterval(atualizarPainel, 1000);
        atualizarPainel();
    </script>
</body>
</html>
"""

# ==============================================================================
# 3. MOTOR DE DETECÇÃO SIEM & SOAR
# ==============================================================================
class FluxusSentinelEngine:
    def __init__(self):
        self.tentativas_falhas = defaultdict(int)

    def registrar_log_tela(self, texto, classe="log-ok"):
        ESTADO_SOC["logs_recentes"].append({"texto": texto, "classe": classe})
        if len(ESTADO_SOC["logs_recentes"]) > 30:
            ESTADO_SOC["logs_recentes"].pop(0)

    def analisar_evento(self, ip, usuario, acao, payload):
        ESTADO_SOC["eventos_analisados"] += 1
        hora = datetime.now().strftime("%H:%M:%S")

        # Regra 1: Brute Force
        if acao == "LOGIN_FALHA":
            self.tentativas_falhas[ip] += 1
            if self.tentativas_falhas[ip] >= 3:
                self.disparar_alerta(hora, "BRUTE_FORCE", ip, usuario, "3 tentativas falhas consecutivas")
                self.tentativas_falhas[ip] = 0
            else:
                self.registrar_log_tela(f"[{hora}] AVISO: Falha login ({self.tentativas_falhas[ip]}/3) | {ip}", "log-warn")
            return

        # Regra 2: SQL Injection
        if "OR 1=1" in payload or "UNION SELECT" in payload:
            self.disparar_alerta(hora, "SQL_INJECTION", ip, usuario, f"Payload: {payload}")
            return

        # Regra 3: Escalonamento de Privilégio
        if acao == "SUDO_EXEC" and usuario != "admin":
            self.disparar_alerta(hora, "PRIV_ESCALATION", ip, usuario, f"Comando: {payload}")
            return

        # Evento Normal
        self.registrar_log_tela(f"[{hora}] OK: {acao} | {ip} ({usuario})", "log-ok")

    def disparar_alerta(self, hora, tipo, ip, usuario, detalhe):
        regra = REGRAS_ATAQUE[tipo]
        ESTADO_SOC["ataques_bloqueados"] += 1
        if regra["severidade"] == "CRÍTICA":
            ESTADO_SOC["criticos"] += 1
        else:
            ESTADO_SOC["altos"] += 1

        incidente = {
            "hora": hora,
            "severidade": regra["severidade"],
            "mitre_attack": regra["mitre"],
            "ip_origem": ip,
            "usuario": usuario,
            "detalhe": detalhe,
            "resposta_automatica": regra["acao"]
        }

        ESTADO_SOC["alertas"].append(incidente)
        if len(ESTADO_SOC["alertas"]) > 25:
            ESTADO_SOC["alertas"].pop(0)

        self.registrar_log_tela(f"[{hora}] 🚨 BLOQUEADO: {regra['mitre']} ({ip})", "log-crit")
        print(f"[{hora}] 🚨 ALERTA [{regra['severidade']}] {regra['mitre']} | IP: {ip}")

        with open("relatorio_incidentes.json", "a", encoding="utf-8") as f:
            f.write(json.dumps(incidente, ensure_ascii=False) + "\n")

    def loop_monitoramento(self):
        while True:
            if random.random() < 0.30:
                for _ in range(3):
                    self.analisar_evento("45.33.22.11", "admin", "LOGIN_FALHA", "Senha incorreta")
                    time.sleep(0.5)
            else:
                ip, usuario, acao, payload = random.choice(TRAFEGO_REDE)
                self.analisar_evento(ip, usuario, acao, payload)
                time.sleep(1.2)

# ==============================================================================
# 4. SERVIDOR WEB LOCAL PARA O PAINEL FRONTEND
# ==============================================================================
class PainelHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD.encode("utf-8"))
        elif self.path == "/api/dados":
            self.send_response(200)
            self.send_header("Content-type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(ESTADO_SOC, ensure_ascii=False).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Silencia logs HTTP padrão para manter o terminal limpo

if __name__ == "__main__":
    PORTA = 8080
    motor = FluxusSentinelEngine()

    # Inicia o motor de detecção em segundo plano
    thread_motor = threading.Thread(target=motor.loop_monitoramento, daemon=True)
    thread_motor.start()

    servidor = HTTPServer(("localhost", PORTA), PainelHandler)
    url = f"http://localhost:{PORTA}"
    print(f"🛡️  Fluxus Sentinel iniciado! Abrindo painel visual em: {url}")
    print("Pressione Ctrl+C no terminal para encerrar.")

    # Abre automaticamente no navegador padrão
    webbrowser.open(url)

    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor encerrado. Relatório salvo em relatorio_incidentes.json")
        servidor.server_close()