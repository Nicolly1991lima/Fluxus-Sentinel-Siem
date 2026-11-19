# 🛡️ Fluxus Sentinel — Sistema de Detecção, Resposta (SIEM/SOAR) & Painel SOC

Plataforma completa de monitoramento de segurança cibernética em tempo real desenvolvida em **Python puro** (*zero dependências externas*) com **Dashboard Web SOC integrado**. O sistema ingere eventos de rede e autenticação corporativa, detecta intrusões mapeando-as na matriz **MITRE ATT&CK**, executa playbooks automatizados de contenção (**SOAR**), atualiza um painel visual em tempo real no navegador e exporta evidências forenses estruturadas em JSON.

---

## 📸 Preview do Painel SOC (Frontend)

> *(Dica: Tire um print da tela do painel aberto no seu navegador, salve como `dashboard.png` na pasta do projeto e suba junto com o código para a imagem aparecer automaticamente aqui!)*

![<img width="1240" height="746" alt="Captura de tela_18-11-2026_214712_localhost" src="https://github.com/user-attachments/assets/7b89e93d-a0a8-4292-ac6e-246bf1c9988b" />
](dashboard.png)

---

## 🎯 Arquitetura & Funcionalidades

* **Dashboard Web SOC em Tempo Real (`Frontend`):** Interface responsiva em *Dark Mode* servida localmente via HTTP nativo, consumindo a API interna (`/api/dados`) a cada segundo para atualizar KPIs de eventos analisados, ataques bloqueados, distribuição de severidade e feed de telemetria ao vivo.
* **Motor Multithread de Detecção (`Backend SIEM`):** Processamento paralelo entre a análise contínua de logs e a interface web sem bloqueio de I/O.
* **Mapeamento MITRE ATT&CK®:** Classificação automática das técnicas adversárias:
  * `T1110.001` — **Brute Force:** Correlação de múltiplas falhas consecutivas de autenticação originadas do mesmo IP.
  * `T1190` — **Exploit Public-Facing Application (SQL Injection):** Inspeção de payloads HTTP em busca de assinaturas maliciosas (`OR 1=1`, `UNION SELECT`).
  * `T1068` — **Privilege Escalation:** Detecção de tentativas não autorizadas de elevação de privilégio administrativo (`sudo`).
* **Playbooks Automatizados (`SOAR`):** Resposta imediata com ações de contenção (bloqueio em Firewall/WAF, revogação de sessões/chaves SSH e exigência de MFA).
* **Exportação Forense (`relatorio_incidentes.json`):** Registro automático de cada incidente em JSON estruturado, pronto para auditoria ou ingestão por ferramentas de *ticketing* e SIEM corporativos.

---

## 🚀 Como Executar (Zero Dependências)

Este projeto utiliza exclusivamente a biblioteca padrão do Python 3 (`http.server`, `threading`, `json`, `collections`, `webbrowser`), dispensando ambientes virtuais ou pacotes externos.

1. **Clone o repositório:**
   ```bash
   git clone [https://github.com/seu-usuario/fluxus-sentinel.git](https://github.com/seu-usuario/fluxus-sentinel.git)
   cd fluxus-sentinel
