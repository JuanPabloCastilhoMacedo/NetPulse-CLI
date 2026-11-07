# 🌐 NetPulse-CLI
![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![Version](https://img.shields.io/badge/Version-1.1.0-green.svg)
![Focus](https://img.shields.io/badge/Focus-Redes_%26_VoIP-orange.svg)
![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)

Ferramenta de linha de comando (CLI) em Python para diagnóstico de redes locais, descoberta de dispositivos conectados, análise de qualidade de conexão para chamadas de voz (VoIP / Telefonia IP) e monitoramento contínuo com alertas via Telegram (Modo NOC).

---

## 💡 Por que criei este projeto?

Trabalhando na área de **Telefonia Fixa** e estudando **Redes de Computadores**, percebi na prática como essas duas áreas se uniram: hoje, a telefonia corporativa roda quase inteiramente dentro da rede de computadores (VoIP).

Quando uma ligação fica picotando, com voz robotizada ou com atraso, nem sempre o problema é o aparelho telefônico — muitas vezes é a própria rede sofrendo com oscilação (**Jitter**) ou perda de pacotes. Criei o **NetPulse-CLI** para unir meus estudos de Python e Redes em uma ferramenta prática que diagnostica a saúde da rede, responde rápido se um link está bom para chamadas e agora também opera como um **Guardião de NOC 24/7**, alertando operadores no Telegram se o link degradar.

---


## 🛠️ O que cada comando faz na prática?

### 1. `netpulse discover --ports` (O Radar da Rede)
Descobre quais aparelhos estão ligados na mesma rede local (roteadores, computadores, celulares, impressoras ou telefones IP).
- Se você não informar a faixa de IP, ele descobre a sua rede local sozinho (ex: `192.168.0.0/24`).
- Com a flag `--ports` (ou `-p`), ele testa as portas mais comuns de gerência de rede e telefonia IP nos aparelhos encontrados:
  - **Gerência e Redes:** `22` (SSH), `23` (Telnet), `53` (DNS), `80/443` (Painel Web HTTP/HTTPS), `161` (SNMP), `3389` (Área de Trabalho Remota), `8080` (HTTP-Alt).
  - **Telefonia IP (VoIP):** `5060` e `5061` (Protocolo SIP usado por centrais PABX e telefones IP).
```text
netpulse discover --ports
```

### 2. `netpulse watch` (Modo NOC - Monitoramento Contínuo com Alertas no Telegram)
Transforma o terminal em uma central de monitoramento em tempo real (NOC) para gateways, troncos SIP ou enlaces de operadora.
- **Medição Contínua:** A cada ciclo (ex: 10s), calcula Latência, Jitter, Perda e **MOS Score** em tempo real.
- **Controle Anti-Spam Inteligente:** Se o link cair (**OFFLINE**) ou a nota MOS ficar abaixo da meta (ex: `--mos-threshold 3.5`), o NetPulse dispara um alerta imediato no Telegram com relatório técnico. Ele **não** repete a notificação enquanto o link continuar ruim, e emite automaticamente um aviso de **RECUPERADO** assim que o enlace normalizar.
- **Validação Imediata:** Use a flag `--test-alert` para enviar um ping de teste no bot antes de iniciar o monitoramento.
```text
netpulse watch pbx.empresa.com --mos-threshold 3.5 --test-alert
```

---

## 🤖 Configurando Alertas no Telegram (Modo NOC)

Para receber notificações no seu smartphone ou canal do Telegram:
1. Abra o Telegram e inicie uma conversa com o [@BotFather](https://t.me/BotFather) para criar seu bot e obter o `TELEGRAM_TOKEN`.
2. Inicie uma conversa com o bot criado e obtenha o seu `TELEGRAM_CHAT_ID` (usando o bot [@userinfobot](https://t.me/userinfobot) ou acessando `https://api.telegram.org/bot<TOKEN>/getUpdates`).
3. Copie o arquivo de exemplo para `.env` e configure suas chaves:
```bash
cp .env.example .env
```
Edite o arquivo `.env`:
```env
TELEGRAM_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHAT_ID=123456789
```
*O NetPulse carrega o `.env` automaticamente sem precisar instalar dependências extras.*

---

## 🚀 Instalação e Uso Rápido

### 1. Clonar o Repositório e Configurar o Ambiente

~~~bash
# Clonar o repositório
git clone https://github.com/seu-usuario/NetPulse-CLI.git
cd NetPulse-CLI

# Criar o ambiente virtual isolado
python -m venv .venv

# Ativar o ambiente virtual
# No Linux / macOS:
source .venv/bin/activate
# No Windows (PowerShell):
.venv\Scripts\Activate.ps1
# No Windows (CMD):
.venv\Scripts\activate.bat

# Atualizar o gerenciador de pacotes e instalar em modo editável
pip install --upgrade pip
pip install -e .
~~~

### 2. Comandos Práticos

~~~bash
# 1. Monitoramento contínuo (Modo NOC) com alertas no Telegram
netpulse watch 10.0.0.1 --interval 10 --mos-threshold 3.5

# 2. Testar conectividade do Bot do Telegram antes de monitorar
netpulse watch 8.8.8.8 --test-alert

# 3. Descoberta de hosts na rede local com auditoria de portas
netpulse discover --ports

# 4. Diagnóstico de SLA VoIP para gateway corporativo usando G.711 e gerando laudo JSON
netpulse quality 8.8.8.8 --codec g711 -o laudo.json

# 5. Diagnóstico de VoIP com codec de alta compressão G.729
netpulse quality 1.1.1.1 --codec g729

# 6. Rastreamento detalhado salto a salto de rota (Traceroute)
netpulse trace 8.8.8.8

# 7. Teste estatístico contínuo de latência e perda (Ping)
netpulse ping 8.8.8.8 -c 10
~~~

### ✍️ DESENVOLVEDOR: Juan Pablo Castilho Macêdo
