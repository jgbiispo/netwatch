<div align="center">

# 🔭 NetWatch

**Monitor e analisador de segurança de redes com IA**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://python.org)
[![DeepSeek](https://img.shields.io/badge/IA-DeepSeek%20Reasoner-purple)](https://deepseek.com)
[![License](https://img.shields.io/badge/Licença-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Em%20desenvolvimento-orange)]()

</div>

---

## O que é

NetWatch é uma ferramenta de linha de comando para monitoramento e análise de segurança de redes locais. Combina **scan de rede ativo** (ARP, ICMP, TCP) com **análise de IA** via DeepSeek Reasoner para detectar anomalias, dispositivos suspeitos e comportamentos atípicos.

### Funcionalidades principais

| Feature | Descrição |
|---------|-----------|
| 📡 **Scan de rede** | Descobre dispositivos via ARP, ICMP e tabela de roteamento |
| 🔒 **Scan de portas** | Identifica serviços abertos e infere tipo de dispositivo |
| 🤖 **Análise com IA** | DeepSeek Reasoner analisa a rede com Thinking Mode (anti-alucinação) |
| 💬 **Chat interativo** | REPL multi-turn para perguntas em linguagem natural |
| 👁️ **Monitor de alertas** | Detecta eventos em tempo real (novos devices, picos de banda, portas suspeitas) |
| 📊 **Histórico SQLite** | Persiste todos os scans em `~/.netwatch/history.db` |
| 🏴‍☠️ **ARP Spoofing** | MITM passivo para capturar tráfego por dispositivo |

---

## Requisitos

- Python 3.11+
- Linux (usa `ip route`, `ip neigh`, sockets raw)
- Privilégios de root (`sudo`) para ARP scan e spoofing
- API key do [DeepSeek](https://platform.deepseek.com/) (para features de IA)

---

## Instalação

```bash
# Clone o repositório
git clone https://github.com/jgbiispo/netwatch.git
cd netwatch

# Crie e ative o ambiente virtual
python3 -m venv .venv
source .venv/bin/activate

# Instale as dependências
pip install -r requirements.txt

# Configure a API key do DeepSeek
python main.py setup
```

---

## Uso

> ⚠️ A maioria dos comandos requer `sudo` para acesso a raw sockets e ARP.

```bash
sudo .venv/bin/python main.py [COMANDO] [OPÇÕES]
```

---

## Comandos

### `scan` — Scan de dispositivos

Descobre todos os dispositivos na rede local e analisa com IA.

```bash
sudo python main.py scan
sudo python main.py scan --no-port-scan     # scan rápido sem portas
sudo python main.py scan --full             # ARP + DHCP leases + multi-subnets
sudo python main.py scan --no-diff          # sem comparação com scan anterior
sudo python main.py scan --no-ai            # desativa análise IA
```

**Exemplo de saída:**
```
                    Dispositivos na rede
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ IP              ┃ MAC               ┃ Fabricante/Tipo      ┃ Origem ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━┩
│ 192.168.1.1     │ aa:bb:cc:dd:ee:ff │ Roteador/Gateway     │ [scan] │
│ 192.168.1.53    │ de:98:54:93:79:fc │ Apple (MAC priv.)    │ [ARP]  │
└─────────────────┴───────────────────┴──────────────────────┴────────┘

✅ NORMAL — Rede estável. Nenhuma anomalia detectada.
```

---

### `chat` — Chat interativo com IA ⭐

Modo REPL onde você faz perguntas em linguagem natural. Escaneia a rede uma vez e mantém o contexto durante toda a sessão.

```bash
sudo python main.py chat
sudo python main.py chat --full-scan    # scan completo antes do chat
```

**Comandos internos:**

| Comando | Ação |
|---------|------|
| `/rescan` | Refaz o scan e atualiza o contexto da IA |
| `/devices` | Exibe tabela de dispositivos atual |
| `/clear` | Limpa o histórico sem rescanear |
| `/help` | Lista comandos e exemplos |
| `/quit` | Encerra o chat |

**Exemplo de conversa:**
```
🤖 NetWatch Chat
  /rescan  — Atualiza os dados da rede
  /devices — Exibe tabela de dispositivos
  /quit    — Encerra o chat

✓ 8 dispositivos encontrados em 192.168.1.0/24

você: tem algum dispositivo suspeito?

╭─ 🤖 IA ──────────────────────────────────────────╮
│ 🟡 **ATENÇÃO**                                    │
│ - 192.168.1.100: dispositivo com fabricante       │
│   desconhecido apareceu pela primeira vez. ...    │
╰───────────────────────────────────────────────────╯

você: quem provavelmente é o 192.168.1.53?
```

---

### `watch` — Monitor de alertas em tempo real ⭐

Monitora a rede continuamente e emite alertas quando eventos relevantes ocorrem.

```bash
sudo python main.py watch                        # padrão: scan a cada 60s
sudo python main.py watch --interval 30          # scan a cada 30s
sudo python main.py watch --threshold 2000       # alerta de banda > 2 MB/s
sudo python main.py watch --notify               # notificações desktop
sudo python main.py watch --ai                   # chama IA em alertas críticos
sudo python main.py watch -i 30 --ai --notify    # tudo junto
```

**Tipos de alertas:**

| Ícone | Severdade | Gatilho |
|-------|-----------|---------|
| 🔴 | CRÍTICO | Novo dispositivo detectado |
| 🔴 | CRÍTICO | Porta de alto risco (Telnet, RDP, VNC...) |
| 🔴 | CRÍTICO | MAC randomizado no gateway (possível rogue AP) |
| 🟡 | ATENÇÃO | Dispositivo desapareceu |
| 🟡 | ATENÇÃO | Pico de upload/download acima do threshold |

**Exemplo de saída:**
```
👁️  NetWatch Watch
Intervalo: 30s · Threshold banda: 5000 KB/s · Gateway: 192.168.1.1
IA em alertas críticos: ativa

✓ 8 dispositivos rastreados. Monitorando 192.168.1.0/24...

[17:42:10] Scan #1 — sem anomalias — 8 dispositivos
──────────── 17:42:40 — Scan #2 — 1 alerta(s) ────────────
🔴 Novo dispositivo detectado
   IP: 192.168.1.200  MAC: aa:bb:cc:11:22:33  Fabricante: ?  (nunca visto antes)
```

---

### `status` — Status geral da rede

```bash
sudo python main.py status           # snapshot único
sudo python main.py status -t        # modo contínuo com live refresh
sudo python main.py status -t --fast # modo contínuo sem scan de portas
```

---

### `ask` — Pergunta pontual à IA

Faz uma pergunta única à IA com dados frescos da rede. Para conversas contínuas, use `chat`.

```bash
sudo python main.py ask "tem algum dispositivo suspeito?"
sudo python main.py ask "quem está consumindo mais banda?"
sudo python main.py ask "o roteador tem portas perigosas abertas?"
```

---

### `history` — Histórico de scans

```bash
python main.py history           # últimos 20 scans
python main.py history -n 50     # últimos 50 scans
```

---

### `known` — Dispositivos conhecidos

Lista todos os dispositivos já detectados em scans anteriores, com frequência de aparição.

```bash
python main.py known
python main.py known -n 50
```

---

### `monitor` — Monitoramento de banda

```bash
python main.py monitor      # uso de banda em tempo real (live)
python main.py bandwidth    # snapshot único de banda
```

---

### `setup` — Configurar API key

```bash
python main.py setup              # prompt interativo
python main.py setup --key sk-... # passar a key diretamente
```

A chave é salva em `~/.netwatch/config.json` com permissão `0600`.

---

## Arquitetura de IA

O NetWatch usa uma abordagem em duas camadas para evitar alucinações e gasto desnecessário de tokens:

```
Scan → Score local (heurísticas) → Threshold
                                       │
                               score > 0?  → Sim → DeepSeek Reasoner
                                   │              (Thinking Mode, temp=0)
                                  Não
                                   │
                         "✅ Rede estável" (sem API call)
```

**Regras anti-alucinação injetadas no system prompt:**
1. Só reporta problemas com evidência concreta nos dados
2. Dispositivos vistos frequentemente (`times_seen > 3`) não são suspeitos por padrão
3. Portas 80/443 em roteadores/TVs são normais
4. MAC aleatório em celulares é normal — apenas no gateway é crítico

---

## Dados persistidos

```
~/.netwatch/
├── config.json      # API key (0600)
└── history.db       # SQLite com scans, dispositivos e histórico
```

**Tabelas:**
- `scans` — registro de cada scan (timestamp, rede, tipo, contagem)
- `scan_devices` — dispositivos de cada scan
- `known_devices` — todos os dispositivos já vistos (MAC como PK, `times_seen`)

---

## Dependências

```
scapy             # ARP scan, packet sniffing, spoofing
psutil            # interfaces, banda, processos
mac-vendor-lookup # identificação de fabricante pelo MAC
rich              # terminal UI (tabelas, paineis, live)
typer             # CLI framework
openai            # cliente compatível com DeepSeek API
```

---

## Licença

MIT © [João Gabriel Bispo](https://github.com/jgbiispo)
