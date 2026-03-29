"""
collector/ai.py
~~~~~~~~~~~~~~~
Integração com DeepSeek via API compatível com OpenAI.
API key armazenada em ~/.netwatch/config.json (nunca no código).

Thinking Mode: usa deepseek-reasoner com temperature=0 para análises
determinísticas e anti-alucinação.
"""

import os
import json
import stat
from pathlib import Path
from datetime import datetime

CONFIG_PATH = Path.home() / ".netwatch" / "config.json"
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-reasoner"

# Portas consideradas de alto risco para a heurística local
HIGH_RISK_PORTS = {
    23:    "Telnet (protocolo inseguro, credenciais em texto puro)",
    3389:  "RDP (acesso remoto Windows exposto)",
    5900:  "VNC (acesso remoto sem criptografia)",
    445:   "SMB (alvo comum de ransomware)",
    135:   "MSRPC (vetor de exploração Windows)",
    1433:  "MSSQL (banco de dados exposto)",
    3306:  "MySQL (banco de dados exposto)",
    5432:  "PostgreSQL (banco de dados exposto)",
    6379:  "Redis (sem autenticação por padrão)",
    27017: "MongoDB (sem autenticação por padrão)",
    21:    "FTP (credenciais em texto puro)",
    111:   "RPC/portmapper (vetor de exploração)",
    512:   "rexec (execução remota insegura)",
    513:   "rlogin (login remoto inseguro)",
    514:   "rsh (shell remoto inseguro)",
    1883:  "MQTT sem TLS (IoT com comunicação aberta)",
    873:   "rsync (transferência de arquivos sem autenticação)",
}

# Portas de médio risco (atenção mas não crítico)
MEDIUM_RISK_PORTS = {
    80:   "HTTP (sem criptografia)",
    8080: "HTTP alternativo (sem criptografia)",
    554:  "RTSP (câmera/stream exposto)",
    8554: "RTSP alternativo",
    8123: "Home Assistant (painel de automação exposto)",
}

# ---------------------------------------------------------------------------
# API Key
# ---------------------------------------------------------------------------

def get_api_key() -> str | None:
    """Lê a API key de: variável de ambiente → config file."""
    key = os.environ.get("NETWATCH_API_KEY")
    if key:
        return key
    if CONFIG_PATH.exists():
        try:
            config = json.loads(CONFIG_PATH.read_text())
            return config.get("api_key")
        except Exception:
            pass
    return None


def save_api_key(key: str) -> None:
    """Salva a API key no config com permissões restritas (0600)."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    config = {}
    if CONFIG_PATH.exists():
        try:
            config = json.loads(CONFIG_PATH.read_text())
        except Exception:
            pass
    config["api_key"] = key
    CONFIG_PATH.write_text(json.dumps(config, indent=2))
    CONFIG_PATH.chmod(0o600)


def is_configured() -> bool:
    return bool(get_api_key())


# ---------------------------------------------------------------------------
# Heurística de risco local (score antes de chamar a IA)
# ---------------------------------------------------------------------------

def score_device(device: dict, gateway_ip: str = None) -> tuple[int, list[str]]:
    """
    Calcula um score de risco local para um dispositivo.
    Retorna (score, lista_de_motivos).

    Scores:
      - Porta crítica aberta:       +3 por porta
      - Porta de atenção aberta:    +1 por porta
      - Dispositivo nunca visto:    +2
      - Fabricante desconhecido
        com portas abertas:         +2
      - MAC randomizado no gateway: +4
      - MAC gateway mudou:          +5

    Um score >= 3 justifica chamada à IA.
    """
    score = 0
    reasons: list[str] = []

    open_ports: list[int] = device.get("open_ports", [])
    vendor: str = device.get("vendor", "Desconhecido")
    mac: str = device.get("mac", "")
    ip: str = device.get("ip", "")
    times_seen: int = device.get("times_seen", 0)

    # Verifica portas críticas
    for port in open_ports:
        if port in HIGH_RISK_PORTS:
            score += 3
            reasons.append(f"Porta crítica {port}/tcp aberta: {HIGH_RISK_PORTS[port]}")
        elif port in MEDIUM_RISK_PORTS:
            score += 1
            reasons.append(f"Porta de atenção {port}/tcp aberta: {MEDIUM_RISK_PORTS[port]}")

    # Dispositivo nunca visto antes
    if times_seen == 0:
        score += 2
        reasons.append("Dispositivo aparece pela primeira vez (sem histórico)")

    # Fabricante desconhecido com portas abertas
    unknown_vendor = (
        "Desconhecido" in vendor
        or vendor.strip() == ""
        or vendor.startswith("(")
    )
    if unknown_vendor and open_ports:
        score += 2
        reasons.append(f"Fabricante não identificado com {len(open_ports)} porta(s) aberta(s)")

    # MAC randomizado no gateway (altíssimo risco — possível rogue AP)
    if gateway_ip and ip == gateway_ip:
        is_randomized = len(mac) >= 2 and mac[1].lower() in ('2', '6', 'a', 'e')
        if is_randomized:
            score += 4
            reasons.append("Gateway com MAC randomizado (possível rogue AP/MITM)")

    return score, reasons


def should_call_ai(
    devices: list,
    diff: dict = None,
    gateway_ip: str = None,
) -> tuple[bool, int]:
    """
    Decide se vale chamar a IA com base na heurística local.
    Retorna (deve_chamar, score_total).

    Chama IA se:
    - Há dispositivos novos (diff["new"] não vazio)
    - Há dispositivos com MAC alterado no gateway
    - Score total da rede > 0
    """
    # Sempre chama se há novos dispositivos
    if diff and diff.get("new"):
        return True, -1

    # Calcula score total
    total_score = 0
    for d in devices:
        s, _ = score_device(d, gateway_ip)
        total_score += s

    return total_score > 0, total_score


# ---------------------------------------------------------------------------
# Contexto
# ---------------------------------------------------------------------------

def _is_randomized_mac(mac: str) -> bool:
    """MAC aleatório tem o 2º nibble como 2, 6, A ou E."""
    return len(mac) >= 2 and mac[1].lower() in ('2', '6', 'a', 'e')


def build_context(
    devices: list,
    bandwidth: dict = None,
    diff: dict = None,
    per_device: dict = None,
    gateway_ip: str = None,
) -> str:
    """
    Transforma os dados da rede em texto estruturado e rico para a IA.
    Inclui: histórico de presença, portas abertas, scores de risco
    e contexto do gateway para análise precisa e sem alucinações.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=== SNAPSHOT DA REDE ===",
        f"Timestamp         : {now}",
        f"Dispositivos ativos: {len(devices)}",
        f"Gateway detectado  : {gateway_ip or 'desconhecido'}",
        "",
    ]

    # --- Dispositivos ---
    lines.append("DISPOSITIVOS (com histórico e risco):")
    lines.append("-" * 70)
    for d in devices:
        ip      = d.get("ip", "?")
        mac     = d.get("mac", "?")
        vendor  = d.get("vendor", "Desconhecido")
        source  = d.get("source", "?")
        ports   = d.get("open_ports", [])
        times   = d.get("times_seen", 0)
        score, risk_reasons = score_device(d, gateway_ip)

        is_gw   = "★ GATEWAY" if gateway_ip and ip == gateway_ip else ""
        is_rand = "[MAC ALEATÓRIO]" if _is_randomized_mac(mac) else ""
        hist    = f"visto {times}x" if times > 0 else "NOVO (nunca visto)"
        risk_tag = f"[RISCO {score}]" if score > 0 else "[ok]"

        lines.append(
            f"  {risk_tag:<10} {ip:<16} {mac}  {vendor[:35]:<35}  "
            f"{hist:<22} {is_gw} {is_rand}"
        )

        # Portas abertas com contexto de risco
        if ports:
            port_labels = []
            for p in sorted(ports):
                if p in HIGH_RISK_PORTS:
                    port_labels.append(f"{p}⚠️")
                elif p in MEDIUM_RISK_PORTS:
                    port_labels.append(f"{p}⚡")
                else:
                    port_labels.append(str(p))
            lines.append(f"    Portas abertas: {', '.join(port_labels)}")

        # Motivos de risco
        for reason in risk_reasons:
            lines.append(f"    ⚠ {reason}")

    lines.append("")

    # --- Tráfego geral ---
    if bandwidth:
        lines += [
            "TRÁFEGO GERAL:",
            f"  Interface : {bandwidth.get('interface', '?')}",
            f"  Upload    : {bandwidth.get('upload', 0) / 1024:.2f} KB/s",
            f"  Download  : {bandwidth.get('download', 0) / 1024:.2f} KB/s",
            "",
        ]

    # --- Tráfego por dispositivo ---
    if per_device:
        active = {
            ip: t for ip, t in per_device.items()
            if t.get("upload", 0) > 512 or t.get("download", 0) > 512
        }
        if active:
            lines.append("TRÁFEGO POR DISPOSITIVO (ativos > 0.5 KB/s):")
            ranked = sorted(
                active.items(),
                key=lambda x: x[1]["download"] + x[1]["upload"],
                reverse=True,
            )[:10]
            for ip, t in ranked:
                lines.append(
                    f"  {ip:<16} Upload: {t['upload']/1024:.1f} KB/s  "
                    f"Download: {t['download']/1024:.1f} KB/s"
                )
            lines.append("")

    # --- Diff (mudanças vs scan anterior) ---
    if diff:
        if diff.get("new"):
            lines.append("⚠ NOVOS DISPOSITIVOS (não vistos no scan anterior):")
            for d in diff["new"]:
                lines.append(
                    f"  + {d['ip']:<16} {d['mac']}  {d.get('vendor', '?')}"
                )
            lines.append("")
        if diff.get("missing"):
            lines.append("DISPOSITIVOS DESAPARECIDOS desde o último scan:")
            for d in diff["missing"]:
                lines.append(
                    f"  - {d['ip']:<16} {d['mac']}  {d.get('vendor', '?')}"
                )
            lines.append("")
        if diff.get("changed"):
            lines.append("⚠ DISPOSITIVOS COM IP ALTERADO:")
            for c in diff["changed"]:
                d = c["device"]
                lines.append(
                    f"  ~ {c['old_ip']:<16} → {d['ip']:<16} {d['mac']}"
                )
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# System Prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
Você é um analista sênior de segurança de redes. Recebe um snapshot estruturado \
de uma rede local e deve identificar APENAS anomalias com EVIDÊNCIAS CLARAS nos dados.

REGRAS ABSOLUTAS (anti-alucinação):
1. Só reporte um problema se houver dado concreto que o sustente (porta aberta, MAC mudado, etc.)
2. NUNCA invente ameaças. Se os dados não mostram problema, diga que está normal.
3. Dispositivos com "visto Nx" (N > 3) são recorrentes — não são suspeitos por padrão.
4. Portas 80/443 abertas em roteadores, TVs e impressoras são NORMAIS — não reporte como risco.
5. MAC aleatório em celulares/tablets é NORMAL — só é crítico se ocorrer no gateway.
6. Só cite "device suspeito" se tiver [RISCO > 0] E justificativa clara do por quê.

FORMATO DE RESPOSTA OBRIGATÓRIO (use exatamente estas seções, omita as que não aplicam):

🔴 **CRÍTICO** — ameaças com evidência direta (ex: porta Telnet aberta, MAC do gateway mudou)
🟡 **ATENÇÃO** — comportamentos que merecem investigação (ex: dispositivo novo com portas abertas)
✅ **NORMAL** — confirmação em uma linha do que está ok

Responda SEMPRE em português brasileiro.
Seja direto e técnico. Cada item deve citar o IP e a evidência específica.
Limite total: 350 palavras.
"""


# ---------------------------------------------------------------------------
# Análise
# ---------------------------------------------------------------------------

def analyze(
    context: str,
    question: str = None,
    force: bool = False,
) -> str | None:
    """
    Envia o contexto para o DeepSeek Reasoner (Thinking Mode).

    Args:
        context: Texto estruturado da rede (build_context).
        question: Pergunta livre do usuário (opcional).
        force: Se True, ignora o threshold e sempre chama a API.

    Retorna a resposta como string ou None se não houver API key.
    """
    key = get_api_key()
    if not key:
        return None

    try:
        from openai import OpenAI
        client = OpenAI(api_key=key, base_url=DEEPSEEK_BASE_URL)

        user_msg = context
        if question:
            user_msg += f"\n\nPERGUNTA DO USUÁRIO:\n{question}"
        else:
            user_msg += "\n\nAnalise a rede acima seguindo estritamente as regras do sistema."

        response = client.chat.completions.create(
            model=DEEPSEEK_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
            # temperature=0 é obrigatório para o Reasoner — determinístico
            # O modelo já raciocina internamente (chain-of-thought)
            temperature=0,
            max_tokens=1500,  # inclui tokens de thinking interno + resposta
        )

        # O deepseek-reasoner expõe o raciocínio em reasoning_content
        # Capturamos apenas a resposta final (content)
        msg = response.choices[0].message
        answer = getattr(msg, "content", None) or ""
        return answer.strip() if answer.strip() else "✅ **NORMAL** — Nenhuma anomalia detectada."

    except Exception as e:
        return f"[Erro na IA: {e}]"


def analyze_with_threshold(
    devices: list,
    bandwidth: dict = None,
    diff: dict = None,
    per_device: dict = None,
    gateway_ip: str = None,
    question: str = None,
) -> tuple[str | None, bool]:
    """
    Wrapper inteligente: só chama a API se houver dados que justifiquem.

    Retorna (resultado, foi_chamado_api).
    - Se a rede estiver estável e não houver pergunta do usuário,
      retorna mensagem estática sem consumir tokens.
    """
    # Pergunta do usuário sempre força chamada à API
    force = bool(question)

    should_call, score = should_call_ai(devices, diff, gateway_ip)

    if not force and not should_call:
        return (
            "✅ **NORMAL** — Rede estável. Nenhuma anomalia detectada neste scan "
            f"(score de risco total: 0, {len(devices)} dispositivo(s) conhecidos).",
            False,
        )

    context = build_context(devices, bandwidth, diff, per_device, gateway_ip)
    result = analyze(context, question)
    return result, True


# ---------------------------------------------------------------------------
# Chat multi-turn
# ---------------------------------------------------------------------------

# Máximo de turnos (par usuário + assistente) mantidos no histórico.
# Ao ultrapassar, os mais antigos são descartados preservando o system message.
MAX_CHAT_HISTORY = 10

CHAT_SYSTEM_PROMPT = """\
Você é um assistente especialista em segurança de redes integrado ao NetWatch.
O usuário está monitorando a própria rede local e pode fazer perguntas em linguagem natural.

O contexto atual da rede (snapshot mais recente) será fornecido na primeira mensagem.
Use APENAS as informações presentes no contexto — nunca invente dados.

REGRAS:
1. Responda sempre em português brasileiro.
2. Se a pergunta é sobre a rede: cite IPs, MACs e portas específicas quando relevante.
3. Se não houver dados suficientes no contexto para responder: diga isso claramente.
4. Seja conciso — máximo 200 palavras por resposta no chat.
5. Para alertas de segurança, use 🔴 (crítico) ou 🟡 (atenção) para destacar.
"""


def chat_turn(
    messages: list,
    question: str,
    context: str,
) -> tuple[str, list]:
    """
    Executa um turno da conversa multi-turn com o DeepSeek.

    Na primeira chamada (messages=[]), inicializa o histórico injetando o
    contexto da rede como parte do system prompt. Em turnos subsequentes,
    apenas appenda a nova pergunta e obtém a resposta.

    Args:
        messages: Histórico acumulado ({ role, content } dicts). Passa [] na 1ª vez.
        question: Pergunta do usuário neste turno.
        context: Snapshot atual da rede (de build_context). Usado apenas no 1º turno.

    Returns:
        (resposta_str, messages_atualizado)
    """
    key = get_api_key()
    if not key:
        return "⚠ IA não configurada. Execute `netwatch setup` primeiro.", messages

    try:
        from openai import OpenAI
        client = OpenAI(api_key=key, base_url=DEEPSEEK_BASE_URL)

        # Primeira mensagem: inicializa com system + contexto da rede
        if not messages:
            system_content = (
                CHAT_SYSTEM_PROMPT
                + "\n\n=== CONTEXTO DA REDE (atualizado em cada /rescan) ===\n"
                + context
            )
            messages = [{"role": "system", "content": system_content}]

        # Adiciona pergunta do usuário
        messages.append({"role": "user", "content": question})

        response = client.chat.completions.create(
            model=DEEPSEEK_MODEL,
            messages=messages,
            temperature=0,      # determinístico como no modo análise
            max_tokens=600,     # respostas concisas no chat
        )

        answer = (response.choices[0].message.content or "").strip()
        if not answer:
            answer = "Não consegui gerar uma resposta. Tente reformular a pergunta."

        messages.append({"role": "assistant", "content": answer})

        # Poda o histórico: preserva system message + últimos MAX_CHAT_HISTORY turnos
        max_msgs = 1 + MAX_CHAT_HISTORY * 2  # system + N pares (user+assistant)
        if len(messages) > max_msgs:
            messages = [messages[0]] + messages[-(MAX_CHAT_HISTORY * 2):]

        return answer, messages

    except Exception as e:
        error_msg = f"[Erro na IA: {e}]"
        # Não adiciona o erro ao histórico para não poluir o contexto
        return error_msg, messages
