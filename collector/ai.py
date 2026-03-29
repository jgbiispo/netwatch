"""
collector/ai.py
~~~~~~~~~~~~~~~
Integração com DeepSeek via API compatível com OpenAI.
API key armazenada em ~/.netwatch/config.json (nunca no código).
"""

import os
import json
import stat
from pathlib import Path
from datetime import datetime

CONFIG_PATH = Path.home() / ".netwatch" / "config.json"
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat"

SYSTEM_PROMPT = """\
Você é um analista de segurança de redes especializado.
Recebe dados estruturados de um scan de rede local e deve:

- Identificar dispositivos suspeitos, desconhecidos ou com comportamento atípico
- Apontar portas abertas que representam risco de segurança (ex: Telnet na 23, RDP na 3389, etc.)
- Detectar anomalias de tráfego (alto volume inesperado, IPs novos consumindo muita banda)
- Comentar sobre mudanças relevantes desde o último scan (novos dispositivos, IPs alterados, sumiços)
- Destacar fabricantes desconhecidos ou MACs randomizados em posições sensíveis (ex: gateway)

Responda SEMPRE em português brasileiro.
Seja direto e técnico — use bullet points para listar problemas.
Se não houver nada suspeito, diga isso claramente em uma linha.
Limite a resposta a no máximo 400 palavras.
"""


# ---------------------------------------------------------------------------
# API Key
# ---------------------------------------------------------------------------

def get_api_key() -> str | None:
    """Lê a API key de: variável de ambiente → config file."""
    # 1. Env var (prioridade)
    key = os.environ.get("NETWATCH_API_KEY")
    if key:
        return key
    # 2. Config file
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
# Contexto
# ---------------------------------------------------------------------------

def build_context(
    devices: list,
    bandwidth: dict = None,
    diff: dict = None,
    per_device: dict = None,
) -> str:
    """
    Transforma os dados da rede em texto estruturado para a IA.
    """
    lines = [
        "=== SNAPSHOT DA REDE ===",
        f"Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Dispositivos ativos: {len(devices)}",
        "",
    ]

    lines.append("DISPOSITIVOS:")
    for d in devices:
        lines.append(
            f"  IP: {d['ip']:<16} MAC: {d['mac']}  "
            f"Fabricante: {d.get('vendor', '?'):<30}  Origem: {d.get('source', '?')}"
        )
    lines.append("")

    if bandwidth:
        lines += [
            "TRÁFEGO GERAL:",
            f"  Interface : {bandwidth.get('interface', '?')}",
            f"  Upload    : {bandwidth.get('upload', 0) / 1024:.2f} KB/s",
            f"  Download  : {bandwidth.get('download', 0) / 1024:.2f} KB/s",
            "",
        ]

    if per_device:
        active = {
            ip: t for ip, t in per_device.items()
            if t.get("upload", 0) > 512 or t.get("download", 0) > 512  # > 0.5 KB/s
        }
        if active:
            lines.append("TRÁFEGO POR DISPOSITIVO (top ativos):")
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

    if diff:
        if diff.get("new"):
            lines.append("NOVOS DISPOSITIVOS (não vistos no scan anterior):")
            for d in diff["new"]:
                lines.append(f"  + {d['ip']:<16} {d['mac']}  {d.get('vendor', '?')}")
            lines.append("")
        if diff.get("missing"):
            lines.append("DISPOSITIVOS DESAPARECIDOS desde o último scan:")
            for d in diff["missing"]:
                lines.append(f"  - {d['ip']:<16} {d['mac']}  {d.get('vendor', '?')}")
            lines.append("")
        if diff.get("changed"):
            lines.append("DISPOSITIVOS COM IP ALTERADO:")
            for c in diff["changed"]:
                d = c["device"]
                lines.append(f"  ~ {c['old_ip']:<16} → {d['ip']:<16} {d['mac']}")
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Análise
# ---------------------------------------------------------------------------

def analyze(context: str, question: str = None) -> str | None:
    """
    Envia o contexto (e opcionalmente uma pergunta) para o DeepSeek.
    Retorna a resposta como string, ou None se não houver API key.
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
            user_msg += "\n\nFaça uma análise de segurança desta rede."

        response = client.chat.completions.create(
            model=DEEPSEEK_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            max_tokens=800,
            temperature=0.3,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"[Erro na IA: {e}]"
