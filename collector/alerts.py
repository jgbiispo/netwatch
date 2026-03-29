"""
collector/alerts.py
~~~~~~~~~~~~~~~~~~~
Sistema de alertas de segurança em tempo real.

Detecta eventos relevantes comparando scans consecutivos:
- Novos dispositivos
- Dispositivos desaparecidos
- Portas de alto risco
- Picos de banda
- MAC randomizado no gateway
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from collector.ai import score_device, HIGH_RISK_PORTS


class AlertLevel(Enum):
    CRITICAL = "critical"   # Ação imediata necessária
    WARNING  = "warning"    # Merece atenção
    INFO     = "info"       # Informativo


@dataclass
class NetworkAlert:
    level:     AlertLevel
    title:     str
    detail:    str
    ip:        str = ""
    mac:       str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now().strftime("%H:%M:%S")
    )

    @property
    def icon(self) -> str:
        return {
            AlertLevel.CRITICAL: "🔴",
            AlertLevel.WARNING:  "🟡",
            AlertLevel.INFO:     "🔵",
        }[self.level]

    @property
    def rich_color(self) -> str:
        return {
            AlertLevel.CRITICAL: "bold red",
            AlertLevel.WARNING:  "bold yellow",
            AlertLevel.INFO:     "bold blue",
        }[self.level]


def detect_alerts(
    prev_devices: list,
    curr_devices: list,
    bandwidth: dict = None,
    gateway_ip: str = None,
    bandwidth_threshold_kbs: float = 5000.0,
) -> list[NetworkAlert]:
    """
    Compara dois snapshots de dispositivos e retorna alertas gerados.

    Args:
        prev_devices: Dispositivos do scan anterior.
        curr_devices: Dispositivos do scan atual (já enriquecidos com times_seen).
        bandwidth: Dados de banda do scan atual.
        gateway_ip: IP do gateway para detectar rogue AP.
        bandwidth_threshold_kbs: Limite (KB/s) para alertas de pico de banda.

    Returns:
        Lista de NetworkAlert ordenada por severidade (CRITICAL primeiro).
    """
    alerts: list[NetworkAlert] = []

    prev_by_mac = {d["mac"].lower(): d for d in prev_devices}
    curr_by_mac = {d["mac"].lower(): d for d in curr_devices}

    # ── 1. Novos dispositivos ───────────────────────────────────────────────
    for mac, dev in curr_by_mac.items():
        if mac not in prev_by_mac:
            times = dev.get("times_seen", 0)
            history_note = (
                f"nunca visto antes" if times == 0
                else f"visto {times}x no histórico"
            )
            alerts.append(NetworkAlert(
                level=AlertLevel.CRITICAL,
                title="Novo dispositivo detectado",
                detail=(
                    f"IP: {dev['ip']}  MAC: {mac}  "
                    f"Fabricante: {dev.get('vendor', '?')}  ({history_note})"
                ),
                ip=dev["ip"],
                mac=mac,
            ))

    # ── 2. Dispositivos desaparecidos ───────────────────────────────────────
    for mac, dev in prev_by_mac.items():
        if mac not in curr_by_mac:
            alerts.append(NetworkAlert(
                level=AlertLevel.WARNING,
                title="Dispositivo desapareceu da rede",
                detail=(
                    f"Último IP: {dev['ip']}  MAC: {mac}  "
                    f"Fabricante: {dev.get('vendor', '?')}"
                ),
                ip=dev["ip"],
                mac=mac,
            ))

    # ── 3. Portas de alto risco (em dispositivos existentes ou novos) ───────
    already_alerted: set[str] = set()
    for mac, dev in curr_by_mac.items():
        # Evita duplicar alertas para novos dispositivos (já alertados acima)
        is_new = mac not in prev_by_mac
        open_ports = dev.get("open_ports", [])
        for port in open_ports:
            if port in HIGH_RISK_PORTS:
                key = f"{mac}:{port}"
                if key not in already_alerted:
                    already_alerted.add(key)
                    level = AlertLevel.CRITICAL if is_new else AlertLevel.WARNING
                    alerts.append(NetworkAlert(
                        level=level,
                        title="Porta de alto risco detectada",
                        detail=(
                            f"IP: {dev['ip']}  Porta {port}/tcp — "
                            f"{HIGH_RISK_PORTS[port]}"
                        ),
                        ip=dev["ip"],
                        mac=mac,
                    ))

    # ── 4. MAC randomizado no gateway (rogue AP / MITM) ────────────────────
    if gateway_ip:
        for mac, dev in curr_by_mac.items():
            if dev["ip"] == gateway_ip:
                is_random = len(mac) >= 2 and mac[1].lower() in ('2', '6', 'a', 'e')
                if is_random:
                    alerts.append(NetworkAlert(
                        level=AlertLevel.CRITICAL,
                        title="Gateway com MAC randomizado",
                        detail=(
                            f"IP: {gateway_ip}  MAC: {mac}  "
                            "Possível Rogue AP ou ataque MITM!"
                        ),
                        ip=gateway_ip,
                        mac=mac,
                    ))

    # ── 5. Pico de banda ────────────────────────────────────────────────────
    if bandwidth:
        upload_kbs   = bandwidth.get("upload", 0) / 1024
        download_kbs = bandwidth.get("download", 0) / 1024

        if upload_kbs > bandwidth_threshold_kbs:
            alerts.append(NetworkAlert(
                level=AlertLevel.WARNING,
                title="Pico de upload detectado",
                detail=(
                    f"Upload: {upload_kbs:.1f} KB/s  "
                    f"(limite configurado: {bandwidth_threshold_kbs:.0f} KB/s)"
                ),
            ))
        if download_kbs > bandwidth_threshold_kbs:
            alerts.append(NetworkAlert(
                level=AlertLevel.WARNING,
                title="Pico de download detectado",
                detail=(
                    f"Download: {download_kbs:.1f} KB/s  "
                    f"(limite configurado: {bandwidth_threshold_kbs:.0f} KB/s)"
                ),
            ))

    # Ordena: CRITICAL → WARNING → INFO
    priority = {AlertLevel.CRITICAL: 0, AlertLevel.WARNING: 1, AlertLevel.INFO: 2}
    alerts.sort(key=lambda a: priority[a.level])

    return alerts


def send_desktop_notification(alert: NetworkAlert) -> bool:
    """
    Envia notificação desktop via notify-send (Linux/freedesktop).
    Retorna True se enviado com sucesso.
    """
    icon = (
        "dialog-error"   if alert.level == AlertLevel.CRITICAL
        else "dialog-warning"
    )
    try:
        subprocess.run(
            [
                "notify-send",
                "--icon", icon,
                "--urgency", "critical" if alert.level == AlertLevel.CRITICAL else "normal",
                f"NetWatch — {alert.title}",
                alert.detail,
            ],
            timeout=3,
            capture_output=True,
        )
        return True
    except FileNotFoundError:
        return False  # notify-send não instalado
    except Exception:
        return False
