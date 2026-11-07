"""
Modelos de dados para resultados de diagnóstico de rede.
"""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class PingResult:
    """Resultado de uma sessão de ping."""
    host: str
    resolved_name: Optional[str] = None
    packets_sent: int = 0
    packets_received: int = 0
    packet_loss_pct: float = 0.0
    min_latency_ms: float = 0.0
    avg_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    jitter_ms: float = 0.0
    latencies: list[float] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def packets_lost(self) -> int:
        return self.packets_sent - self.packets_received

    @property
    def is_reachable(self) -> bool:
        return self.packets_received > 0


@dataclass
class PortResult:
    """Resultado do scan de uma porta."""
    port: int
    service: str = ""
    is_open: bool = False


@dataclass
class HostInfo:
    """Informações de um host descoberto na rede."""
    ip_address: str
    is_alive: bool = False
    latency_ms: Optional[float] = None
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    open_ports: list[PortResult] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def open_ports_summary(self) -> str:
        """Retorna resumo das portas abertas como string."""
        if not self.open_ports:
            return "—"
        parts = []
        for p in sorted(self.open_ports, key=lambda x: x.port):
            if p.is_open:
                parts.append(f"{p.port}/{p.service}")
        return ", ".join(parts) if parts else "—"


@dataclass
class DiscoveryResult:
    """Resultado de uma descoberta de hosts na rede."""
    network: str
    total_hosts_scanned: int = 0
    hosts_alive: int = 0
    hosts: list[HostInfo] = field(default_factory=list)
    scan_duration_sec: float = 0.0
    port_scan_enabled: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        """Converte o resultado para dicionário serializável."""
        return {
            "network": self.network,
            "total_hosts_scanned": self.total_hosts_scanned,
            "hosts_alive": self.hosts_alive,
            "scan_duration_sec": round(self.scan_duration_sec, 2),
            "port_scan_enabled": self.port_scan_enabled,
            "timestamp": self.timestamp,
            "hosts": [
                {
                    "ip_address": h.ip_address,
                    "hostname": h.hostname,
                    "is_alive": h.is_alive,
                    "latency_ms": round(h.latency_ms, 2) if h.latency_ms is not None else None,
                    "mac_address": h.mac_address,
                    "open_ports": [
                        {"port": p.port, "service": p.service, "is_open": p.is_open}
                        for p in h.open_ports if p.is_open
                    ] if h.open_ports else [],
                }
                for h in self.hosts
            ],
        }

    def to_markdown(self) -> str:
        """Gera relatório em Markdown."""
        lines = [
            f"# 🔍 Relatório de Descoberta de Hosts — NetPulse CLI",
            f"",
            f"**Data:** {self.timestamp}",
            f"",
            f"## Resumo",
            f"",
            f"| Parâmetro | Valor |",
            f"|-----------|-------|",
            f"| Rede | {self.network} |",
            f"| Hosts escaneados | {self.total_hosts_scanned} |",
            f"| Hosts ativos | {self.hosts_alive} |",
            f"| Duração do scan | {self.scan_duration_sec:.1f}s |",
            f"| Port scan | {'Sim' if self.port_scan_enabled else 'Não'} |",
            f"",
            f"## Hosts Ativos",
            f"",
        ]

        if self.port_scan_enabled:
            lines.append(f"| # | IP | Hostname | Latência | Portas Abertas |")
            lines.append(f"|---|-----|----------|----------|----------------|")
        else:
            lines.append(f"| # | IP | Hostname | Latência |")
            lines.append(f"|---|-----|----------|----------|")

        for idx, h in enumerate(self.hosts, 1):
            lat = f"{h.latency_ms:.1f} ms" if h.latency_ms is not None else "—"
            hostname = h.hostname or "—"
            if self.port_scan_enabled:
                ports = h.open_ports_summary
                lines.append(f"| {idx} | {h.ip_address} | {hostname} | {lat} | {ports} |")
            else:
                lines.append(f"| {idx} | {h.ip_address} | {hostname} | {lat} |")

        lines.append("")
        lines.append("---")
        lines.append("*Gerado por NetPulse CLI*")
        return "\n".join(lines)


@dataclass
class TracerouteHop:
    """Informações de um salto no traceroute."""
    hop_number: int
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    latency_ms: Optional[float] = None
    is_timeout: bool = False

    @property
    def display_address(self) -> str:
        if self.is_timeout:
            return "* * *"
        if self.hostname and self.hostname != self.ip_address:
            return f"{self.hostname} ({self.ip_address})"
        return self.ip_address or "???"


@dataclass
class TracerouteResult:
    """Resultado de um traceroute completo."""
    destination: str
    resolved_name: Optional[str] = None
    max_hops: int = 30
    hops: list[TracerouteHop] = field(default_factory=list)
    reached_destination: bool = False
    total_hops: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class QualityResult:
    """Resultado da análise de qualidade de link."""
    host: str
    resolved_name: Optional[str] = None
    codec: str = "g711"
    packets_sent: int = 0
    packets_received: int = 0
    packet_loss_pct: float = 0.0
    min_latency_ms: float = 0.0
    avg_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    jitter_ms: float = 0.0
    mos_score: float = 0.0
    r_factor: float = 0.0
    quality_rating: str = "N/A"
    voip_suitable: bool = False
    latency_ok: bool = False
    jitter_ok: bool = False
    loss_ok: bool = False
    latencies: list[float] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        """Converte o resultado para dicionário serializável."""
        return {
            "host": self.host,
            "resolved_name": self.resolved_name,
            "codec": self.codec,
            "timestamp": self.timestamp,
            "packets": {
                "sent": self.packets_sent,
                "received": self.packets_received,
                "loss_pct": round(self.packet_loss_pct, 2),
            },
            "latency": {
                "min_ms": round(self.min_latency_ms, 2),
                "avg_ms": round(self.avg_latency_ms, 2),
                "max_ms": round(self.max_latency_ms, 2),
                "ok": self.latency_ok,
            },
            "jitter": {
                "ms": round(self.jitter_ms, 2),
                "ok": self.jitter_ok,
            },
            "loss": {
                "pct": round(self.packet_loss_pct, 2),
                "ok": self.loss_ok,
            },
            "quality": {
                "r_factor": round(self.r_factor, 1),
                "mos_score": round(self.mos_score, 2),
                "rating": self.quality_rating,
                "voip_suitable": self.voip_suitable,
            },
        }

    def to_markdown(self) -> str:
        """Gera relatório em Markdown."""
        target = self.host
        if self.resolved_name and self.resolved_name != self.host:
            target = f"{self.resolved_name} ({self.host})"

        voip_str = "✅ SIM" if self.voip_suitable else "❌ NÃO"
        lat_str = "✅ OK" if self.latency_ok else "❌ FALHA"
        jitter_str = "✅ OK" if self.jitter_ok else "❌ FALHA"
        loss_str = "✅ OK" if self.loss_ok else "❌ FALHA"

        lines = [
            f"# 📊 Laudo de Qualidade de Link — NetPulse CLI",
            f"",
            f"**Data:** {self.timestamp}",
            f"",
            f"## Alvo",
            f"",
            f"| Parâmetro | Valor |",
            f"|-----------|-------|",
            f"| Host | {target} |",
            f"| Codec | {self.codec.upper()} |",
            f"",
            f"## Resultado QoS",
            f"",
            f"| Métrica | Valor | Status |",
            f"|---------|-------|--------|",
            f"| MOS Score | {self.mos_score:.2f} | {self.quality_rating} |",
            f"| R-Factor | {self.r_factor:.1f} | — |",
            f"| Adequado para VoIP | — | {voip_str} |",
            f"",
            f"## Métricas Detalhadas",
            f"",
            f"| Métrica | Valor | Limite VoIP | Status |",
            f"|---------|-------|-------------|--------|",
            f"| Latência Média | {self.avg_latency_ms:.2f} ms | < 150 ms | {lat_str} |",
            f"| Latência Mínima | {self.min_latency_ms:.2f} ms | — | — |",
            f"| Latência Máxima | {self.max_latency_ms:.2f} ms | — | — |",
            f"| Jitter | {self.jitter_ms:.2f} ms | < 30 ms | {jitter_str} |",
            f"| Perda de Pacotes | {self.packet_loss_pct:.2f}% | < 1.0% | {loss_str} |",
            f"",
            f"## Pacotes",
            f"",
            f"| Parâmetro | Valor |",
            f"|-----------|-------|",
            f"| Enviados | {self.packets_sent} |",
            f"| Recebidos | {self.packets_received} |",
            f"| Perdidos | {self.packets_sent - self.packets_received} |",
            f"",
            f"---",
            f"*Gerado por NetPulse CLI*",
        ]
        return "\n".join(lines)
