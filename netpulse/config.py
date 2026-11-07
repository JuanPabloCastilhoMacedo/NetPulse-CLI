"""
Configurações globais do NetPulse CLI.
"""

# Configurações de Ping
DEFAULT_PING_COUNT = 10
DEFAULT_PING_INTERVAL = 0.5  # segundos
DEFAULT_PING_TIMEOUT = 2.0   # segundos
DEFAULT_PACKET_SIZE = 64     # bytes

# Configurações de Descoberta
DEFAULT_DISCOVERY_TIMEOUT = 1.0  # segundos
DEFAULT_DISCOVERY_WORKERS = 50   # threads simultâneas

# Configurações de Traceroute
DEFAULT_MAX_HOPS = 30
DEFAULT_TRACE_TIMEOUT = 2.0  # segundos

# Configurações de Qualidade / QoS
DEFAULT_QOS_COUNT = 30
DEFAULT_QOS_INTERVAL = 0.1  # segundos (100ms entre pacotes)

# Configurações de Monitoramento Contínuo (Watch / NOC)
DEFAULT_WATCH_INTERVAL = 10.0  # segundos entre ciclos
DEFAULT_WATCH_COUNT = 10       # pacotes por ciclo
DEFAULT_MOS_THRESHOLD = 3.5    # MOS mínimo aceitável

# Codecs VoIP e seus parâmetros
# Ie = Equipment Impairment Factor (ITU-T G.113)
# Bpl = Packet Loss Robustness Factor
VOIP_CODECS = {
    "g711": {
        "name": "G.711 (PCM)",
        "bitrate_kbps": 64,
        "ie": 0,       # Sem degradação intrínseca
        "bpl": 4.3,
        "description": "Codec padrão de telefonia, sem compressão",
    },
    "g729": {
        "name": "G.729 (CS-ACELP)",
        "bitrate_kbps": 8,
        "ie": 11,
        "bpl": 19.0,
        "description": "Codec comprimido, ideal para baixa banda",
    },
    "g722": {
        "name": "G.722 (SB-ADPCM)",
        "bitrate_kbps": 64,
        "ie": 0,
        "bpl": 4.3,
        "description": "Codec HD Voice, qualidade superior",
    },
}

# Classificação de MOS Score
MOS_THRESHOLDS = {
    "excelente": 4.0,
    "bom": 3.6,
    "razoavel": 3.1,
    "ruim": 2.6,
}

# Limites recomendados para VoIP (ITU-T)
VOIP_LIMITS = {
    "latency_ms": 150.0,       # Latência máxima one-way
    "jitter_ms": 30.0,         # Jitter máximo
    "packet_loss_pct": 1.0,    # Perda máxima aceitável (%)
}

# Portas para scan de infraestrutura e VoIP
INFRA_PORTS = {
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    161: "SNMP",
    443: "HTTPS",
    3389: "RDP",
    5060: "SIP",
    5061: "SIPS",
    8080: "HTTP-Alt",
}

# Timeout para port scan (segundos)
DEFAULT_PORT_SCAN_TIMEOUT = 0.3
