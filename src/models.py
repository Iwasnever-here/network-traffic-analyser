from dataclasses import dataclass

@dataclass
class Packetinfo:
    src_ip: str
    dst_ip: str
    protocol: str
    size: int
    timestamp: float


