import re  # Regex module for pattern matching
from dataclasses import dataclass  # Dataclass decorator for creating data classes

_CVE_RE = re.compile(r"(?<![A-Za-z0-9])CVE-\d{4}-\d{4,}", re.IGNORECASE)


def extract_cves(text: str) -> tuple[str, ...]:
    encontrados = _CVE_RE.findall(text)
    mayusculas = [c.upper() for c in encontrados]
    return tuple(sorted(set(mayusculas)))


@dataclass(frozen=True, order=True)
class FileHash:
    value: str
    algorithm: str


_ALGORITHM_BY_LENGTH = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}

_HASH_RE = re.compile(
    r"(?<![0-9A-Za-z])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9A-Za-z])",
    re.IGNORECASE,
)


def extract_hashes(text: str) -> tuple[FileHash, ...]:
    encontrados = _HASH_RE.findall(text)
    minusculas = [h.lower() for h in encontrados]
    unicos = {FileHash(h, _ALGORITHM_BY_LENGTH[len(h)]) for h in minusculas}
    return tuple(sorted(unicos))
