import re # Regex module for pattern matching

_CVE_RE = re.compile(r"(?<![A-Za-z0-9])CVE-\d{4}-\d{4,}", re.IGNORECASE)

def extract_cves(text: str) -> tuple[str, ...]:
    encontrados = _CVE_RE.findall(text)
    mayusculas = [c.upper() for c in encontrados]
    return tuple(sorted(set(mayusculas)))