import ipaddress  # Module for IP address manipulation
import re  # Regex module for pattern matching
from dataclasses import dataclass  # Dataclass decorator for creating data classes

# CVE

_CVE_RE = re.compile(r"(?<![A-Za-z0-9])CVE-\d{4}-\d{4,}", re.IGNORECASE)


def extract_cves(text: str) -> tuple[str, ...]:
    encontrados = _CVE_RE.findall(text)
    mayusculas = [c.upper() for c in encontrados]
    return tuple(sorted(set(mayusculas)))


# HASHES


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


# IPs

_IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")


def extract_ips(text: str) -> tuple[str, ...]:
    unicos = set()
    for candidato in _IP_RE.findall(text):
        try:
            unicos.add(ipaddress.IPv4Address(candidato))
        except ValueError:
            continue

    return tuple(str(ip) for ip in sorted(unicos))


# DOMAINS

_DOMAIN_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", re.IGNORECASE)

_GENERIC_TLDS = frozenset(
    "com net org info biz edu gov mil int io co xyz top site online club shop store app dev "
    "cloud tech pro name mobi asia tel travel jobs museum aero coop cat post xxx icu cyou "
    "buzz click link live life work fun vip win bid loan men review stream download trade "
    "date racing party science cricket accountant faith webcam website space press host "
    "digital network email solutions services support systems tools world today agency "
    "company center group zone onion".split()
)
_COUNTRY_TLDS = frozenset(
    "ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br "
    "bs bt bw by bz ca cc cd cf cg ch ci ck cl cm cn cr cu cv cw cx cy cz de dj dk dm do dz "
    "ec ee eg er es et eu fi fj fk fm fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu "
    "gw gy hk hm hn hr ht hu id ie il im in iq ir is it je jm jo jp ke kg kh ki km kn kp kr "
    "kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc me mg mh mk ml mm mn mo mp mq mr ms mt "
    "mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pm pn pr pt "
    "pw qa re ro ru rw sa sb sc sd se sg si sk sl sm sn sr ss st su sv sx sy sz tc td tf tg "
    "th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt "
    "za zm zw".split()
)
_AMBIGUOUS_CCTLDS = frozenset({"py", "sh", "pl", "rs", "md", "ps", "so"})
_VALID_TLDS = _GENERIC_TLDS | (_COUNTRY_TLDS - _AMBIGUOUS_CCTLDS)


def extract_domains(text: str) -> tuple[str, ...]:
    encontrados = _DOMAIN_RE.findall(text)
    minusculas = [d.lower() for d in encontrados]

    validos = []
    for d in minusculas:
        partes = d.split(".")
        tld = partes[-1]
        if tld in _VALID_TLDS:
            validos.append(d)

    return tuple(sorted(set(validos)))
