import re
from collections.abc import Callable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from threatgraph.extract.iocs import (
    extract_cves,
    extract_domains,
    extract_hashes,
    extract_ips,
)

_MITRE_ID_PATTERN = r"^T[0-9]{4}(\.[0-9]{3})?$"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class Technique(_StrictModel):
    mitre_id: str = Field(pattern=_MITRE_ID_PATTERN)
    name: str = Field(min_length=1)

    @field_validator("mitre_id", mode="before")
    @classmethod
    def normalize_mitre_id(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().upper()
        return value


class ThreatActor(_StrictModel):
    name: str = Field(min_length=1, max_length=100)


class RelationType(StrEnum):
    USES_IP = "USES_IP"
    USES_DOMAIN = "USES_DOMAIN"
    USES_HASH = "USES_HASH"
    EXPLOITS = "EXPLOITS"
    USES_TECHNIQUE = "USES_TECHNIQUE"


# Each function returns the canonical form of ``target`` if it is exactly one value of
# that kind, and None otherwise. The detection rules come from iocs.py, so there is a
# single definition of what an IP, a domain, a hash or a CVE is.
def _canonical_ip(target: str) -> str | None:
    found = extract_ips(target)
    return found[0] if found == (target,) else None


def _canonical_domain(target: str) -> str | None:
    found = extract_domains(target)
    return found[0] if found == (target.lower(),) else None


def _canonical_hash(target: str) -> str | None:
    found = extract_hashes(target)
    if len(found) == 1 and found[0].value == target.lower():
        return found[0].value
    return None


def _canonical_cve(target: str) -> str | None:
    found = extract_cves(target)
    return found[0] if found == (target.upper(),) else None


def _canonical_technique(target: str) -> str | None:
    candidate = target.upper()
    return candidate if re.fullmatch(_MITRE_ID_PATTERN, candidate) else None


_CANONICALIZERS: dict[RelationType, Callable[[str], str | None]] = {
    RelationType.USES_IP: _canonical_ip,
    RelationType.USES_DOMAIN: _canonical_domain,
    RelationType.USES_HASH: _canonical_hash,
    RelationType.EXPLOITS: _canonical_cve,
    RelationType.USES_TECHNIQUE: _canonical_technique,
}


class Relation(_StrictModel):
    actor: str = Field(min_length=1, max_length=100)
    type: RelationType
    target: str = Field(min_length=1)
    evidence: str = Field(min_length=1, max_length=1000)

    @field_validator("target")
    @classmethod
    def target_matches_type(cls, value: str, info: ValidationInfo) -> str:
        relation_type = info.data.get("type")
        if relation_type is None:  # the type itself was invalid: that error is already reported
            return value
        canonical = _CANONICALIZERS[relation_type](value)
        if canonical is None:
            raise ValueError(f"{value!r} is not a valid target for {relation_type}")
        return canonical
