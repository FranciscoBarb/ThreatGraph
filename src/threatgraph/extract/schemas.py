from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class Technique(_StrictModel):
    mitre_id: str = Field(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")
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


class Relation(_StrictModel):
    actor: str = Field(min_length=1, max_length=100)
    type: RelationType
    target: str = Field(min_length=1)
    evidence: str = Field(min_length=1, max_length=1000)
