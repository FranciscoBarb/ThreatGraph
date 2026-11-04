from pydantic import BaseModel, ConfigDict, Field, field_validator


class Technique(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    mitre_id: str = Field(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")
    name: str = Field(min_length=1)

    @field_validator("mitre_id", mode="before")
    @classmethod
    def normalize_mitre_id(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().upper()
        return value
