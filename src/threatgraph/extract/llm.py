import json
import re
from typing import Any, Protocol

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from pydantic import ValidationError

from threatgraph.extract.schemas import ReportExtraction


class ChatModel(Protocol):
    def invoke(self, messages: list[Any]) -> Any: ...


_INSTRUCTIONS = """\
You are a cyber threat intelligence analyst. Read the report and extract:
- actors: threat actor names mentioned in the report.
- techniques: MITRE ATT&CK techniques the report describes, with ID (e.g. T1566) and name.
- relations: facts of the form "actor does X". "type" is one of USES_IP, USES_DOMAIN,
  USES_HASH, EXPLOITS, USES_TECHNIQUE and "target" is the IP, domain, file hash, CVE ID or
  technique ID.

Rules:
- Only include a relation if the report states it explicitly. Never infer or guess.
- "evidence" must be one sentence copied word for word from the report that mentions both
  the actor and the target.
- Every actor named in a relation must also appear in "actors", and every technique used in
  a USES_TECHNIQUE relation must appear in "techniques".
- If there is nothing to extract, return empty lists.
- Reply with a single JSON object that follows the schema below. No explanations and no
  extra text.

JSON schema:
"""
_SYSTEM_PROMPT = _INSTRUCTIONS + json.dumps(ReportExtraction.model_json_schema())

_FENCE_RE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.DOTALL)


def _strip_fence(text: str) -> str:
    text = text.strip()
    match = _FENCE_RE.match(text)
    return match.group(1) if match else text


class ExtractionError(Exception):
    """The model never produced a reply that passes the schema."""


def _describe_error(error: ValidationError) -> str:
    """Short, readable list of what was wrong, to send back to the model."""
    lines = []
    for item in error.errors():
        where = ".".join(str(part) for part in item["loc"]) or "(root)"
        lines.append(f"- {where}: {item['msg']}")
    return "\n".join(lines)


def extract_with_llm(text: str, model: ChatModel, max_retries: int = 2) -> ReportExtraction:
    messages = [SystemMessage(content=_SYSTEM_PROMPT), HumanMessage(content=text)]
    problem = ""
    for _ in range(max_retries + 1):
        reply = model.invoke(messages)
        try:
            return ReportExtraction.model_validate_json(_strip_fence(reply.content))
        except ValidationError as error:
            problem = _describe_error(error)
            messages.append(AIMessage(content=reply.content))
            messages.append(
                HumanMessage(
                    content=(
                        f"Your previous reply was invalid:\n{problem}\n"
                        "Return the corrected JSON object only."
                    )
                )
            )
    raise ExtractionError(
        f"no valid extraction after {max_retries + 1} attempts. Last problems:\n{problem}"
    )
