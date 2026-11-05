import json
import re
from typing import Any, Protocol

from langchain_core.messages import HumanMessage, SystemMessage

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


def extract_with_llm(text: str, model: ChatModel) -> ReportExtraction:
    messages = [SystemMessage(content=_SYSTEM_PROMPT), HumanMessage(content=text)]
    reply = model.invoke(messages)
    return ReportExtraction.model_validate_json(_strip_fence(reply.content))
