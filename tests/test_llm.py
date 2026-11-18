import json

import pytest
from langchain_core.messages import AIMessage

from threatgraph.extract.llm import ExtractionError, extract_with_llm
from threatgraph.extract.schemas import RelationType, ReportExtraction

REPORT = "LockBit operators used 185.220.101.5 as command and control."

VALID_REPLY = json.dumps(
    {
        "actors": [{"name": "LockBit"}],
        "techniques": [],
        "relations": [
            {
                "actor": "LockBit",
                "type": "USES_IP",
                "target": "185.220.101.5",
                "evidence": REPORT,
            }
        ],
    }
)

# Same reply, but with no actors: the relation names LockBit and that actor
# is not listed, so ReportExtraction rejects it.
INVALID_REPLY = json.dumps({**json.loads(VALID_REPLY), "actors": []})


class ScriptedModel:
    """Stands in for a chat model: returns canned replies and records what it was sent."""

    def __init__(self, *replies: str):
        self._replies = list(replies)
        self.calls = []

    def invoke(self, messages):
        self.calls.append(list(messages))
        return AIMessage(content=self._replies.pop(0))


def test_valid_json_reply_becomes_a_report_extraction():
    extraction = extract_with_llm(REPORT, ScriptedModel(VALID_REPLY))

    assert isinstance(extraction, ReportExtraction)
    assert extraction.relations[0].type is RelationType.USES_IP


def test_json_wrapped_in_a_markdown_fence_is_accepted():
    model = ScriptedModel(f"```json\n{VALID_REPLY}\n```")

    assert extract_with_llm(REPORT, model).actors[0].name == "LockBit"


def test_the_report_text_is_sent_to_the_model():
    model = ScriptedModel(VALID_REPLY)

    extract_with_llm(REPORT, model)

    sent = " ".join(str(message.content) for message in model.calls[0])
    assert REPORT in sent


def test_invalid_reply_is_retried_and_the_error_is_sent_back():
    model = ScriptedModel(INVALID_REPLY, VALID_REPLY)

    extraction = extract_with_llm(REPORT, model)

    assert isinstance(extraction, ReportExtraction)
    assert len(model.calls) == 2
    # The second attempt carries the reason for the failure so the model can fix it
    assert "unlisted actor" in str(model.calls[1][-1].content)


def test_reply_that_is_not_json_is_retried():
    model = ScriptedModel("this is not json", VALID_REPLY)

    extraction = extract_with_llm(REPORT, model)

    assert isinstance(extraction, ReportExtraction)
    assert len(model.calls) == 2


def test_gives_up_after_max_retries():
    model = ScriptedModel(INVALID_REPLY, INVALID_REPLY, INVALID_REPLY)

    with pytest.raises(ExtractionError):
        extract_with_llm(REPORT, model, max_retries=2)

    # 1 initial attempt + 2 retries
    assert len(model.calls) == 3
