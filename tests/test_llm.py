import json

from langchain_core.messages import AIMessage

from threatgraph.extract.llm import extract_with_llm
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
