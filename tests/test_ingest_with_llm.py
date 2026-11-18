import json

import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel

from threatgraph.graph.load import get_driver
from threatgraph.ingest import ingest_file

pytestmark = pytest.mark.integration

REPORT_ID = "test-ingest-llm-report"
ACTOR = "TestIngestActor"
IP = "203.0.113.251"
SENTENCE = f"{ACTOR} used {IP} as its command-and-control server."
REPLY = json.dumps(
    {
        "actors": [{"name": ACTOR}],
        "techniques": [],
        "relations": [{"actor": ACTOR, "type": "USES_IP", "target": IP, "evidence": SENTENCE}],
    }
)

_CLEANUP = "MATCH (n) WHERE n.name = $actor OR n.address = $ip OR n.id = $report DETACH DELETE n"


@pytest.fixture
def session():
    driver = get_driver()
    with driver.session() as session:
        session.run(_CLEANUP, actor=ACTOR, ip=IP, report=REPORT_ID)
        yield session
        session.run(_CLEANUP, actor=ACTOR, ip=IP, report=REPORT_ID)
    driver.close()


@pytest.fixture
def report_file(tmp_path):
    path = tmp_path / f"{REPORT_ID}.txt"
    path.write_text(SENTENCE, encoding="utf-8")
    return path


def test_ingest_with_a_model_loads_iocs_and_relations(session, report_file):
    ingest_file(report_file, session, FakeListChatModel(responses=[REPLY]))

    relation = session.run(
        "MATCH (:ThreatActor {name: $actor})-[r:USES_IP]->(:IP_Address {address: $ip}) "
        "RETURN r.source_report AS report, r.evidence AS evidence",
        actor=ACTOR,
        ip=IP,
    ).single()
    mentions = session.run(
        "MATCH (:Report {id: $report})-[:MENTIONS]->(:IP_Address {address: $ip}) "
        "RETURN count(*) AS c",
        report=REPORT_ID,
        ip=IP,
    ).single()["c"]

    assert relation["report"] == REPORT_ID
    assert relation["evidence"] == SENTENCE
    assert mentions == 1  # the regex stage also ran


def test_ingest_without_a_model_only_does_the_regex_stage(session, report_file):
    ingest_file(report_file, session)

    actors = session.run(
        "MATCH (a:ThreatActor {name: $actor}) RETURN count(a) AS c", actor=ACTOR
    ).single()["c"]

    assert actors == 0
