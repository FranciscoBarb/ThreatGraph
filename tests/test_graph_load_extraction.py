import pytest

from threatgraph.extract.schemas import ReportExtraction
from threatgraph.graph.load import get_driver, load_extraction

pytestmark = pytest.mark.integration

REPORT_ID = "test-extraction-report-1"
OTHER_REPORT_ID = "test-extraction-report-2"
ACTOR = "TestActorForExtraction"
IP = "203.0.113.250"
DOMAIN = "test-extraction-domain.top"
HASH = "0123456789abcdef" * 4
CVE = "CVE-2099-0001"
TECHNIQUE_ID = "T9999"

TARGETS = {
    "USES_IP": IP,
    "USES_DOMAIN": DOMAIN,
    "USES_HASH": HASH,
    "EXPLOITS": CVE,
    "USES_TECHNIQUE": TECHNIQUE_ID,
}
EVIDENCE = {
    "USES_IP": f"{ACTOR} used {IP} as its command-and-control server.",
    "USES_DOMAIN": f"{ACTOR} staged tools on {DOMAIN}.",
    "USES_HASH": f"{ACTOR} deployed a binary with hash {HASH}.",
    "EXPLOITS": f"{ACTOR} exploited {CVE} to move laterally.",
    "USES_TECHNIQUE": f"{ACTOR} sent spear-phishing emails ({TECHNIQUE_ID}).",
}

# Matches only the nodes created by these tests, never real data.
_TEST_NODES = (
    "n.name IN [$actor, $domain] OR n.address = $ip OR n.value = $hash "
    "OR n.cve_id = $cve OR n.mitre_id = $technique OR n.id IN $reports"
)
_PARAMS = {
    "actor": ACTOR,
    "domain": DOMAIN,
    "ip": IP,
    "hash": HASH,
    "cve": CVE,
    "technique": TECHNIQUE_ID,
    "reports": [REPORT_ID, OTHER_REPORT_ID],
}


def make_extraction(evidence: dict[str, str] = EVIDENCE) -> ReportExtraction:
    return ReportExtraction.model_validate(
        {
            "actors": [{"name": ACTOR}],
            "techniques": [{"mitre_id": TECHNIQUE_ID, "name": "Test Technique"}],
            "relations": [
                {
                    "actor": ACTOR,
                    "type": relation_type,
                    "target": TARGETS[relation_type],
                    "evidence": text,
                }
                for relation_type, text in evidence.items()
            ],
        }
    )


def _cleanup(session) -> None:
    session.run(f"MATCH (n) WHERE {_TEST_NODES} DETACH DELETE n", **_PARAMS)


@pytest.fixture
def session():
    driver = get_driver()
    with driver.session() as session:
        _cleanup(session)
        yield session
        _cleanup(session)
    driver.close()


def count_test_graph(session) -> tuple[int, int]:
    nodes = session.run(f"MATCH (n) WHERE {_TEST_NODES} RETURN count(n) AS c", **_PARAMS).single()[
        "c"
    ]
    relationships = session.run(
        "MATCH (n)-[r]->() WHERE n.name = $actor OR n.id IN $reports RETURN count(r) AS c",
        **_PARAMS,
    ).single()["c"]
    return nodes, relationships


def relations_of_actor(session) -> list[tuple[str, str, str]]:
    records = session.run(
        "MATCH (:ThreatActor {name: $actor})-[r]->() "
        "RETURN type(r) AS type, r.source_report AS report, r.evidence AS evidence",
        actor=ACTOR,
    )
    return [(r["type"], r["report"], r["evidence"]) for r in records]


def test_relations_are_stored_with_report_and_evidence(session):
    load_extraction(session, REPORT_ID, make_extraction())

    expected = [(kind, REPORT_ID, text) for kind, text in EVIDENCE.items()]
    assert sorted(relations_of_actor(session)) == sorted(expected)


def test_report_mentions_its_actors_and_techniques(session):
    load_extraction(session, REPORT_ID, make_extraction())

    record = session.run(
        "MATCH (:Report {id: $report})-[:MENTIONS]->(n) "
        "WHERE n:ThreatActor OR n:Technique RETURN count(n) AS c",
        report=REPORT_ID,
    ).single()
    assert record["c"] == 2


def test_loading_the_same_extraction_twice_does_not_duplicate(session):
    load_extraction(session, REPORT_ID, make_extraction())
    first = count_test_graph(session)

    load_extraction(session, REPORT_ID, make_extraction())

    assert count_test_graph(session) == first


def test_reloading_a_report_keeps_one_relation_and_updates_the_evidence(session):
    load_extraction(session, REPORT_ID, make_extraction())
    new_text = f"{ACTOR} also relied on {IP} for exfiltration."

    load_extraction(session, REPORT_ID, make_extraction({**EVIDENCE, "USES_IP": new_text}))

    stored = relations_of_actor(session)
    assert len(stored) == 5
    assert ("USES_IP", REPORT_ID, new_text) in stored


def test_same_actor_in_two_reports_is_one_node_with_one_relation_per_report(session):
    load_extraction(session, REPORT_ID, make_extraction())
    load_extraction(session, OTHER_REPORT_ID, make_extraction())

    actors = session.run(
        "MATCH (a:ThreatActor {name: $actor}) RETURN count(a) AS c", actor=ACTOR
    ).single()["c"]
    reports = session.run(
        "MATCH (:ThreatActor {name: $actor})-[r:USES_IP]->(:IP_Address {address: $ip}) "
        "RETURN collect(r.source_report) AS reports",
        actor=ACTOR,
        ip=IP,
    ).single()["reports"]

    assert actors == 1
    assert sorted(reports) == [REPORT_ID, OTHER_REPORT_ID]
