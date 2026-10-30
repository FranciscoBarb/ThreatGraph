import hashlib

import pytest

from threatgraph.extract.iocs import FileHash, IOCs
from threatgraph.graph.load import get_driver, load_iocs, merge_threat_actor

pytestmark = pytest.mark.integration  # needs a running Neo4j

TEST_ACTOR = "TEST-ACTOR-pytest"
TEST_REPORT = "test-report-pytest"
TEST_IOCS = IOCs(
    ips=("198.51.100.77",),
    domains=("pytest-only.test",),
    hashes=(FileHash(hashlib.sha256(b"threatgraph-pytest").hexdigest(), "SHA-256"),),
    cves=("CVE-1999-99999",),
)

_DELETE_TEST_DATA = """
MATCH (n)
WHERE (n:ThreatActor AND n.name = $actor)
   OR (n:Report AND n.id = $report)
   OR (n:IP_Address AND n.address IN $ips)
   OR (n:Domain AND n.name IN $domains)
   OR (n:FileHash AND n.value IN $hashes)
   OR (n:Vulnerability AND n.cve_id IN $cves)
DETACH DELETE n
"""


def _delete_test_data(session) -> None:
    session.run(
        _DELETE_TEST_DATA,
        actor=TEST_ACTOR,
        report=TEST_REPORT,
        ips=list(TEST_IOCS.ips),
        domains=list(TEST_IOCS.domains),
        hashes=[h.value for h in TEST_IOCS.hashes],
        cves=list(TEST_IOCS.cves),
    )


@pytest.fixture
def session():
    with get_driver() as driver, driver.session() as session:
        _delete_test_data(session)  # leftovers from a crashed run
        yield session
        _delete_test_data(session)


def count_test_actors(session) -> int:
    result = session.run(
        "MATCH (n:ThreatActor {name: $name}) RETURN count(n) AS total", name=TEST_ACTOR
    )
    return result.single()["total"]


def test_can_connect_to_neo4j():
    with get_driver() as driver:
        driver.verify_connectivity()


def test_merging_the_same_actor_twice_creates_one_node(session):
    merge_threat_actor(session, TEST_ACTOR)
    merge_threat_actor(session, TEST_ACTOR)

    assert count_test_actors(session) == 1


def test_loading_the_same_report_twice_creates_no_duplicates(session):
    load_iocs(session, TEST_REPORT, TEST_IOCS)
    load_iocs(session, TEST_REPORT, TEST_IOCS)

    result = session.run(
        "MATCH (r:Report {id: $report}) "
        "OPTIONAL MATCH (r)-[m:MENTIONS]->(x) "
        "RETURN count(DISTINCT r) AS reports, count(m) AS mentions, "
        "count(DISTINCT x) AS iocs",
        report=TEST_REPORT,
    ).single()

    assert (result["reports"], result["mentions"], result["iocs"]) == (1, 4, 4)
