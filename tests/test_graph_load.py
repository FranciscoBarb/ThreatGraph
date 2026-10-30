import pytest

from threatgraph.graph.load import get_driver, merge_threat_actor

pytestmark = pytest.mark.integration  # needs a running Neo4j

TEST_ACTOR = "TEST-ACTOR-pytest"
_DELETE_TEST_DATA = "MATCH (n:ThreatActor {name: $name}) DETACH DELETE n"


@pytest.fixture
def session():
    with get_driver() as driver, driver.session() as session:
        session.run(_DELETE_TEST_DATA, name=TEST_ACTOR)  # leftovers from a crashed run
        yield session
        session.run(_DELETE_TEST_DATA, name=TEST_ACTOR)


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
