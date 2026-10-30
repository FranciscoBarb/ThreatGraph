import pytest

from threatgraph.graph.load import get_driver

pytestmark = pytest.mark.integration  # needs a running Neo4j


def test_can_connect_to_neo4j():
    with get_driver() as driver:
        driver.verify_connectivity()
