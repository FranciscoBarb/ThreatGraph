import os

from dotenv import load_dotenv
from neo4j import Driver, GraphDatabase, Session

from threatgraph.extract.iocs import IOCs


def get_driver() -> Driver:
    load_dotenv()
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ["NEO4J_PASSWORD"]
    return GraphDatabase.driver(uri, auth=(user, password))


_MERGE_THREAT_ACTOR = "MERGE (a:ThreatActor {name: $name})"


def merge_threat_actor(session: Session, name: str) -> None:
    session.run(_MERGE_THREAT_ACTOR, name=name)


_MERGE_REPORT = "MERGE (:Report {id: $report_id})"

_MENTION_IPS = """
MATCH (r:Report {id: $report_id})
UNWIND $values AS value
MERGE (n:IP_Address {address: value})
MERGE (r)-[:MENTIONS]->(n)
"""

_MENTION_DOMAINS = """
MATCH (r:Report {id: $report_id})
UNWIND $values AS value
MERGE (n:Domain {name: value})
MERGE (r)-[:MENTIONS]->(n)
"""

_MENTION_CVES = """
MATCH (r:Report {id: $report_id})
UNWIND $values AS value
MERGE (n:Vulnerability {cve_id: value})
MERGE (r)-[:MENTIONS]->(n)
"""

_MENTION_HASHES = """
MATCH (r:Report {id: $report_id})
UNWIND $hashes AS h
MERGE (n:FileHash {value: h.value})
  ON CREATE SET n.algorithm = h.algorithm
MERGE (r)-[:MENTIONS]->(n)
"""


def load_iocs(session: Session, report_id: str, iocs: IOCs) -> None:
    session.run(_MERGE_REPORT, report_id=report_id)
    session.run(_MENTION_IPS, report_id=report_id, values=list(iocs.ips))
    session.run(_MENTION_DOMAINS, report_id=report_id, values=list(iocs.domains))
    session.run(_MENTION_CVES, report_id=report_id, values=list(iocs.cves))
    hashes = [{"value": h.value, "algorithm": h.algorithm} for h in iocs.hashes]
    session.run(_MENTION_HASHES, report_id=report_id, hashes=hashes)
