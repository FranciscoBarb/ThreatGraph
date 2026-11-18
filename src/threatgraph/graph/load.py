import os

from dotenv import load_dotenv
from neo4j import Driver, GraphDatabase, Session

from threatgraph.extract.iocs import IOCs, extract_hashes
from threatgraph.extract.schemas import RelationType, ReportExtraction


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


_MENTION_ACTORS = """
MERGE (r:Report {id: $report_id})
WITH r
UNWIND $names AS name
MERGE (a:ThreatActor {name: name})
MERGE (r)-[:MENTIONS]->(a)
"""

_MENTION_TECHNIQUES = """
MERGE (r:Report {id: $report_id})
WITH r
UNWIND $techniques AS technique
MERGE (n:Technique {mitre_id: technique.mitre_id})
  ON CREATE SET n.name = technique.name
MERGE (r)-[:MENTIONS]->(n)
"""

# One fixed query per relation type: Cypher cannot take the relationship type as a
# parameter, and building it with an f-string would put model output inside the query.
_RELATION_QUERIES = {
    RelationType.USES_IP: """
        MERGE (a:ThreatActor {name: $actor})
        MERGE (t:IP_Address {address: $target})
        MERGE (a)-[r:USES_IP {source_report: $report_id}]->(t)
        SET r.evidence = $evidence
        """,
    RelationType.USES_DOMAIN: """
        MERGE (a:ThreatActor {name: $actor})
        MERGE (t:Domain {name: $target})
        MERGE (a)-[r:USES_DOMAIN {source_report: $report_id}]->(t)
        SET r.evidence = $evidence
        """,
    RelationType.USES_HASH: """
        MERGE (a:ThreatActor {name: $actor})
        MERGE (t:FileHash {value: $target})
          ON CREATE SET t.algorithm = $algorithm
        MERGE (a)-[r:USES_HASH {source_report: $report_id}]->(t)
        SET r.evidence = $evidence
        """,
    RelationType.EXPLOITS: """
        MERGE (a:ThreatActor {name: $actor})
        MERGE (t:Vulnerability {cve_id: $target})
        MERGE (a)-[r:EXPLOITS {source_report: $report_id}]->(t)
        SET r.evidence = $evidence
        """,
    RelationType.USES_TECHNIQUE: """
        MERGE (a:ThreatActor {name: $actor})
        MERGE (t:Technique {mitre_id: $target})
        MERGE (a)-[r:USES_TECHNIQUE {source_report: $report_id}]->(t)
        SET r.evidence = $evidence
        """,
}


def load_extraction(session: Session, report_id: str, extraction: ReportExtraction) -> None:
    session.run(
        _MENTION_ACTORS,
        report_id=report_id,
        names=[actor.name for actor in extraction.actors],
    )
    session.run(
        _MENTION_TECHNIQUES,
        report_id=report_id,
        techniques=[technique.model_dump() for technique in extraction.techniques],
    )
    for relation in extraction.relations:
        parameters = {
            "report_id": report_id,
            "actor": relation.actor,
            "target": relation.target,
            "evidence": relation.evidence,
        }
        if relation.type is RelationType.USES_HASH:
            # The target is already a validated hash: exactly one result.
            (file_hash,) = extract_hashes(relation.target)
            parameters["algorithm"] = file_hash.algorithm
        session.run(_RELATION_QUERIES[relation.type], **parameters)
