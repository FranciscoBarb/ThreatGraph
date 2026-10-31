from pathlib import Path

from neo4j import Session

from threatgraph.extract.iocs import IOCs, extract_iocs
from threatgraph.graph.load import load_iocs


def ingest_file(path: Path, session: Session) -> IOCs:
    text = path.read_text(encoding="utf-8")
    iocs = extract_iocs(text)
    load_iocs(session, path.stem, iocs)
    return iocs
