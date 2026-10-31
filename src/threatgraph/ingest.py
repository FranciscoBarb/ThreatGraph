import argparse
from pathlib import Path

from neo4j import Session

from threatgraph.extract.iocs import IOCs, extract_iocs
from threatgraph.graph.load import get_driver, load_iocs


def ingest_file(path: Path, session: Session) -> IOCs:
    text = path.read_text(encoding="utf-8")
    iocs = extract_iocs(text)
    load_iocs(session, path.stem, iocs)
    return iocs


def main() -> None:
    parser = argparse.ArgumentParser(description="Load a report text file into Neo4j.")
    parser.add_argument("path", type=Path, help="path to a .txt report")
    args = parser.parse_args()

    with get_driver() as driver, driver.session() as session:
        iocs = ingest_file(args.path, session)

    print(
        f"Loaded {args.path.stem}: {len(iocs.ips)} IPs, {len(iocs.domains)} domains, "
        f"{len(iocs.hashes)} hashes, {len(iocs.cves)} CVEs"
    )


if __name__ == "__main__":
    main()
