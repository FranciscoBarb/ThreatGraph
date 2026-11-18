import argparse
from pathlib import Path

from neo4j import Session

from threatgraph.extract.iocs import IOCs, extract_iocs
from threatgraph.extract.llm import ChatModel, build_model, extract_with_llm
from threatgraph.graph.load import get_driver, load_extraction, load_iocs


def ingest_file(path: Path, session: Session, model: ChatModel | None = None) -> IOCs:
    text = path.read_text(encoding="utf-8")
    report_id = path.stem

    # Extract everything first and write afterwards: if the model fails,
    # nothing has been written and the graph stays as it was.
    iocs = extract_iocs(text)
    extraction = extract_with_llm(text, model) if model is not None else None

    load_iocs(session, report_id, iocs)
    if extraction is not None:
        load_extraction(session, report_id, extraction)
    return iocs


def main() -> None:
    parser = argparse.ArgumentParser(description="Load a report text file into Neo4j.")
    parser.add_argument("path", type=Path, help="path to a .txt report")
    args = parser.parse_args()

    with get_driver() as driver, driver.session() as session:
        iocs = ingest_file(args.path, session, build_model())

    print(
        f"Loaded {args.path.stem}: {len(iocs.ips)} IPs, {len(iocs.domains)} domains, "
        f"{len(iocs.hashes)} hashes, {len(iocs.cves)} CVEs"
    )


if __name__ == "__main__":
    main()
