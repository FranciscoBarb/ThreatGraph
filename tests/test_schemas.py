import pytest
from pydantic import ValidationError

from threatgraph.extract.schemas import (
    Relation,
    RelationType,
    ReportExtraction,
    Technique,
    ThreatActor,
)

# Model tests for the Technique schema


def test_valid_technique_is_accepted():
    technique = Technique(mitre_id="T1566", name="Phishing")

    assert (technique.mitre_id, technique.name) == ("T1566", "Phishing")


def test_subtechnique_ids_are_accepted():
    technique = Technique(mitre_id="T1566.001", name="Spearphishing Attachment")

    assert technique.mitre_id == "T1566.001"


@pytest.mark.parametrize(
    "bad_id",
    [
        "1566",  # missing the T
        "T156",  # too short
        "T15666",  # too long
        "T1566.1",  # sub-technique needs three digits
        "TA0001",  # a tactic, not a technique
        "",
    ],
)
def test_invalid_mitre_ids_are_rejected(bad_id):
    with pytest.raises(ValidationError):
        Technique(mitre_id=bad_id, name="Phishing")


def test_mitre_id_is_normalized_to_uppercase_without_spaces():
    assert Technique(mitre_id=" t1566 ", name="Phishing").mitre_id == "T1566"


def test_empty_name_is_rejected():
    with pytest.raises(ValidationError):
        Technique(mitre_id="T1566", name="")


def test_unexpected_fields_are_rejected():
    with pytest.raises(ValidationError):
        Technique(mitre_id="T1566", name="Phishing", confidence="high")


# Model tests for the ThreatActor schema


def test_valid_threat_actor_is_accepted():
    assert ThreatActor(name="LockBit").name == "LockBit"


def test_actor_name_is_stripped():
    assert ThreatActor(name="  Lazarus Group  ").name == "Lazarus Group"


@pytest.mark.parametrize("bad_name", ["", "   "])
def test_empty_actor_name_is_rejected(bad_name):
    with pytest.raises(ValidationError):
        ThreatActor(name=bad_name)


def test_overlong_actor_name_is_rejected():
    with pytest.raises(ValidationError):
        ThreatActor(name="x" * 101)


def test_actor_unexpected_fields_are_rejected():
    with pytest.raises(ValidationError):
        ThreatActor(name="LockBit", country="RU")


# Model tests for the Relation schema

EVIDENCE = "LockBit operators used 185.220.101.5 as command and control."


def test_valid_relation_is_accepted():
    relation = Relation(actor="LockBit", type="USES_IP", target="185.220.101.5", evidence=EVIDENCE)

    assert relation.type is RelationType.USES_IP
    assert relation.evidence == EVIDENCE


def test_unknown_relation_type_is_rejected():
    with pytest.raises(ValidationError):
        Relation(actor="LockBit", type="LIKES", target="185.220.101.5", evidence=EVIDENCE)


@pytest.mark.parametrize("field", ["actor", "target", "evidence"])
def test_empty_fields_are_rejected(field):
    data = {
        "actor": "LockBit",
        "type": "USES_IP",
        "target": "185.220.101.5",
        "evidence": EVIDENCE,
    }
    data[field] = ""

    with pytest.raises(ValidationError):
        Relation(**data)


def test_llm_cannot_set_source_report():
    with pytest.raises(ValidationError):
        Relation(
            actor="LockBit",
            type="USES_IP",
            target="185.220.101.5",
            evidence=EVIDENCE,
            source_report="made-up-report",
        )


@pytest.mark.parametrize(
    ("relation_type", "target"),
    [
        ("USES_IP", "185.220.101.5"),
        ("USES_DOMAIN", "update-check.top"),
        ("USES_HASH", "489e45a95f2ac9c4d54bc44e4ae69c9f"),
        ("EXPLOITS", "CVE-2023-4966"),
        ("USES_TECHNIQUE", "T1566"),
    ],
)
def test_target_matching_the_type_is_accepted(relation_type, target):
    relation = Relation(actor="LockBit", type=relation_type, target=target, evidence=EVIDENCE)

    assert relation.target == target


@pytest.mark.parametrize(
    ("relation_type", "target"),
    [
        ("USES_IP", "update-check.top"),  # a domain where an IP goes
        ("USES_IP", "999.1.1.1"),  # octet out of range
        ("USES_IP", "see 185.220.101.5 here"),  # a sentence, not a bare value
        ("USES_DOMAIN", "185.220.101.5"),
        ("USES_DOMAIN", "payload.exe"),  # file name
        ("USES_HASH", "abc123"),  # too short
        ("USES_HASH", "CVE-2023-4966"),
        ("EXPLOITS", "T1566"),
        ("EXPLOITS", "CVE-2023-49"),  # sequence number too short
        ("USES_TECHNIQUE", "TA0001"),  # a tactic
        ("USES_TECHNIQUE", "Phishing"),  # a name, not an ID
    ],
)
def test_target_not_matching_the_type_is_rejected(relation_type, target):
    with pytest.raises(ValidationError):
        Relation(actor="LockBit", type=relation_type, target=target, evidence=EVIDENCE)


@pytest.mark.parametrize(
    ("relation_type", "raw", "canonical"),
    [
        ("USES_DOMAIN", "Update-Check.TOP", "update-check.top"),
        ("USES_HASH", "489E45A95F2AC9C4D54BC44E4AE69C9F", "489e45a95f2ac9c4d54bc44e4ae69c9f"),
        ("EXPLOITS", "cve-2023-4966", "CVE-2023-4966"),
        ("USES_TECHNIQUE", " t1566 ", "T1566"),
    ],
)
def test_target_is_normalized_to_its_canonical_form(relation_type, raw, canonical):
    relation = Relation(actor="LockBit", type=relation_type, target=raw, evidence=EVIDENCE)

    assert relation.target == canonical


def _payload(**overrides):
    data = {
        "actors": [{"name": "LockBit"}],
        "techniques": [{"mitre_id": "T1566", "name": "Phishing"}],
        "relations": [
            {
                "actor": "LockBit",
                "type": "USES_IP",
                "target": "185.220.101.5",
                "evidence": EVIDENCE,
            },
            {
                "actor": "LockBit",
                "type": "USES_TECHNIQUE",
                "target": "T1566",
                "evidence": "LockBit sent phishing emails.",
            },
        ],
    }
    data.update(overrides)
    return data


def test_empty_extraction_is_valid():
    extraction = ReportExtraction()

    assert (extraction.actors, extraction.techniques, extraction.relations) == ((), (), ())


def test_extraction_is_built_from_llm_style_json():
    extraction = ReportExtraction.model_validate(_payload())

    assert len(extraction.actors) == 1
    assert len(extraction.relations) == 2
    assert extraction.relations[0].type is RelationType.USES_IP


def test_relation_naming_an_unlisted_actor_is_rejected():
    with pytest.raises(ValidationError):
        ReportExtraction.model_validate(_payload(actors=[{"name": "Lazarus Group"}]))


def test_technique_relation_to_an_unlisted_technique_is_rejected():
    with pytest.raises(ValidationError):
        ReportExtraction.model_validate(_payload(techniques=[]))


def test_ioc_relations_do_not_need_a_listed_target():
    relations = [
        {
            "actor": "LockBit",
            "type": "EXPLOITS",
            "target": "CVE-2023-4966",
            "evidence": EVIDENCE,
        }
    ]

    extraction = ReportExtraction.model_validate(_payload(techniques=[], relations=relations))

    assert extraction.relations[0].target == "CVE-2023-4966"
