import pytest
from pydantic import ValidationError

from threatgraph.extract.schemas import Technique


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
