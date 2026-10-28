from threatgraph.extract.iocs import extract_cves


def test_finds_a_cve_in_a_sentence():
    assert extract_cves("exploits CVE-2023-2134 in the wild") == ("CVE-2023-2134",)


def test_long_sequence_numbers_are_not_truncated():
    assert extract_cves("CVE-2021-12345678") == ("CVE-2021-12345678",)


def test_lowercase_to_uppercase_conversion():
    assert extract_cves("cve-2021-12345678") == ("CVE-2021-12345678",)


def test_duplicates_collapse_to_one():
    assert extract_cves("CVE-2021-12345678 and CVE-2021-12345678") == ("CVE-2021-12345678",)


def test_result_is_sorted():
    assert extract_cves("CVE-2021-12345678 and CVE-2020-12345678") == (
        "CVE-2020-12345678",
        "CVE-2021-12345678",
    )


def test_short_sequence_number_is_rejected():
    assert extract_cves("CVE-2024-123") == ()


def test_cve_glued_to_a_letter_is_rejected():
    assert extract_cves("XCVE-2024-1234") == ()


def test_text_without_cves_returns_empty_tuple():
    assert extract_cves("nada que ver") == ()
