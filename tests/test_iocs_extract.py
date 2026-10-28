import dataclasses
import hashlib

import pytest

from threatgraph.extract.iocs import FileHash, IOCs, extract_iocs

MD5 = hashlib.md5(b"payload", usedforsecurity=False).hexdigest()
SHA256 = hashlib.sha256(b"payload").hexdigest()

REPORT = f"""
LockBit affiliates exploited CVE-2023-4966 against exposed appliances.
C2 traffic went to 185.220.101.5 and update-check.top. The dropper
(payload.exe, md5 {MD5}) was followed by a second stage with SHA-256 {SHA256}.
Internal pivot host 192.168.1.20.
"""


def test_extracts_every_ioc_type_from_a_realistic_paragraph():
    result = extract_iocs(REPORT)

    assert result.cves == ("CVE-2023-4966",)
    assert result.ips == ("185.220.101.5", "192.168.1.20")
    assert result.domains == ("update-check.top",)
    assert set(result.hashes) == {FileHash(MD5, "MD5"), FileHash(SHA256, "SHA-256")}


def test_empty_text_gives_empty_result():
    assert extract_iocs("") == IOCs()


def test_result_is_immutable():
    with pytest.raises(dataclasses.FrozenInstanceError):
        extract_iocs(REPORT).ips = ()
