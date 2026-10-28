import hashlib

from threatgraph.extract.iocs import FileHash, extract_hashes

MD5 = hashlib.md5(b"threatgraph", usedforsecurity=False).hexdigest()  # Hashes with 32 characters
SHA1 = hashlib.sha1(b"threatgraph", usedforsecurity=False).hexdigest()  # Hashes with 40 characters
SHA256 = hashlib.sha256(b"threatgraph").hexdigest()  # Hashes with 64 characters


def test_md5_is_found_and_labelled():
    assert extract_hashes(f"dropper md5 {MD5}") == (FileHash(MD5, "MD5"),)


def test_uppercase_is_normalized_and_duplicates_collapse():
    text = f"{MD5.upper()} and again {MD5}"

    assert extract_hashes(text) == (FileHash(MD5, "MD5"),)


def test_hash_glued_to_other_alphanumerics_is_rejected():
    assert extract_hashes(f"g{MD5}") == ()
    assert extract_hashes(f"{MD5}z") == ()


def test_sha1_and_sha256_are_labelled():
    result = extract_hashes(f"sha1 {SHA1}; sha256 {SHA256}")

    assert set(result) == {FileHash(SHA1, "SHA-1"), FileHash(SHA256, "SHA-256")}


def test_unknown_length_hex_yields_nothing():
    forty_eight_hex = SHA256[:48]
    assert extract_hashes(forty_eight_hex) == ()


def test_longer_hashes_are_not_split_into_fake_ones():
    sha512 = hashlib.sha512(b"threatgraph").hexdigest()

    assert extract_hashes(sha512) == ()
