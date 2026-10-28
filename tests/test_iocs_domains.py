from threatgraph.extract.iocs import extract_domains


def test_domain_in_a_sentence_is_found():
    assert extract_domains("beacons to evil-domain.com daily") == ("evil-domain.com",)


def test_uppercase_is_normalized():
    assert extract_domains("EVIL.COM") == ("evil.com",)


def test_domain_at_the_end_of_a_sentence_loses_the_dot():
    assert extract_domains("contact evil.com.") == ("evil.com",)


def test_domain_inside_a_url_is_found():
    assert extract_domains("https://evil.com:8443/a") == ("evil.com",)


def test_ip_addresses_are_not_domains():
    assert extract_domains("1.2.3.4 and 185.220.101.5") == ()


def test_email_gives_its_domain_not_the_local_part():
    assert extract_domains("sent from john.smith@phish-bank.com") == ("phish-bank.com",)


def test_file_names_are_not_domains():
    assert extract_domains("dropped payload.exe and setup.py and report.pdf") == ()


def test_onion_leak_sites_are_found():
    assert extract_domains("see lockbit3abcdefg.onion") == ("lockbit3abcdefg.onion",)


def test_ambiguous_country_tlds_are_dropped_on_purpose():
    # Known limitation: .pl, .sh, .py... are real TLDs but far more often file extensions.
    # Revisit with the evaluation set in phase 5.
    assert extract_domains("scan.pl and install.sh and tienda.pl") == ()
