from threatgraph.extract.iocs import extract_ips


def test_ip_in_a_sentence_is_found_without_the_trailing_dot():
    assert extract_ips("The C2 was 45.33.32.156.") == ("45.33.32.156",)


def test_out_of_range_octets_are_rejected():
    assert extract_ips("256.1.1.1 and 999.999.999.999") == ()


def test_result_is_sorted_numerically_not_alphabetically():
    text = "45.33.32.156, 8.8.8.8, 45.33.32.156"

    assert extract_ips(text) == ("8.8.8.8", "45.33.32.156")


def test_version_strings_with_five_groups_are_not_ips():
    assert extract_ips("version 1.2.3.4.5") == ()


def test_leading_zero_is_rejected():
    assert extract_ips("01.2.3.4") == ()


def test_private_addresses_are_kept():
    assert extract_ips("pivot 192.168.1.10 and 10.0.0.5") == ("10.0.0.5", "192.168.1.10")


def test_ip_inside_urls_and_ports_is_found():
    assert extract_ips("http://45.33.32.156:8080/gate.php and 8.8.8.8:443") == (
        "8.8.8.8",
        "45.33.32.156",
    )
