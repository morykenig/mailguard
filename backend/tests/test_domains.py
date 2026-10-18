import pytest

from app.domains import find_lookalike, host_info, skeleton


@pytest.mark.parametrize(
    ("domain", "target", "technique"),
    [
        ("paypa1.com", "paypal.com", "homoglyph"),
        ("rnicrosoft.com", "microsoft.com", "homoglyph"),
        ("xn--pypal-4ve.com", "paypal.com", "homoglyph"),  # Cyrillic 'а'
        ("paypa1-secure.com", "paypal.com", "homoglyph"),
        ("paypal-secure.com", "paypal.com", "brand-in-name"),
        ("dhl-express-track.com", "dhl.com", "brand-in-name"),
        ("paypal.co", "paypal.com", "tld-swap"),
        ("gooogle.com", "google.com", "typo"),
        ("amazom.com", "amazon.com", "typo"),
    ],
)
def test_detects_lookalikes(domain, target, technique):
    match = find_lookalike(host_info(domain))
    assert match is not None
    assert (match.target, match.technique) == (target, technique)


@pytest.mark.parametrize(
    "domain", ["paypal.com", "www.paypal.com", "mail.google.com", "github.com", "groups.io", "example.com", "ups.com"]
)
def test_legitimate_domains_are_not_lookalikes(domain):
    assert find_lookalike(host_info(domain)) is None


def test_org_domain_is_protected():
    match = find_lookalike(host_info("upwlnd.io"), ("upwind.io",))
    assert match is not None and match.target == "upwind.io"


def test_registrable_domain_and_ip():
    assert host_info("a.b.example.co.uk").registrable == "example.co.uk"
    assert host_info("evil.web.app").registrable == "evil.web.app"  # PSL private suffix
    assert host_info("10.0.0.1").is_ip
    assert host_info("not a host") is None


def test_skeleton_collapses_confusables():
    assert skeleton("pаypa1") == skeleton("paypal")
    assert skeleton("rnicrosoft") == "microsoft"


@pytest.mark.parametrize(
    "domain",
    [
        "googlemail.com",
        "googleusercontent.com",
        "githubusercontent.com",
        "paypalobjects.com",
        "google.co.il",
        "finance.gov.il",
        "cloud.com",
        "mail.com",
        "start-ups.co.il",
        "live-music.com",
        "goo.ne.jp",
        "we.com",
    ],
)
def test_known_false_positive_traps(domain):
    assert find_lookalike(host_info(domain)) is None
