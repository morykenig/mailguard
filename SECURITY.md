# Security policy

MailGuard is a security tool, so it is held to a higher bar: it processes attacker-written
input by design.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub's "Report a vulnerability"
(Security Advisories) rather than a public issue. Include steps to reproduce and, if possible,
a sample `.eml` file. You can expect an acknowledgement within 3 working days.

## In scope

* Bypassing request authentication, replay protection or response-signature verification
* Making the backend slow, crash or exhaust resources with a crafted email
* Getting attacker-controlled content rendered as markup or a clickable link in the add-on
* Leaking email content, secrets or indicators to logs or third parties
* Evading a detection that the README claims (please include the sample)

## Design references

* Threat model and controls: README §6
* Known detection gaps (documented as `xfail` tests): `backend/tests/test_redteam.py` and README §10
