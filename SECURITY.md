# Security

This library exists to make signed records checkable by someone who does not
trust the party that produced them, so a flaw in signing, hashing,
canonicalisation, chain validation or identity resolution is a security issue.

## Reporting

Please report suspected vulnerabilities privately through GitHub's
"Report a vulnerability" on this repository's Security tab, rather than in a
public issue. Say what you found, how to reproduce it, and which package and
version it affects. Expect an acknowledgement, not a service-level agreement:
this is pre-1.0 software maintained by a small team.

## What is and is not in scope

In scope: anything that lets a record verify that should not (a forged
signature, a hash collision through canonicalisation, a broken chain that
validates, a withheld payload read as verified or a tampered one read as
withheld, an identity resolved to the wrong key).

Not a vulnerability: that a valid signature does not prove the signer told the
truth, that an anchor does not prove goods were delivered, or that a name in a
self asserted registration is unverified. The documentation says so, and the
library is built around saying it.
