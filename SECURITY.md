# Security Policy

## What this repository is

This is a **security disclosure** for Apache Log4j (`log4j-core`): configuration-time evaluation
of untrusted Thread Context Map data, leading to remote code execution. See `README.md` for the
finding and `WORKUP.md` for the full analysis.

**Disclosure status:** this repository is the first and only public disclosure of the issue. It
has not been reported to the Apache Logging Services project or any other vendor, and it has not
been published anywhere else before this repository.

## If you are affected

Please forward the finding to the vendor so it can be fixed in a supported release:

* Apache Logging Services security team: <security@apache.org>
* Process and reporting guidelines: <https://logging.apache.org/security.html>

## If you find a problem *in this repository*

Open a GitHub issue on this repository. Do **not** report it to the Apache Logging Services
team — it is a bug in the lab, not in Log4j.

## Using the lab

Everything in `lab/` binds to `127.0.0.1` and targets only the victim process it starts itself.
Do not point the lab at systems you do not own or are not authorised to test.
