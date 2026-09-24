# KERI profile RFC 9421 vectors

These five files are copied verbatim from bakobo/fiki, `vectors/keri/`, at commit `530cd8c269675bb8fc311d8896034cfd2a46fafc`, `keri_vectors_format` 1. fiki generates them independently of keripy (`vectors/keri/generate.py` there), and signify-ts carries identical copies.

Do not edit them here. A case that disagrees with keripy is resolved against the profile and, if the vector is wrong, fixed in fiki and copied again. `tests/end/test_httpsigning.py` runs every case (`test_shared_vectors`).

- `rfc9421.json`: RFC 9421 Appendix B.2.6.
- `requests.json`, `responses.json`: messages a canonical verifier accepts, with the expected base.
- `refusals.json`: messages a canonical verifier refuses, each with its profile section 9 code.
- `legacy.json`: legacy signatures pinned in KERIA's and signify-ts's tests.
