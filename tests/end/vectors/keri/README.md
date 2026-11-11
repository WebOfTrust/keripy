# KERI profile RFC 9421 vectors

These five files are copied verbatim from bakobo/fiki, `vectors/keri/`, at commit `e8e553f4e1780c5fa015c187ad5fe1f206e97e6f` on `main` (https://github.com/bakobo/fiki/tree/e8e553f4e1780c5fa015c187ad5fe1f206e97e6f/vectors/keri), `keri_vectors_format` 7. They test the KERI profile of RFC 9421, version 1.1, published at https://github.com/bakobo/fiki/blob/keri-profile-v1.1/docs/keri-profile.md. fiki generates them independently of keripy (`vectors/keri/generate.py` there), and signify-ts carries identical copies.

Do not edit them here. A case that disagrees with keripy is resolved against the profile and, if the vector is wrong, fixed in fiki and copied again. `tests/end/test_httpsigning.py` runs every case (`test_shared_vectors`).

- `rfc9421.json`: RFC 9421 Appendix B.2.6.
- `requests.json`, `responses.json`: messages a canonical verifier accepts, with the expected base.
- `refusals.json`: messages a canonical verifier refuses, each with its profile section 9 code.
- `legacy.json`: legacy signatures pinned in KERIA's and signify-ts's tests, and legacy messages fiki generated from controllers with more than one current key. Each generated case carries the key state the verifier holds for its `Signify-Resource`, the single effective signer that state reduces to (profile section 8), and its refusal code when it has one; `test_legacy_vectors_take_the_effective_signer` runs them.
