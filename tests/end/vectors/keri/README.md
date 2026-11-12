# KERI profile RFC 9421 vectors

These five files are copied verbatim from bakobo/fiki, `vectors/keri/`, at commit `63821f7ac4fd6e4062b3932e77e325a7227b4f6d` on `main`, tagged `keri-profile-v1.2` (https://github.com/bakobo/fiki/tree/63821f7ac4fd6e4062b3932e77e325a7227b4f6d/vectors/keri), `keri_vectors_format` 8. They test the KERI profile of RFC 9421, version 1.2, published at https://github.com/bakobo/fiki/blob/keri-profile-v1.2/docs/keri-profile.md. fiki generates them independently of keripy (`vectors/keri/generate.py` there), and signify-ts carries identical copies.

Do not edit them here. A case that disagrees with keripy is resolved against the profile and, if the vector is wrong, fixed in fiki and copied again. `tests/end/test_httpsigning.py` runs every case (`test_shared_vectors`).

- `rfc9421.json`: RFC 9421 Appendix B.2.6.
- `requests.json`, `responses.json`: messages a canonical verifier accepts, with the expected base. The cases marked `verified_by_fiki` false, a `Signature` and a `Content-Digest` without their `=` padding, are ones fiki carries as data; keripy verifies them like every other case.
- `refusals.json`: messages a canonical verifier refuses, each with its profile section 9 code.
- `legacy.json`: legacy signatures pinned in KERIA's and signify-ts's tests, and legacy messages fiki generated from controllers with more than one current key. Each generated case carries the key state the verifier holds for its `Signify-Resource` (null for none), its `sufficient_keys`, every current key that alone satisfies the signing threshold (profile section 8), and its refusal code when it has one; `test_legacy_vectors_take_any_sufficient_key` runs them.
