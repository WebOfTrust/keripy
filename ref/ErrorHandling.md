# Coding Conventions: KERI Error Hierarchy

Source of exceptions: `keri/kering.py` (`KeriError` and subclasses).
Companion convention: [naming.md](./naming.md).

## Prefer standard Python exceptions

Custom exceptions (`KeriError` and subclasses) should be used only where a standard
Python exception is not suitable or descriptive enough, typically when callers need a
distinct catchable type that must not be confused with an ordinary `ValueError`,
`TypeError`, or similar.

Python’s exception tree is rich; inventing parallel types “because keripy has
KeriErrors” dilutes that tree and breaks dependents that already catch the standard
types. Default to the standard exception. Add or choose a `KeriError` subclass only
when the standard type cannot express the failure or the recovery policy.

This convention has been applied most thoroughly on the intake path (extract →
deserialize → validate). Elsewhere the custom tree is thinner, and many correct raises
remain ordinary Python exceptions.

## Why intake is thoroughly typed

KERI controllers, witnesses, watchers, and agents are long-running services. They
continuously pull messages from streams, parse them, validate them, and process the
next one. Failures on that path are expected: peers send malformed, incomplete, or
adversarial data. The service must catch, log, and continue without crashing.

A bare `ValueError` or `TypeError` at the top of `parse` / `process` is ambiguous: it
might be bad wire input or a real bug in local code. Catching all of them would
swallow programming errors; catching none would let every bad message take down the
process. So intake uses dedicated types:

1. **Extract** — `ExtractionError` (and subclasses) while pulling CESR from the stream.
2. **Deserialize** — `DeserializeError` (under extraction) for structural decode failures.
3. **Validate** — `ValidationError` (and subclasses) for protocol, signature, and
   state checks once a message is in hand.

Top-level parse/process code catches these (especially `ValidationError`), logs, and
moves on. Failures *not* raised as those types are presumed unexpected: they should
propagate (or hit an intentional, carefully placed catch-all) so real bugs surface.

### Generation is usually still a standard exception

Checks while *creating* local material—e.g. refusing a dumb threshold—are not
validating a peer message. A standard `ValueError` (or similar) is often exactly
right: tooling and tests should fail hard. Do not rewrite generation-time raises to
`ValidationError` merely to “match” the custom hierarchy.

Where construction *does* need a distinct catch (for example `EmptyMaterialError` so
`Matter` subclasses can intercept empty material during init), a `MaterialError`
subclass is appropriate, because the standard tree was not descriptive enough for that
control flow.

---

## Intake exceptions

### Extraction (`ExtractionError`)

Raised while pulling messages and attachments from a CESR stream—*before* value
validation. The parser is the primary consumer.

| Exception | Meaning |
|-----------|---------|
| `ShortageError` | Not enough bytes yet for a complete message or material |
| `ColdStartError` | Bad tritet in the first byte of a cold start |
| `SizedGroupError` | Failure inside an already-sized group (group already consumed) |
| `TopLevelStreamError` | Failure extracting at the top level of the stream |
| `VersionError` | Bad or unsupported version |
| `ProtocolError` | Bad or unsupported protocol type |
| `KindError` | Bad or unsupported serialization kind |
| `IlkError` | Bad or unsupported message type (ilk) |
| `ConversionError` | Base64 ↔ binary conversion failure |
| `DerivationCodeError` | Base for CESR code problems during extraction |
| `UnexpectedCodeError` | Unknown / unsupported derivation code |
| `UnexpectedCountCodeError` | Count-code start (`-`) encountered unexpectedly |
| `UnexpectedOpCodeError` | Opcode start (`_`) encountered unexpectedly |

### Deserialize (`DeserializeError` ⊂ `ExtractionError`)

Structural failures turning extracted bytes into a message object, still before
semantic validation.

| Exception | Meaning |
|-----------|---------|
| `FieldError` | Deserialized field error |
| `ElementError` | Deserialized element error |

### Validation (`ValidationError`)

Failures once a message is in hand: missing or extra fields, signatures, ordering,
duplicity, anchors, credentials, registry/TEL consistency, and related protocol
checks. This is the class long-running processors catch to log-and-continue.

**Field / shape**

| Exception | Meaning |
|-----------|---------|
| `MissingFieldError` | Required field or element missing |
| `ExtraFieldError` | Disallowed extra field |
| `AlternateFieldError` | Disallowed alternate field |
| `EmptyListError` | Required non-empty list is empty |
| `DerivationError` | Derivation-related validation failure |

**Signatures, receipts, proofs**

| Exception | Meaning |
|-----------|---------|
| `MissingSignatureError` | Below threshold of controller signatures |
| `MissingWitnessSignatureError` | Below threshold of witness signatures |
| `MissingDestinationError` | Destination (`i`) missing from an `exn` |
| `UnverifiedWitnessReceiptError` | Witness receipt unverified (event not yet in DB) |
| `UnverifiedReceiptError` | Receipt unverified (event not yet in DB) |
| `UnverifiedTransferableReceiptError` | Receipt from transferable AID unverified |
| `UnverifiedReplyError` | Reply not verified (usually missing sigs) |
| `UnverifiedProofError` | Credential CESR proof signature unverified |
| `UnverifiedBlindError` | Disclosed blind block does not reproduce anchored BLID |

**Ordering, delegation, KEL**

| Exception | Meaning |
|-----------|---------|
| `OutOfOrderError` | Prior event missing; cannot verify sigs yet (escrow candidate) |
| `OutOfOrderKeyStateError` | Referenced event missing for key-state verification |
| `OutOfOrderTxnStateError` | Referenced event missing for txn-state verification |
| `LikelyDuplicitousError` | Event is likely duplicitous |
| `MissingDelegationError` | Missing event with delegation source attachments |
| `MissingDelegableApprovalError` | Missing delegable approval evidence |
| `MisfitEventSourceError` | Event source does not fit expectations |
| `MisdigestError` | Prior digest breaks the hash chain (permanent; not escrow) |

**TEL / registry / credential binding**

| Exception | Meaning |
|-----------|---------|
| `MissingAnchorError` | TEL event not yet anchored to a validating KEL event |
| `MissingRegistryError` | Registry missing from Tevers |
| `MissingIssuerError` | Issuer missing from Tevers |
| `InvalidCredentialStateError` | Credential not issued or revoked |
| `MissequenceError` | TEL sequence breaks the strict chain rule (permanent) |
| `MisregistryError` | Update `rd` does not match registry inception SAID (permanent) |
| `MisanchorError` | Anchor seal found in a non-issuer KEL (permanent) |
| `RootSealError` | Aggregate/Merkle-style root seal without inclusion proof |
| `MisbindingError` | ACDC ↔ TEL binding equalities fail (permanent) |
| `DuplicitousRegistryError` | Two distinct anchored TEL events at the same sn |

Catch what you intend to recover from. An error that must not be treated as “bad
message, keep going” should not be raised as a `ValidationError` at the leaf—or
should be converted only at a stack frame that knows the recovery policy.

---

## Other `KeriError` groups

Same rule, applied less densely: use these only when a standard exception is not
suitable or descriptive enough for the named condition.

| Group | Exceptions (summary) |
|-------|----------------------|
| Resources / config | `ClosedError`, `ConfigurationError` |
| AuthN / AuthZ | `AuthError`, `AuthNError`, `AuthZError`, `DecryptError` |
| Database | `DatabaseError`, `MissingEntryError` |
| Material (crypto init) | `MaterialError`, `RawMaterialError`, `SoftMaterialError`, `EmptyMaterialError`, `InvalidVersionError`, `InvalidCodeError`, `InvalidSoftError`, `InvalidTypeError`, `InvalidValueError`, `InvalidSizeError`, and size subclasses |
| Serialize | `SerializeError` |
| Exchange / groups / schema | `ExchangeError`, `InvalidEventTypeError`, `MissingAidError`, `InvalidGroupError`, `GroupFormationError`, `MissingChainError`, `RevokedChainError`, `MissingSchemaError`, `FailedSchemaValidationError`, `UntrustedKeyStateSource`, `QueryNotFoundError` |
| KRAM | `KramError`, `KramConfigurationError`, `MissingAuthAttachmentError`, `MissingSenderKeyStateError` |

Do not assume every raise in nearby code must join the same group.

---

## Changing raised types

Swapping a raised type (e.g. `ValueError` → `ValidationError`) is a potentially
breaking change for dependents and for tests that assert the old type. Change 
only when the standard type is genuinely not suitable *and* call sites will
catch the new type correctly.  Prefer converting higher in the stack when only 
some paths need the custom semantics. If such a change is appropriately made, it should be 
described in the [change log](./ChangeLog.md).

Do not assume every raise should become a `KeriError`. When in doubt, keep the
standard exception or ask.
