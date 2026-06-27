# Configuration File Labels

## Overview

KERI habitats store configuration in a JSON (or HJSON, MsgPack, or CBOR) file
managed by `src/keri/app/configing.py`.  This document describes the labels
(keys) used in that configuration file.

The labels below are drawn from the existing `Configer` docstring examples and
the hab configuration logic in `src/keri/app/habbing.py`.

## Example configuration

```json
{
    "dt": "2021-01-01T00:00:00.000000+00:00",
    "nel": {
        "dt": "2021-01-01T00:00:00.000000+00:00",
        "curls": [
            "tcp://localhost:5621/"
        ]
    },
    "iurls": [
        "tcp://localhost:5620/?role=peer&name=tam"
    ],
    "durls": [
        "http://127.0.0.1:7723/oobi/EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy",
        "http://127.0.0.1:7723/oobi/EMhvwOlyEJ9kN4PrwCpr9Jsv7TxPhiYveZ0oP3lJzdEi"
    ],
    "wurls": [
        "http://127.0.0.1:5644/.well-known/keri/oobi/EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy?name=Root"
    ]
}
```

## Label reference

| Label   | Meaning                          | Type / shape     | Example                                          | Notes |
|---------|----------------------------------|------------------|--------------------------------------------------|-------|
| `dt`    | Datetime                         | ISO 8601 string  | `"2021-01-01T00:00:00.000000+00:00"`            | Timestamp of the configuration file. Must be parseable by `fromIso8601`. |
| `nel`   | Network endpoint list            | Object           | `{"dt": "...", "curls": ["tcp://..."]}`          | Contains the controller's own datetime and controller URLs. |
| `curls` | Controller URLs                  | Array of strings | `["tcp://localhost:5621/"]`                      | TCP endpoints where this controller accepts connections. Used by witnesses and other peers to reach the controller. Nested inside `nel`. |
| `iurls` | Introduction OOBI URLs           | Array of strings | `["tcp://localhost:5620/?role=peer&name=tam"]`   | Out-of-band introduction URLs. Written to `db.oobis` so the habitat can discover other identifiers. |
| `durls` | Delegation OOBI URLs             | Array of strings | `["http://127.0.0.1:7723/oobi/EB..."]`           | Delegation OOBI URLs. Written to `db.oobis`. Used when the identifier has delegated authority relationships. |
| `wurls` | Well-known (MFA) OOBI URLs       | Array of strings | `["http://127.0.0.1:5644/.well-known/keri/oobi/EB...?name=Root"]` | Well-known OOBI URLs for multi-factor authentication (MFA). Written to `db.woobi`. |

## Usage notes

- The configuration file location depends on the `Configer` tail directory
  (`keri/cf/`, `keri/clean/cf/`, `.keri/cf/`, or `.keri/clean/cf/`).
- File format is determined by extension: `.json` (HJSON), `.mgpk` (MsgPack),
  or `.cbor` (CBOR).
- Labels are processed in `src/keri/app/habbing.py` during habitat creation
  and rotation.  Unrecognized labels are ignored.

## Related code

- `src/keri/app/configing.py` — `Configer` class reads and writes the config
  file.
- `src/keri/app/habbing.py` — Habitat creation and rotation logic processes
  `iurls`, `durls`, `wurls`, `curls`, and `dt`.
