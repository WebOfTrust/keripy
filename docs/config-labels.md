# Configuration File Labels

## Overview

KERI configuration files are managed by `src/keri/app/configing.py`.
A file may contain both Habery-level settings and sections for individual
habitats:

- `Habery.reconfigure()` reads Habery-level settings from the top level.
- `Hab.reconfigure()` reads habitat-specific settings from the object keyed
  by that habitat's name.

The habitat-name key is dynamic. Names such as `tam` and `nel` in existing
examples are habitat names, not reserved configuration labels.

## Configuration shape

```json
{
    "dt": "2026-07-30T00:00:00.000000+00:00",
    "iurls": [
        "tcp://localhost:5620/?role=peer&name=tam"
    ],
    "durls": [
        "http://127.0.0.1:7723/oobi/EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy"
    ],
    "wurls": [
        "http://127.0.0.1:5644/.well-known/keri/oobi/EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy?name=Root"
    ],
    "<hab-name>": {
        "dt": "2026-07-30T00:00:00.000000+00:00",
        "curls": [
            "tcp://localhost:5621/"
        ]
    }
}
```

Replace `<hab-name>` with the habitat's actual name. For example, a habitat
named `tam` uses a top-level `"tam"` object. The literal key
`"<hab-name>"` is only a placeholder in this documentation.

## Habery-level labels

`Habery.reconfigure()` reads these labels from the top level of the
configuration object.

| Label | Meaning | Type / shape | Notes |
|---|---|---|---|
| `dt` | Configuration datetime | ISO 8601 string | Parsed with `fromIso8601`. Habery-level OOBI processing occurs when this label is present. |
| `iurls` | Introduction OOBI URLs | Array of strings | Written to `db.oobis` as `OobiRecord` entries. |
| `durls` | Delegation OOBI URLs | Array of strings | Written to `db.oobis` as `OobiRecord` entries. |
| `wurls` | Well-known OOBI URLs | Array of strings | Written to `db.woobi` as `OobiRecord` entries. |

## Habitat-level sections

Each habitat-specific section is keyed by the habitat's actual name.
`Hab.reconfigure()` selects `conf[self.name]` and reads these labels from
that object.

| Label | Meaning | Type / shape | Notes |
|---|---|---|---|
| `dt` | Habitat configuration datetime | ISO 8601 string | Parsed with `fromIso8601`. Controller endpoint setup occurs when this label is present. |
| `curls` | Controller URLs | Array of strings | Used to create the habitat's controller end-role authorization and location-scheme records. |

A habitat section therefore has this shape:

```json
{
    "<hab-name>": {
        "dt": "2026-07-30T00:00:00.000000+00:00",
        "curls": [
            "tcp://localhost:5621/"
        ]
    }
}
```

## Usage notes

- The configuration file is read during initialization and is intended to
  preload database state, not serve as a live runtime database.
- The configuration file location depends on the `Configer` tail directory:
  `keri/cf/`, `keri/clean/cf/`, `.keri/cf/`, or
  `.keri/clean/cf/`.
- File format is selected by extension: `.json` (HJSON when
  `human=True`, strict JSON when `human=False`), `.mgpk` (MsgPack), or
  `.cbor` (CBOR).
- Unrecognized labels are not processed by the reconfiguration methods
  described above.

## Related code

- `src/keri/app/configing.py` — `Configer` reads and writes the
  configuration file.
- `src/keri/app/habbing.py` — `Habery.reconfigure()` and
  `Hab.reconfigure()` consume the two configuration levels.
- `tests/app/test_habbing_v1.py` — demonstrates habitat-name keys such as
  `tam` and `nel`.
