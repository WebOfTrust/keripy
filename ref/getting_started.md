# Getting Started
This guide is meant to be a brief introduction for how to use keripy.  For a comprehensive
overview of the protocol please refer to the [whitepaper](https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf)
or view other KERI related resources on the [KERI website](https://keri.one/keri-resources/).

## Transferability
KERI supports both transferable identifiers and ephemeral(non transferable) identifiers.

## Identifier Types
There are several types of identifiers in KERI:
 * Basic
 * Self-Addressing
 * Multi-Sig Self-Addressing
 * Delegated Self-Addressing

### Basic
A basic self-certifying identifier includes a prefix that is composed of a Base-64 (URL safe)
derivation code prepended to Base-64 encoding of a public digital signing key.

#### Inception

##### Non Transferable
```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.app.keeping as keeping
import keri.db.dbing as dbing

with dbing.openLMDB(name="edy") as db, keeping.openKS(name="edy") as kpr:
    # --------------------------------------------------------------------------
    # -----------------------Non Transferable Identifiers-----------------------
    # --------------------------------------------------------------------------

    # ---------------------Basic Non Transferable Identifier--------------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(ks=kpr, salt=salt)
    verfers, _, _, _ = mgr.incept(icount=1, ncount=0)

    srdr = eventing.incept(keys=[verfers[0].qb64], code=coring.MtrDex.Ed25519)  # code marks this identifier as basic
    print(srdr.raw.decode("utf-8"))
    print()
```

##### Transferable
```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.app.keeping as keeping
import keri.db.dbing as dbing

with dbing.openLMDB(name="edy") as db, keeping.openKS(name="edy") as kpr:
    # --------------------------------------------------------------------------
    # --------------------------Transferable Identifiers------------------------
    # --------------------------------------------------------------------------

    # -----------------------Basic Transferable Identifier----------------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(ks=kpr, salt=salt)
    verfers, digers, _, _ = mgr.incept(icount=1, ncount=1, transferable=True)

    keys = [verfers[0].qb64]

    srdr = eventing.incept(keys=keys, ndigs=[digers[0].qb64], code=coring.MtrDex.Ed25519)  # code marks this identifier as basic
    print(srdr.raw.decode("utf-8"))
    print()
```

#### Rotation

##### Non Transferable
In order to rotate, your identifier must be transferable.  You cannot change a transferable identifier to a
non transferable identifier after an inception event. You can however rotate to a null key(s) effectively abandoning
your identifier.

##### Transferable

```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.app.keeping as keeping
import keri.db.dbing as dbing

with dbing.openLMDB(name="edy") as db, keeping.openKS(name="edy") as kpr:
    # --------------------------------------------------------------------------
    # --------------------------Transferable Identifiers------------------------
    # --------------------------------------------------------------------------

    # -----------------------Basic Transferable Identifier----------------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(ks=kpr, salt=salt)
    verfers, digers, _, _ = mgr.incept(icount=1, ncount=1, transferable=True)

    keys = [verfers[0].qb64]

    srdr = eventing.incept(keys=keys, ndigs=[digers[0].qb64], code=coring.MtrDex.Ed25519)  # code marks this identifier as basic
    print(srdr.raw.decode("utf-8"))
    print()

    # -------------------------------Basic Rotation-----------------------------
    verfers, digers, _, _ = mgr.rotate(verfers[0].qb64)  # generate new keys

    # create rotation event
    identifier = srdr.pre
    keys = [verfers[0].qb64]
    icpDigest = srdr.saider.qb64
    srdr = eventing.rotate(pre=identifier, keys=keys, dig=icpDigest, ndigs=[digers[0].qb64], sn=1)

    print(srdr.raw.decode("utf-8"))
    print()
```

### Self-Addressing
A self addressing identifier allows inception configuration data to be included in the inception statement.
The inception statement is cryptographically bound to the identifier by replacing the public key in the
identifier prefix with a content digest (hash) of the inception statement and the incepting public key.

#### Inception

##### Non Transferable
```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.app.keeping as keeping
import keri.db.dbing as dbing

with dbing.openLMDB(name="edy") as db, keeping.openKS(name="edy") as kpr:
    # --------------------------------------------------------------------------
    # -----------------------Non Transferable Identifiers-----------------------
    # --------------------------------------------------------------------------

    # -----------------Self-Addressing Non Transferable Identifier--------------

    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(ks=kpr, salt=salt)
    verfers, _, _, _ = mgr.incept(icount=1, ncount=0, transferable=False)  # set a non transferable derivation code

    srdr = eventing.incept(keys=[verfers[0].qb64], code=coring.MtrDex.Blake3_256)  # code marks identifier as self-addressing
    print(srdr.raw.decode("utf-8"))
    print()

    # ----------Abandoned Self-Addressing Identifier(Non Transferable)----------
    # Has a transferable derivation code, but contains an empty pre-rotation key.  Essentially the identifier has been
    # abandoned.  This example is for illustration purposes only you should never need to abandon a self-addressing
    # identifier on inception.  Normally this is done with a rotation.
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(ks=kpr, salt=salt)
    verfers, _, _, _ = mgr.incept(icount=1, ncount=0, transferable=True)

    srdr = eventing.incept(keys=[verfers[0].qb64], code=coring.MtrDex.Blake3_256)  # empty nxt i.e. abandoned
    print(srdr.raw.decode("utf-8"))
    print()
```

##### Transferable
```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.app.keeping as keeping
import keri.db.dbing as dbing

with dbing.openLMDB(name="edy") as db, keeping.openKS(name="edy") as kpr:
    # --------------------------------------------------------------------------
    # --------------------------Transferable Identifiers------------------------
    # --------------------------------------------------------------------------

    # ------------------Self-Addressing Transferable Identifier-----------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(ks=kpr, salt=salt)
    verfers, digers, _, _ = mgr.incept(icount=1, ncount=1, transferable=True)

    keys = [verfers[0].qb64]

    srdr = eventing.incept(keys=keys, ndigs=[digers[0].qb64], code=coring.MtrDex.Blake3_256)  # code marks identifier as self-addressing
    print(srdr.raw.decode("utf-8"))
    print()
```

#### Rotation

##### Non Transferable
In order to rotate, your identifier must be transferable.  You cannot change a transferable identifier to a
non transferable identifier after an inception event. You can however rotate to a null key(s) effectively abandoning
your identifier.

##### Transferable

```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.app.keeping as keeping
import keri.db.dbing as dbing

with dbing.openLMDB(name="edy") as db, keeping.openKS(name="edy") as kpr:
    # --------------------------------------------------------------------------
    # --------------------------Transferable Identifiers------------------------
    # --------------------------------------------------------------------------

    # ------------------Self-Addressing Transferable Identifier-----------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(ks=kpr, salt=salt)
    verfers, digers, _, _ = mgr.incept(icount=1, ncount=1, transferable=True)

    keys = [verfers[0].qb64]

    srdr = eventing.incept(keys=keys, ndigs=[digers[0].qb64],
                           code=coring.MtrDex.Blake3_256)  # code marks identifier as self-addressing
    print(srdr.raw.decode("utf-8"))
    print()

    # --------------------------Self-Addressing Rotation------------------------
    verfers, digers, _, _ = mgr.rotate(verfers[0].qb64)  # generate new keys

    # create rotation event
    identifier = srdr.pre
    keys = [verfers[0].qb64]
    icpDigest = srdr.saider.qb64
    srdr = eventing.rotate(pre=identifier, keys=keys, dig=icpDigest, ndigs=[digers[0].qb64], sn=1)

    print(srdr.raw.decode("utf-8"))
    print()
```


### Multi-Sig Basic
This type is not supported by KERI

### Multi-Sig Self-Addressing

#### Inception

##### Non Transferable
```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.app.keeping as keeping
import keri.db.dbing as dbing

with dbing.openLMDB(name="edy") as db, keeping.openKS(name="edy") as kpr:
    # --------------------------------------------------------------------------
    # -----------------------Non Transferable Identifiers-----------------------
    # --------------------------------------------------------------------------

    # ------------Self-Addressing Non Transferable Multisig Identifier----------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(ks=kpr, salt=salt)
    verfers, _, _, _ = mgr.incept(icount=3, ncount=0, transferable=False)

    srdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers], code=coring.MtrDex.Blake3_256)  # code marks identifier as self-addressing
    print(srdr.raw.decode("utf-8"))
    print()
```

##### Transferable
```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.app.keeping as keeping
import keri.db.dbing as dbing

with dbing.openLMDB(name="edy") as db, keeping.openKS(name="edy") as kpr:
    # --------------------------------------------------------------------------
    # --------------------------Transferable Identifiers------------------------
    # --------------------------------------------------------------------------

    # --------------Self-Addressing Transferable Multisig Identifier------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(ks=kpr, salt=salt)
    verfers, digers, _, _ = mgr.incept(icount=3, ncount=3, transferable=True)

    keys = [verfer.qb64 for verfer in verfers]

    srdr = eventing.incept(keys=keys, ndigs=[diger.qb64 for diger in digers], code=coring.MtrDex.Blake3_256)  # code marks identifier as self-addressing
    print(srdr.raw.decode("utf-8"))
    print()
```

#### Rotation

##### Non Transferable
In order to rotate, your identifier must be transferable.  You cannot change a transferable identifier to a
non transferable identifier after an inception event. You can however rotate to a null key(s) effectively abandoning
your identifier.

##### Transferable

```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.app.keeping as keeping
import keri.db.dbing as dbing

with dbing.openLMDB(name="edy") as db, keeping.openKS(name="edy") as kpr:
    # --------------------------------------------------------------------------
    # --------------------------Transferable Identifiers------------------------
    # --------------------------------------------------------------------------

    # --------------Self-Addressing Transferable Multisig Identifier------------
    # ---------Self-Addressing Transferable Multisig Identifier Rotation--------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(ks=kpr, salt=salt)
    verfers, digers, _, _ = mgr.incept(icount=3, ncount=3, transferable=True)

    keys = [verfer.qb64 for verfer in verfers]

    srdr = eventing.incept(keys=keys, ndigs=[diger.qb64 for diger in digers],
                           code=coring.MtrDex.Blake3_256)  # code marks identifier as self-addressing
    print(srdr.raw.decode("utf-8"))
    print()

    # ---------Self-Addressing Transferable Multisig Identifier Rotation--------
    verfers, digers, _, _ = mgr.rotate(verfers[0].qb64, count=3)  # generate 3 new keys

    # create rotation event
    identifier = srdr.pre
    keys = [verfer.qb64 for verfer in verfers]
    icpDigest = srdr.saider.qb64
    srdr = eventing.rotate(pre=identifier, keys=keys, dig=icpDigest, ndigs=[digers[0].qb64], sn=1)

    print(srdr.raw.decode("utf-8"))
    print()
```

### Delegated Basic
This type is not supported by KERI

### Delegated Self-Addressing

#### Inception

##### Non Transferable

##### Transferable

#### Rotation

##### Non Transferable
In order to rotate, your identifier must be transferable.  You cannot change a transferable identifier to a
non transferable identifier after an inception event. You can however rotate to a null key(s) effectively abandoning
your identifier.

##### Transferable

## Message Types
There are currently two types of messages the KERI protocol uses Events and Receipts.

### Events
Events contain information about a controllers identifier and it's current or past key state.
See [KID0003](https://github.com/WebOfTrust/keri/blob/master/kids/kid0003.md#element-labels) for
explanations of the different keys meanings.  There are several types of event messages including:

* inception
    ```json
    {
      "v":"KERI10JSON0000e6_",
      "i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBOCJnPYabcas",
      "s":"0",
      "t":"icp",
      "kt":"1",
      "k":[
        "Dpt7mGZ3y5UmhT1NLExb1IW8vMJ8ylQW3K44LfkTgAqE"
      ],
      "n":"Erpltchg7BUv21Qz3ZXhOhVu63m7S7YbPb21lSeGYd90",
      "wt":"0",
      "w":[],
      "c":[]
    }
    ```
* rotation
    ```json
    {
      "v":"KERI10JSON000122_",
      "i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBOCJnPYabcas",
      "s":"1",
      "t":"rot",
      "p":"Ey2pXEnaoQVwxA4jB6k0QH5G2Us-0juFL5hOAHAwIEkc",
      "kt":"1",
      "k":[
        "D-HwiqmaETxls3vAVSh0xpXYTs94NUJX6juupWj_EgsA"
      ],
      "n":"ED6lKZwg-BWl_jlCrjosQkOEhqKD4BJnlqYqWmhqPhaU",
      "wt":"0",
      "wr":[],
      "wa":[],
      "a":[]
    }
    ```
* delegated inception
    ```json

    ```
* delegated rotation
    ```json

    ```
* interaction
    ```json
    {
      "v":"KERI10JSON000098_",
      "i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBOCJnPYabcas",
      "s":"2",
      "t":"ixn",
      "p":"EO7V6wDClWWiN_7sfGDTD8KsfRQaHyap6fz_O4CYvsek",
      "a":[]
    }
    ```

### Receipts
Receipts are used to confirm and or prove that a witness or validator received an event message.  The receipt is signed
by the validator or witness and can be used to detect duplicity if the witness or validator ever tries to claim it never
saw the event. There are two types of receipts:
* Witness Receipts
    ```json

    ```
* Validator Receipts
    ```json
    {
      "v":"KERI10JSON000105_",
      "i":"EsU9ZQwug7DS-GU040Ugj1t7p6Au14VkBOCJnPYabcas",
      "s":"2",
      "t":"vrc",
      "d":"EuCLxtdKdRgzzgBnPhTwFKz36u58DqQyMqhX5CUrurPE",
      "a":{
        "i":"EBiIFxr_o1b4x1YR21PblAFpFG61qDghqFBDyVSOXYW0",
        "s":"0",
        "d":"ElsHFkbZQjRb7xHnuE-wyiarIZ9j-1CEQ89I0E3WevcE"
      }
    }
    ```

## Modes
The KERI protocol has two operational modes, Direct Replay Mode(Direct Mode) and Indirect Replay Mode(Indirect Mode).
This guide will dive into both modes.

### Direct Mode
Direct mode is used to communicate directly with another entity without reliance on supporting infrastructure like witness and validators

### Indirect Mode
Indirect mode needs supporting infrastructure like witness and validators to function securely. This mode supports all of the options shown under the direct mode heading as well as a few additional options.

## Event Life Cycle

#### Creating An Inception Event Message
Creating an event message involves appending count code prefixes and signatures to an event object.
There is a function that will handle all this for you called messagize().
```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.app.keeping as keeping
import keri.db.dbing as dbing

with dbing.openLMDB(name="edy") as db, keeping.openKS(name="edy") as kpr:
    # -----------------------Basic Transferable Identifier----------------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(ks=kpr, salt=salt)
    verfers, digers, _, _ = mgr.incept(icount=1, ncount=1)

    keys = [verfers[0].qb64]
    srdr = eventing.incept(keys=keys, ndigs=[digers[0].qb64], code=coring.MtrDex.Ed25519)
    sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

    # Create the message
    msg = eventing.messagize(srdr, sigers=sigers)
    print(msg)
    print()
```

#### Signing An Inception Event
In order for an event to be valid it must be signed.  The Manager object can be used to sign an event. This will create
signatures, but they are not yet attached to the event.  See the section below for how to attach them to the event by
creating an event message.

```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.app.keeping as keeping
import keri.db.dbing as dbing

with dbing.openLMDB(name="edy") as db, keeping.openKS(name="edy") as kpr:
    # -----------------------Basic Transferable Identifier----------------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(ks=kpr, salt=salt)
    verfers, digers, _, _ = mgr.incept(icount=1, ncount=1)

    keys = [verfers[0].qb64]

    srdr = eventing.incept(keys=keys, ndigs=[digers[0].qb64], code=coring.MtrDex.Ed25519)

    # Create Signatures
    sigers = mgr.sign(ser=srdr.raw, verfers=verfers)
```

#### Verifying An Inception Event Message
```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.core.parsing as parsing
import keri.app.keeping as keeping
import keri.db.dbing as dbing

with dbing.openLMDB(name="edy") as db, keeping.openKS(name="edy") as kpr:
    # -----------------------Basic Transferable Identifier----------------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(ks=kpr, salt=salt)
    verfers, digers, _, _ = mgr.incept(icount=1, ncount=1)

    keys = [verfers[0].qb64]

    srdr = eventing.incept(keys=keys, ndigs=[digers[0].qb64], code=coring.MtrDex.Ed25519)

    sigers = mgr.sign(ser=srdr.raw, verfers=verfers)

    # Create the message
    msg = eventing.messagize(srdr, sigers=sigers)

    # --------------------------------Validation--------------------------------
    kevery = eventing.Kevery(db=db)
    valid = True
    try:
        parsing.Parser().parseOne(ims=msg, kvy=kevery)
    except Exception:
        valid = False

    print("Valid: {}".format(valid))
    print()
```

#### Rotating Keys

```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.app.keeping as keeping
import keri.db.dbing as dbing

with dbing.openLMDB(name="edy") as db, keeping.openKS(name="edy") as kpr:
    # -----------------------Basic Transferable Identifier----------------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(ks=kpr, salt=salt)
    verfers, digers, _, _ = mgr.incept(icount=1, ncount=1, transferable=True)

    keys = [verfers[0].qb64]

    srdr = eventing.incept(keys=keys, ndigs=[digers[0].qb64], code=coring.MtrDex.Ed25519)  # code marks this identifier as basic

    print(srdr.raw.decode("utf-8"))
    print()

    # -------------------------------Basic Rotation-----------------------------
    verfers, digers, _, _ = mgr.rotate(verfers[0].qb64)  # generate new keys

    # create rotation event
    identifier = srdr.pre
    keys = [verfers[0].qb64]
    icpDigest = srdr.saider.qb64
    srdr = eventing.rotate(pre=identifier, keys=keys, dig=icpDigest, ndigs=[digers[0].qb64], sn=1)  # Create rotation event

    print(srdr.raw.decode("utf-8"))
    print()
```

#### Interaction

#### Abandonment
Abandonment or revocation is a subset of rotation.  KERI events always include a pre rotated key.  To abandon an
identifier a rotation event is created and the pre rotated key is set to an empty string or null.

```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.app.keeping as keeping
import keri.db.dbing as dbing

with dbing.openLMDB(name="edy") as db, keeping.openKS(name="edy") as kpr:
    # -----------------------Basic Transferable Identifier----------------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(ks=kpr, salt=salt)
    verfers, digers, _, _ = mgr.incept(icount=1, ncount=1, transferable=True)

    keys = [verfers[0].qb64]

    srdr = eventing.incept(keys=keys, ndigs=[digers[0].qb64], code=coring.MtrDex.Ed25519)  # code marks this identifier as basic

    print(srdr.raw.decode("utf-8"))
    print()

    # ------------------------------Basic Abandonment---------------------------
    verfers, digers, _, _ = mgr.rotate(verfers[0].qb64,
                                       count=0)  # grab inception next keys but generate no next keys for rotation

    # create rotation event
    identifier = srdr.pre
    keys = [verfers[0].qb64]
    icpDigest = srdr.saider.qb64
    srdr = eventing.rotate(pre=identifier, keys=keys, dig=icpDigest, sn=1)  # nxt is empty i.e. abandoned

    print(srdr.raw.decode("utf-8"))
    print()
```
