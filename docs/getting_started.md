# Getting Started
This guide is meant to be a brief introduction for how to use keripy.  For a comprehensive 
overview of the protocol please refer to the [whitepaper](https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf)
or view other KERI related resources on the [KERI website](https://keri.one/keri-resources/).

## Identifier Types
There are two types of identifiers in KERI, basic self certifying identifiers and self-addressing self certifying identifiers

### Basic
A basic self-certifying identifier includes a prefix that is composed of a Base-64 (URL safe)
derivation code prepended to Base-64 encoding of a public digital signing key.

### Self-Addressing
A self addressing identifier allows inception configuration data to be included in the inception statement. 
The inception statement is cryptographically bound to the identifier by replacing the public key in the 
identifier prefix with a content digest (hash) of the inception statement and the incepting public key.

## Modes
The KERI protocol has two operational modes, Direct Replay Mode(Direct Mode) and Indirect Replay Mode(Indirect Mode).
This guide will dive into both modes.

### Direct Mode
Direct mode is used to communicate directly with another entity without reliance on supporting infrastructure like witness and validators

#### Inception
```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.base.keeping as keeping
import keri.db.dbing as dbing

with dbing.openDB(name="edy") as db, keeping.openKeep(name="edy") as kpr:
    # --------------------------------------------------------------------------
    # -----------------------Non Transferable Identifiers-----------------------
    # --------------------------------------------------------------------------
    
    # ---------------------Basic Non Transferable Identifier--------------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(keeper=kpr, salt=salt)
    verfers, digers = mgr.incept(icount=1, ncount=0)

    srdr = eventing.incept(keys=[verfers[0].qb64], code=coring.CryOneDex.Ed25519)
    print(srdr.raw.decode("utf-8"))
    print()

    # -----------------Self-Addressing Non Transferable Identifier--------------

    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(keeper=kpr, salt=salt)
    verfers, digers = mgr.incept(icount=1, ncount=0, transferable=False)

    srdr = eventing.incept(keys=[verfers[0].qb64], code=coring.CryOneDex.Blake3_256)
    print(srdr.raw.decode("utf-8"))
    print()
    
    # ----------Abandoned Self-Addressing Identifier(Non Transferable)----------
    # Has a transferable derivation code, but contains an empty pre-rotation key.  Essentially the identifier has been 
    # abandoned.  This example is for illustration purposes only you should never need to abandon a self-addressing 
    # identifier on inception.  Normally this is done with a rotation.
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(keeper=kpr, salt=salt)
    verfers, digers = mgr.incept(icount=1, ncount=0)

    srdr = eventing.incept(keys=[verfers[0].qb64], code=coring.CryOneDex.Blake3_256)
    print(srdr.raw.decode("utf-8"))
    print()

    # --------------------------------------------------------------------------
    # --------------------------Transferable Identifiers------------------------
    # --------------------------------------------------------------------------

    # -----------------------Basic Transferable Identifier----------------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(keeper=kpr, salt=salt)
    verfers, digers = mgr.incept(icount=1, ncount=1)

    keys = [verfers[0].qb64]

    nxt = coring.Nexter(digs=[digers[0].qb64]).qb64
    srdr = eventing.incept(keys=keys, nxt=nxt, code=coring.CryOneDex.Ed25519)
    print(srdr.raw.decode("utf-8"))
    print()

    # ------------------Self-Addressing Transferable Identifier-----------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(keeper=kpr, salt=salt)
    verfers, digers = mgr.incept(icount=1, ncount=1)

    keys = [verfers[0].qb64]

    nxt = coring.Nexter(digs=[digers[0].qb64]).qb64
    srdr = eventing.incept(keys=keys, nxt=nxt, code=coring.CryOneDex.Blake3_256)
    print(srdr.raw.decode("utf-8"))
    print()

    # -----------------Basic Non Transferable Multisig Identifier---------------

    # MULTI SIG NOT SUPPORTED FOR BASIC IDENTIFIERS

    # ----------------------Basic Transferable Multisig Identifier--------------------

    # MULTI SIG NOT SUPPORTED FOR BASIC IDENTIFIERS
    
```

### Indirect Mode
indirect mode supporting infrastructure like witness and validators to function securely. This mode supports all of the options shown under the direct mode heading as well as a few additional options. 
    
```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.base.keeping as keeping
import keri.db.dbing as dbing

with dbing.openDB(name="edy") as db, keeping.openKeep(name="edy") as kpr:
    # --------------------------------------------------------------------------
    # -----------------------Non Transferable Identifiers-----------------------
    # --------------------------------------------------------------------------
    
    # ------------Self-Addressing Non Transferable Multisig Identifier----------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(keeper=kpr, salt=salt)
    verfers, digers = mgr.incept(icount=3, ncount=0, transferable=False)

    srdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers], code=coring.CryOneDex.Blake3_256)
    print(srdr.raw.decode("utf-8"))
    print()

    # --------------------------------------------------------------------------
    # --------------------------Transferable Identifiers------------------------
    # --------------------------------------------------------------------------

    # -----------------Self-Addressing Transferable Multisig Identifier---------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(keeper=kpr, salt=salt)
    verfers, digers = mgr.incept(icount=3, ncount=3)

    keys = [verfer.qb64 for verfer in verfers]

    nxt = coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64
    srdr = eventing.incept(keys=keys, nxt=nxt, code=coring.CryOneDex.Blake3_256)
    print(srdr.raw.decode("utf-8"))
    print()
```

#### Signing An Inception Event
In order for an event to be valid it must be signed.  The Manager object can be used to sign an event. This will create
signatures, but they are not yet attached to the event.  See the section below for how to attach them to the event by 
creating an event message.

```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.base.keeping as keeping
import keri.db.dbing as dbing


with dbing.openDB(name="edy") as db, keeping.openKeep(name="edy") as kpr:
    # -----------------------Basic Transferable Identifier----------------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(keeper=kpr, salt=salt)
    verfers, digers = mgr.incept(icount=1, ncount=1)

    keys = [verfers[0].qb64]

    nxt = coring.Nexter(digs=[digers[0].qb64]).qb64
    srdr = eventing.incept(keys=keys, nxt=nxt, code=coring.CryOneDex.Ed25519)
    
    # Create Signatures
    sigers = mgr.sign(ser=srdr.raw, verfers=verfers)
```

#### Creating An Inception Event Message
Creating an event message involves appending count code prefixes and signatures to an event object.  
There is a function that will handle all this for you called messagize().
```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.base.keeping as keeping
import keri.db.dbing as dbing


with dbing.openDB(name="edy") as db, keeping.openKeep(name="edy") as kpr:
    # -----------------------Basic Transferable Identifier----------------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(keeper=kpr, salt=salt)
    verfers, digers = mgr.incept(icount=1, ncount=1)

    keys = [verfers[0].qb64]

    nxt = coring.Nexter(digs=[digers[0].qb64]).qb64
    srdr = eventing.incept(keys=keys, nxt=nxt, code=coring.CryOneDex.Ed25519)
    
    sigers = mgr.sign(ser=srdr.raw, verfers=verfers)
    
    # Create the message
    msg = eventing.messagize(srdr, sigers)
    print(msg)
    print()
```

#### Verifying An Inception Event Message
```python
import keri.core.eventing as eventing
import keri.core.coring as coring
import keri.base.keeping as keeping
import keri.db.dbing as dbing


with dbing.openDB(name="edy") as db, keeping.openKeep(name="edy") as kpr:
    # -----------------------Basic Transferable Identifier----------------------
    salt = coring.Salter().qb64

    # Init key pair manager
    mgr = keeping.Manager(keeper=kpr, salt=salt)
    verfers, digers = mgr.incept(icount=1, ncount=1)

    keys = [verfers[0].qb64]

    nxt = coring.Nexter(digs=[digers[0].qb64]).qb64
    srdr = eventing.incept(keys=keys, nxt=nxt, code=coring.CryOneDex.Ed25519)
    
    sigers = mgr.sign(ser=srdr.raw, verfers=verfers)
    
    # Create the message
    msg = eventing.messagize(srdr, sigers)
    
    # --------------------------------Validation--------------------------------
    kevery = eventing.Kevery(baser=db)
    valid = True
    try:
        kevery.processOne(ims=msg)
    except Exception:
        valid = False
    
    print("Valid: {}".format(valid))
    print()
```

#### Rotation

#### Abandonment
Abandonment or revocation is a subset of rotation.  KERI events always include a pre rotated key.  To abandon an 
identifier a rotation event is created and the pre rotated key is set to an empty string or null.