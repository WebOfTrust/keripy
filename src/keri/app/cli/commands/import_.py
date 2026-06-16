# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.import_ module

`kli import` - import a CESR stream or set of exported .cesr files.

Usage examples:
  Importing files:
    - kli import -n mykeystore --base /path/to/bases --cesr-in /tmp/my_cesr_exported_files/
  stdin:
    - cat big-bundle.cesr | kli import -n mykeystore -b "" --cesr-in -
"""

import argparse
import os
import sys

from hio.base import doing

from keri import help
from keri.app.cli.common import existing
from keri.core import parsing, eventing, routing, serdering
from keri.peer import exchanging
from keri.vdr import credentialing, eventing as teventing, verifying, viring

logger = help.ogler.getLogger()

importParser = argparse.ArgumentParser(description="Import a CESR stream or set of .cesr files into a local keystore.")
importParser.set_defaults(handler=lambda args: do_import(args),
                          transferable=True)

importParser.add_argument('--name', '-n', help='keystore name and file location of keystore', required=True)
importParser.add_argument('--base', '-b', help='additional optional prefix to file location of keystore',
                         required=False, default="")
importParser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                         dest="bran", default=None)
importParser.add_argument('--cesr-in', help='Path to a CESR file, directory of .cesr files, or "-" for stdin',
                         required=False, default=None)


def do_import(args):
    """Entry point for the import command. Returns doers for the controller."""
    imp = ImportDoer(name=args.name,
                     base=args.base,
                     bran=args.bran,
                     cesrIn=args.cesr_in)
    return [imp]


class ImportDoer(doing.DoDoer):
    """DoDoer that performs a one-shot CESR import + escrow pump."""

    def __init__(self, name, base, bran, cesrIn=None, **kwa):
        self.name = name
        self.base = base
        self.bran = bran
        self.cesrIn = cesrIn

        # Open the *target* keystore (the new member's).
        self.hby = existing.setupHby(name=self.name, base=self.base, bran=self.bran)
        self.rgy = credentialing.Regery(hby=self.hby, name=self.name, base=self.base)

        # Build the full parser stack (KEL + TEL + ACDC + replies + exchange).
        # lax/local settings are chosen to be permissive for imported historical material
        # (similar to how witness indirect and join paths operate).
        cues = []  # simple cue sink; not a full deck for this one-shot import
        self.rvy = routing.Revery(db=self.hby.db, cues=cues)
        self.kvy = eventing.Kevery(db=self.hby.db, lax=True, local=False, rvy=self.rvy, cues=cues)
        self.kvy.registerReplyRoutes(router=self.rvy.rtr)

        self.tvy = teventing.Tevery(reger=self.rgy.reger, db=self.hby.db, local=False, cues=cues)
        self.tvy.registerReplyRoutes(router=self.rvy.rtr)

        self.exc = exchanging.Exchanger(hby=self.hby, handlers=[])
        self.verifier = verifying.Verifier(hby=self.hby, reger=self.rgy.reger)

        self.psr = parsing.Parser(framed=True,
                                  kvy=self.kvy,
                                  tvy=self.tvy,
                                  rvy=self.rvy,
                                  exc=self.exc,
                                  vry=self.verifier,
                                  local=True)

        doers = [doing.doify(self.importDo)]
        super(ImportDoer, self).__init__(doers=doers, **kwa)

    def exit(self, deeds=None):
        """Close command-owned resources when HIO exits this doer."""
        super(ImportDoer, self).exit(deeds=deeds)
        self.close()

    def close(self):
        """Release command-owned Habery and Regery resources without clearing stores."""
        if self.rgy is not None:
            self.rgy.close()
            self.rgy = None

        if self.hby is not None:
            self.hby.close(clear=self.hby.temp)
            self.hby = None

    def importDo(self, tymth, tock=0.0, **kwa):
        """Main generator: feed bundle and pump escrows to quiescence."""
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        registries = self._regsFromFiles()

        # Collect the raw bytes to feed.
        ims = self._readBundleCESR()
        if not ims:
            logger.info("import: no data in CESR input; nothing to do")
            return

        self._notice("import: feeding %d bytes of CESR to parser...", len(ims))

        try:
            self.psr.parse(ims=bytearray(ims))
        except Exception as ex:
            logger.warning("import: parser raised during feed (continuing to escrows): %s", ex)

        # Exhaust all escrows. Multiple passes expected for anchored TEL/ACDC material.
        # Limit passes to avoid spinning forever on bad input.
        maxPasses = 64
        passes = 0
        while passes < maxPasses:
            self._processEscrows("main")
            yield self.tock
            passes += 1

        # One extra run after a short settle (helps with any stragglers that depend on cues).
        yield 0.1
        self._processEscrows("settle")

        if not registries:
            registries = self._readRegistries()

        yield from self._waitForRegistries(registries)
        self._saveDefaultRegNames(registries)

        # Refresh the existing Regery so named Registry objects are available without
        # reopening the same LMDB environment inside this process.
        self.rgy.setup()
        self._processEscrows("post-import")

        self._notice("import: completed after %d escrow passes. Target keystore should now reflect imported state.", passes)
        return

    def _cesrFilePaths(self):
        """Return bundle file paths that can be read without consuming stdin."""
        if not self.cesrIn or self.cesrIn in ("-", "/dev/stdin"):
            return []

        if os.path.isdir(self.cesrIn):
            paths = []
            for fn in sorted(os.listdir(self.cesrIn)):
                if fn.endswith(".cesr"):
                    paths.append(os.path.join(self.cesrIn, fn))
            return paths

        if os.path.isfile(self.cesrIn):
            return [self.cesrIn]

        return []

    def _regsFromFiles(self):
        """Discover registry VCP TELs from CESR files without assigning local names."""
        registries = {}
        for path in self._cesrFilePaths():
            if not os.path.basename(path).endswith("-tel.cesr"):
                continue

            with open(path, "rb") as f:
                raw = f.read()

            vcp = self._readRegVcp(raw, source=path)
            if vcp is None:
                continue

            regk, issuerPre = vcp
            registries[regk] = issuerPre
            self._notice("import: discovered registry TEL regk=%s issuer=%s", regk, issuerPre)

        return registries

    def _readRegVcp(self, raw, source="<bytes>"):
        """Return (registry SAID, issuer prefix) when raw begins with a registry VCP event."""
        if not raw:
            return None

        try:
            serder = serdering.SerderKERI(raw=raw)
        except Exception as ex:
            logger.debug("import: unable to read first event from %s: %s", source, ex)
            return None

        if serder.ked.get("t") != "vcp":
            return None

        regk = serder.ked.get("i")
        issuerPre = serder.ked.get("ii")
        if not regk or not issuerPre:
            raise ValueError(f"registry VCP in {source} is missing i or ii")

        return regk, issuerPre

    def _processEscrows(self, context):
        """Process KEL, TEL, reply, exchange, registry, and verifier escrows once."""
        for label, escrow in (
            ("kvy", self.kvy.processEscrows),
            ("tvy", self.tvy.processEscrows),
            ("rvy", self.rvy.processEscrowReply),
            ("exc", self.exc.processEscrow),
            ("rgy", self.rgy.processEscrows),
            ("verifier", self.verifier.processEscrows),
        ):
            try:
                escrow()
            except Exception as ex:
                logger.warning("import: %s escrow processing failed during %s: %s", label, context, ex)

    def _waitForRegistries(self, registries):
        """Wait until every discovered registry SAID has materialized in TEL state."""
        if not registries:
            return 0.0

        pending = set(registries)
        maxPasses = 64
        passes = 0
        while pending:
            visible = {regk for regk in pending if self._regTeverVisible(regk)}
            pending -= visible
            if not pending:
                return 0.0

            self._processEscrows("registry wait")
            yield 0.05
            passes += 1
            if passes >= maxPasses:
                break

        missing = ", ".join(sorted(pending))
        raise ValueError(f"import: registries did not become visible by SAID: {missing}")

    def _regTeverVisible(self, regk):
        """Return True once the registry is available through the Reger TEL state cache."""
        try:
            if regk in self.rgy.reger.tevers:
                return True
        except Exception:
            pass

        try:
            return self.rgy.reger.states.get(keys=regk) is not None
        except Exception:
            return False

    def _saveDefaultRegNames(self, registries):
        """Write local registry-name mappings only after registries are visible."""
        for regk in registries:
            name = regk
            issuerPre = registries.get(regk) or self._registryIssuer(regk)
            if issuerPre is None:
                raise ValueError(f"import: unable to determine issuer prefix for registry {regk}")

            if issuerPre not in self.hby.habs:
                raise ValueError(f"import: registry {regk} issuer prefix {issuerPre} is not a local hab")

            existing = self.rgy.reger.regs.get(keys=name)
            if existing is not None:
                if existing.registryKey != regk or existing.prefix != issuerPre:
                    raise ValueError(f"import: registry name {name} already maps to "
                                     f"{existing.registryKey}/{existing.prefix}, not {regk}/{issuerPre}")
                self._notice("import: registry name %s already maps to %s", name, regk)
                continue

            ok = self.rgy.reger.regs.put(keys=name,
                                         val=viring.RegistryRecord(registryKey=regk, prefix=issuerPre))
            if not ok:
                raise ValueError(f"import: failed to materialize registry name {name} for {regk}")

            self._notice("import: materialized registry %s -> %s (issuer=%s)", name, regk, issuerPre)

    def _registryIssuer(self, regk):
        """Read the issuer prefix from the imported registry VCP event."""
        for raw in self.rgy.reger.clonePreIter(pre=regk):
            serder = serdering.SerderKERI(raw=raw)
            if serder.ked.get("t") == "vcp":
                return serder.ked.get("ii")
        return None

    def _readRegistries(self):
        """Discover visible registry SAIDs from registry state after parsing."""
        registries = {}  # regk:issuerPre
        for (regk,), state in self.rgy.reger.states.getItemIter():
            issuerPre = state.ii
            if regk and issuerPre:
                registries[regk] = issuerPre
                self._notice("import: discovered visible registry regk=%s issuer=%s", regk, issuerPre)
        return registries

    def _notice(self, msg, *args):
        """Emit operator-visible import progress as both log and stdout."""
        text = msg % args if args else msg
        logger.info(text)
        print(text)

    def _readBundleCESR(self):
        """Return a single bytes object containing all CESR to be imported."""
        if not self.cesrIn:
            # Try stdin if nothing specified and stdin looks non-tty.
            if not sys.stdin.isatty():
                data = sys.stdin.buffer.read()
                return data if data else b""
            return b""

        path = self.cesrIn
        if path == "-" or path == "/dev/stdin":
            return sys.stdin.buffer.read()

        files = self._cesrFilePaths()
        if files:
            collected = bytearray()
            for file_path in files:
                with open(file_path, "rb") as f:
                    collected.extend(f.read())
            return bytes(collected)

        # Treat as a literal CESR string? Uncommon; fall back to empty with warning.
        logger.warning("import: CESR input path %s is neither file nor dir; treating as empty", path)
        return b""
