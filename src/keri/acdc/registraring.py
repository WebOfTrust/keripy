# -*- encoding: utf-8 -*-
"""
keri.acdc.registraring module

Registrar service support for managing Registries of ACDC state


"""

from hio.help import ogler

from ..kering import ClosedError, ConfigurationError, ValidationError
from ..core import Blinder, Diger, Number, SerderACDC
from . import messaging
from .registering import RegistryStore, openRegistry

logger = ogler.getLogger()


class Regery:
    """Local manager for V2 ACDC blindable state registries."""

    def __init__(self, hby, name="test", base="", baser=None, temp=False, web=False):
        """Create a registry manager around one registry storage backend.

        Parameters:
            hby (Habery): local habitat environment that owns the registries.
            name (str): human-facing storage name for the registry backend.
            base (str): optional storage base path qualifier.
            baser (RegBaser | WebRegBaser | None): optional pre-opened registry
                backend. When ``None``, one is created from ``openRegistry``.
            temp (bool): True means use temporary storage semantics.
            web (bool): True means use the web storage backend.

        Returns:
            None
        """
        self.hby = hby
        self.name = name
        self.base = base
        self.temp = temp
        self.baser = baser if baser is not None else openRegistry(name=name,
                                                                  base=base,
                                                                  temp=temp,
                                                                  web=web)
        self.store = RegistryStore(self.baser)
        self.regs = {}
        self.names = {}
        if self.store.opened:
            self.loadRegistries()

    def makeRegistry(self, name, prefix, **kwa):
        """Create, stage, and register a new local V2 registry.

        Parameters:
            name (str): local alias for the registry.
            prefix (str): qb64 AID prefix of the habitat that controls the
                registry.
            **kwa: keyword arguments forwarded to ``messaging.regcept``.

        Returns:
            Registry: newly created managed registry instance.
        """
        if name in self.names:
            raise ConfigurationError(f"registry {name} already exists")

        hab = self.hby.habs.get(prefix)
        if hab is None:
            raise ConfigurationError(f"unknown prefix {prefix} for registry {name}")

        serder = messaging.regcept(israid=hab.pre, **kwa)
        if serder.said in self.regs:
            raise ConfigurationError(f"registry {serder.said} already exists")

        reg = Registry(hab=hab, store=self.store, name=name)
        reg.processEvent(serder)
        self.store.records.pin(keys=name,
                               val=self.store.records.klas(registryKey=reg.regk))
        self.regs[reg.regk] = reg
        self.names[name] = reg
        return reg

    def loadRegistries(self):
        """Load persisted registry aliases into the in-memory manager maps.

        Raises:
            ConfigurationError: if a persisted registry is missing its stored
                inception event, if that event is not a ``rip``, or if the
                controlling habitat named by the stored inception issuer is not
                loaded in this Habery.
        """
        for (name,), record in self.store.records.getTopItemIter():
            rip = self.store.event(record.registryKey)
            if rip is None:
                raise ConfigurationError(f"missing registry inception event {record.registryKey} for registry {name}")
            if rip.ilk != "rip":
                raise ConfigurationError(f"registry {record.registryKey} for {name} has invalid inception type {rip.ilk}")

            prefix = rip.sad["i"]
            hab = self.hby.habs.get(prefix)
            if hab is None:
                raise ConfigurationError(f"unknown prefix {prefix} for registry {name}")

            reg = self.regs.get(record.registryKey)
            if reg is None:
                reg = Registry(hab=hab, store=self.store, name=name, regk=record.registryKey)
                head = self.store.head(reg.regk)
                reg.regd = head.qb64 if head is not None else reg.regk
                self.regs[reg.regk] = reg
            self.names[name] = reg

    def registryByName(self, name):
        """Look up one managed registry by its local alias.

        Parameters:
            name (str): local alias used when the registry was created.

        Returns:
            Registry | None: matching registry instance when present, else None.
        """
        return self.names.get(name)

    def processEscrows(self):
        """Retry queued escrow work for every managed registry.

        Parameters:
            None

        Returns:
            None
        """
        for reg in self.regs.values():
            reg.processEscrows()

    def close(self):
        """Close the underlying registry storage backend.

        Parameters:
            None

        Returns:
            None

        Raises:
            ClosedError: if the registry backend has already been closed.
        """
        if not self.store.opened:
            raise ClosedError("attempt to close unopened registry store")
        self.store.close()


class Registry:
    """Transaction-state registry backed by the ACDC registry stores."""

    def __init__(self, hab, store, name="test", regk=None):
        """Create one local registry state machine bound to a habitat.

        Parameters:
            hab (Hab): controlling habitat for this registry.
            store (RegistryStore): storage adapter for registry events, anchors,
                and escrows.
            name (str): local alias for the registry.
            regk (str | None): registry identifier when reopening or attaching to
                an existing registry state.

        Returns:
            None
        """
        self.hab = hab
        self.store = store
        self.name = name
        self.regk = regk
        self.regd = None

    @property
    def head(self):
        """Return the SAID of the current accepted head event.

        Returns:
            Saider | None: SAID of the current accepted head event, or None when
                the registry has no accepted head yet.
        """
        return self.store.head(self.regk) if self.regk is not None else None

    @property
    def sn(self):
        """Return the sequence number of the current accepted head event.

        Returns:
            int: accepted head sequence number, or ``-1`` when the registry has
                not committed any event yet.
        """
        head = self.store.headEvent(self.regk) if self.regk is not None else None
        return int(head.sad["n"], 16) if head is not None else -1

    @property
    def regser(self):
        """Return the accepted registry inception event when available.

        Returns:
            SerderACDC | None: accepted ``rip`` event, or None when inception has
                not been committed yet.
        """
        return self.store.seqEvent(self.regk, 0) if self.regk is not None else None

    def _verifyAnchor(self, serder, number, diger):
        """Verify that one KEL event actually seals the given registry event

        Parameters:
            serder (SerderACDC): registry event whose anchor is being checked
            number (Number): sequence number of the supposed anchoring KEL
                event
            diger (Diger): digest of the supposed anchoring KEL event

        Returns:
            bool: True when the controlling habitat's KEL contains a fully
                witnessed event at ``number`` whose SAID matches ``diger`` and
                whose seal list includes this registry event
        """
        if number is None or diger is None:
            return False

        dig = self.hab.db.kels.getLast(keys=self.hab.pre, on=number.sn)
        if not dig:
            return False

        dig = dig.encode("utf-8")
        if not (aserder := self.hab.db.evts.get(keys=(self.hab.pre, dig))):
            return False

        if aserder.said != diger.qb64 or not self.hab.db.fullyWitnessed(aserder):
            return False

        regk = serder.said if serder.ilk == "rip" else serder.regid
        for seal in aserder.ked.get("a", []):
            if (isinstance(seal, dict) and
                    seal.get("i") == regk and
                    seal.get("s") == serder.sad["n"] and
                    seal.get("d") == serder.said):
                return True

        return False

    def _validateEvent(self, serder):
        """Validate registry-event structure and current-slot consistency.

        Parameters:
            serder (SerderACDC): candidate registry event to validate.

        Returns:
            tuple: ``(regk, sn, existing, prior)`` where ``regk`` is the
                registry identifier, ``sn`` is the integer sequence number,
                ``existing`` is any already accepted event at this slot, and
                ``prior`` is the accepted predecessor when one exists.

        Raises:
            ValidationError: if the event type is unsupported, the event has an
                invalid sequence shape, the ``rip`` issuer does not match the
                controlling habitat, the event belongs to another bound
                registry, the accepted slot is occupied by another SAID, or the
                accepted prior does not match ``p``.
        """
        if serder.ilk not in ("rip", "upd", "bup"):
            raise ValidationError(f"unsupported registry event type {serder.ilk}")

        regk = serder.said if serder.ilk == "rip" else serder.regid
        sn = int(serder.sad["n"], 16)
        if serder.ilk == "rip" and sn != 0:
            raise ValidationError(f"registry inception event {serder.said} has invalid sn {sn}")
        if serder.ilk == "rip" and serder.sad["i"] != self.hab.pre:
            raise ValidationError(f"registry inception event {serder.said} has invalid issuer {serder.sad['i']}")
        if serder.ilk != "rip" and sn < 1:
            raise ValidationError(f"registry event {serder.said} has invalid sn {sn}")

        if self.regk is not None and regk != self.regk:
            raise ValidationError(f"registry event {serder.said} does not belong to {self.regk}")

        existing = self.store.seqEvent(regk, sn)
        if existing is not None and existing.said != serder.said:
            raise ValidationError(f"conflicting registry event at {regk}:{sn}")

        prior = None
        if serder.ilk != "rip":
            prior = self.store.seqEvent(regk, sn - 1)
            if prior is not None and prior.said != serder.sad["p"]:
                raise ValidationError(f"registry event {serder.said} has invalid prior {serder.sad['p']}")

        return regk, sn, existing, prior

    def _commit(self, serder):
        """Accept one verified registry event into the ordered registry log.

        Parameters:
            serder (SerderACDC): verified registry event ready to be committed.

        Returns:
            SerderACDC: the same committed registry event.
        """
        # Retrieve the registry key and sn from the event
        regk = serder.said if serder.ilk == "rip" else serder.regid
        sn = int(serder.sad["n"], 16)

        # Update the registry store and clear every escrowed candidate for this
        # slot now that one event has won it
        self.store.accept(regk, sn, serder)
        for escrowdb in (self.store.baser.maes, self.store.baser.ooes):
            for (said,) in escrowdb.get(keys=regk, on=sn):
                escrowdb.rem(keys=regk, on=sn, val=said)

        # Update the registry state with the new head
        self.regk = regk
        self.regd = serder.said

        return serder

    def _processMissingAnchors(self):
        """Retry missing-anchor escrows using any now-visible local KEL seals.

        Parameters:
            None

        Returns:
            None
        """
        if self.regk is None:
            return

        escrowed = [(sn, said) for _, sn, said in self.store.baser.maes.getTopItemIter(keys=self.regk)]
        for sn, said in escrowed:
            serder = self.store.event(said)
            if serder is None:
                self.store.clearEscrows(self.regk, sn, said)
                continue

            accepted = self.store.seqEvent(self.regk, sn)
            if accepted is not None and accepted.said != said:
                self.store.clearEscrows(self.regk, sn, said)
                continue

            try:
                self.processEvent(serder)
            except ValidationError:
                self.store.clearEscrows(self.regk, sn, said)

    def _processQueued(self):
        """Advance any queued out-of-order events that are now satisfiable.

        Parameters:
            None

        Returns:
            None

        Notes:
            This only advances events that already have a verified stored anchor
            and whose immediate prior event has since been committed.
        """
        if self.regk is None:
            return

        # Iteratively check for queued events at the next sequence number and attempt 
        # to commit them if possible
        while True:
            # Look at the next sequence number and retrieve any queued out-of-order events
            sn = self.sn + 1
            queued = [said for (said,) in self.store.baser.ooes.get(keys=self.regk, on=sn)]
            if not queued:
                return

            advanced = False
            # When competing siblings exist at one sequence slot, prefer the
            # earliest verified sealing event so "first anchored wins" is
            # deterministic instead of depending on DB iteration order.
            queued = sorted(queued,
                            key=lambda said: (
                                self.store.anchor(said)[0].sn if self.store.anchor(said) is not None else float("inf"),
                                self.store.anchor(said)[1].qb64 if self.store.anchor(said) is not None else "",
                                said,
                            ))

            # We assume there may be multiple queued events at the same
            # sequence number, but we only commit one per iteration.
            for said in queued:
                serder = self.store.event(said)
                if serder is None:
                    # Body is missing, escrow entry is invalid, clear it and continue
                    self.store.clearEscrows(self.regk, sn, said)
                    continue

                accepted = self.store.seqEvent(self.regk, sn)
                if accepted is not None and accepted.said != said:
                    self.store.clearEscrows(self.regk, sn, said)
                    continue

                if self.store.anchor(said) is None:
                    # Anchor is missing, cannot commit yet
                    continue

                # Retrieve the prior event and check if it matches the expected prior SAID
                prior = self.store.seqEvent(self.regk, sn - 1)
                if prior is None:
                    continue
                if prior.said != serder.sad["p"]:
                    self.store.clearEscrows(self.regk, sn, said)
                    continue

                # All prerequisites are satisfied, commit the event and then
                # let the loop continue iteratively to the next sequence slot.
                self._commit(serder)
                advanced = True
                break

            if not advanced:
                return

    def processEvent(self, serder):
        """Store one registry event and commit it when anchor and order allow.

        Parameters:
            serder (SerderACDC): candidate registry event to process. Supported
                ilks are ``rip``, ``upd``, and ``bup``.

        Returns:
            bool: True when the event is accepted immediately or was already
                accepted idempotently. False when the event is stored but left
                in escrow because its anchor or prior ordering prerequisites are
                not yet satisfied.

        Raises:
            ValidationError: if the event type is unsupported, belongs to a
                different registry, conflicts with an existing committed event,
                has an invalid inception sequence number, or names an invalid
                prior event.
        """
        # Validate the event shape and any accepted-slot/accepted-prior
        # constraints before mutating in-memory or persisted state.
        regk, sn, existing, prior = self._validateEvent(serder)

        # If this is the first rip being processed for this Registry object,
        # bind it to that registry key now that validation has succeeded.
        if self.regk is None and serder.ilk == "rip":
            self.regk = regk
            self.regd = serder.said

        # Check whether this registry slot has already been accepted.
        if existing is not None:
            self.regk = regk
            self.regd = existing.said
            return True

        # Store new events before escrowing so they can be replayed later once
        # their anchor or prior dependency arrives.
        self.store.putEvent(serder)

        if self.store.anchor(serder.said) is None:
            # For the normal V2 path, discover the sealing KEL event from the
            # local KEL instead of accepting an anchor couple through
            # processEvent. Explicit caller-supplied anchors go through
            # anchorMsg, while the state machine either finds a verified local
            # seal here or stages the event in missing-anchor escrow.
            seal = dict(i=regk, s=serder.sad["n"], d=serder.said)
            aserder = self.hab.db.fetchLastSealingEventByEventSeal(pre=self.hab.pre,
                                                                   seal=seal)
            if aserder is not None:
                number = Number(num=aserder.sn)
                diger = Diger(qb64=aserder.said)
                if self._verifyAnchor(serder, number, diger):
                    self.store.putAnchor(serder.said, number, diger)

            if self.store.anchor(serder.said) is None:
                # No valid anchor exists yet, so keep the event staged in
                # missing-anchor escrow until a sealing KEL event appears.
                self.store.escrowMissingAnchor(regk, sn, serder.said)
                return False

        # If the event had previously been staged as missing-anchor, clear that
        # escrow entry now that a verified anchor exists.
        self.store.baser.maes.rem(keys=regk, on=sn, val=serder.said)

        if serder.ilk == "rip":
            self._commit(serder)
            self._processQueued()
            return True

        if prior is None:
            self.store.escrowOutOfOrder(regk, sn, serder.said)
            return False

        self._commit(serder)
        self._processQueued()
        return True
              
    def processEscrows(self):
        """Retry missing-anchor and out-of-order escrows for this registry.

        Parameters:
            None

        Returns:
            None
        """
        self._processMissingAnchors()
        self._processQueued()

    def anchorMsg(self, said, number=None, diger=None):
        """Validate and record the KEL anchor for one stored registry event.

        Parameters:
            said (str): SAID of the stored registry event to anchor.
            number (Number | None): optional sequence number of the sealing KEL
                event. Must be supplied together with ``diger``. When both are
                omitted, the local KEL is searched for a sealing event that
                matches this registry event.
            diger (Diger | None): optional digest of the sealing KEL event.
                Must be supplied together with ``number``. When both are
                omitted, the local KEL is searched for a sealing event that
                matches this registry event.

        Returns:
            bool: True when the validated anchor allows the event to commit
                immediately, False when the event remains queued behind an
                unmet prior-event dependency.

        Raises:
            ValidationError: if the event is unknown, if only one of
                ``number``/``diger`` is supplied, or if the supplied anchor
                does not validate against the controlling habitat's KEL.
        """
        serder = self.store.event(said)
        if serder is None:
            raise ValidationError(f"unknown registry event {said}")

        regk = serder.said if serder.ilk == "rip" else serder.regid
        if self.regk is not None and regk != self.regk:
            raise ValidationError(f"registry event {said} does not belong to {self.regk}")

        # Reuse the same event-shape and accepted-slot validation that
        # processEvent() will enforce so a rejected event never leaves a stored
        # anchor behind.
        self._validateEvent(serder)

        if (number is None) != (diger is None):
            raise ValidationError("anchorMsg requires both number and diger or neither")

        if number is None or diger is None:
            seal = dict(i=regk, s=serder.sad["n"], d=serder.said)
            aserder = self.hab.db.fetchLastSealingEventByEventSeal(pre=self.hab.pre,
                                                                   seal=seal)
            if aserder is not None:
                number = Number(num=aserder.sn)
                diger = Diger(qb64=aserder.said)

        if not self._verifyAnchor(serder, number, diger):
            raise ValidationError(f"invalid anchor for registry event {said}")

        self.store.putAnchor(said, number, diger)
        return self.processEvent(serder)

    def make(self, **kwa):
        """Create and stage a registry inception event for this registry.

        Parameters:
            **kwa: keyword arguments forwarded to ``messaging.regcept``.

        Returns:
            SerderACDC: created ``rip`` event staged until a sealing KEL event
                is later validated with ``anchorMsg``.
        """
        serder = messaging.regcept(israid=self.hab.pre, **kwa)
        self.processEvent(serder)
        return serder

    def update(self, acdc, state, **kwa):
        """Create and stage one cleartext registry state update event.

        Parameters:
            acdc (SerderACDC): valid transaction-state ACDC whose registry
                identifier and issuer must match this registry and its
                controlling habitat.
            state (str): cleartext registry state label to record.
            **kwa: keyword arguments forwarded to ``messaging.update``.

        Returns:
            SerderACDC: created ``upd`` event staged until a sealing KEL event
                is later validated with ``anchorMsg``.

        Raises:
            ConfigurationError: if the registry has not yet committed an
                accepted inception/head event, if ``acdc`` is not a valid
                ``SerderACDC``, or if the ACDC does not belong to this
                registry or controlling habitat.
        """
        if self.regk is None or self.store.headEvent(self.regk) is None:
            raise ConfigurationError("registry must be anchored before updates")
        if not isinstance(acdc, SerderACDC):
            raise ConfigurationError("acdc must be a SerderACDC")
        if not acdc.verify():
            raise ConfigurationError(f"acdc {acdc.said} is invalid")
        regid = getattr(acdc, "regid", None)
        if regid is None:
            regid = acdc.sad.get("rd")
        if regid != self.regk:
            raise ConfigurationError(f"acdc {acdc.said} does not belong to registry {self.regk}")
        issuer = getattr(acdc, "israid", None)
        if issuer is None:
            issuer = acdc.sad.get("i")
        if issuer != self.hab.pre:
            raise ConfigurationError(f"acdc {acdc.said} has issuer {issuer} not {self.hab.pre}")

        serder = messaging.update(regid=self.regk,
                                  prior=self.store.headEvent(self.regk).said,
                                  acdc=acdc.said,
                                  state=state,
                                  sn=self.sn + 1,
                                  **kwa)
        self.processEvent(serder)
        return serder

    def blind(self, acdc, state, **kwa):
        """Create and stage one blindable registry state update event.

        Parameters:
            acdc (SerderACDC): valid transaction-state ACDC whose registry
                identifier and issuer must match this registry and its
                controlling habitat.
            state (str): logical state represented by the blindable update.
            **kwa: keyword arguments forwarded to ``Blinder.blind`` and
                ``messaging.blindate``. Keys used to build a blinder are removed
                from ``kwa`` before the message event is created. Blinders are
                always derived internally for this update; passing ``blinder``
                explicitly is not supported.

        Returns:
            tuple: ``(blinder, serder)`` where ``blinder`` is the generated
                ``Blinder`` instance and ``serder`` is the created ``bup``
                event staged until a sealing KEL event is later validated with
                ``anchorMsg``.

        Raises:
            ConfigurationError: if the registry has not yet committed an
                accepted inception/head event, if ``acdc`` is not a valid
                ``SerderACDC``, if the ACDC does not belong to this registry or
                controlling habitat, or if an unsupported explicit ``blinder``
                argument is supplied.
        """
        if self.regk is None or self.store.headEvent(self.regk) is None:
            raise ConfigurationError("registry must be anchored before updates")
        if not isinstance(acdc, SerderACDC):
            raise ConfigurationError("acdc must be a SerderACDC")
        if not acdc.verify():
            raise ConfigurationError(f"acdc {acdc.said} is invalid")
        regid = getattr(acdc, "regid", None)
        if regid is None:
            regid = acdc.sad.get("rd")
        if regid != self.regk:
            raise ConfigurationError(f"acdc {acdc.said} does not belong to registry {self.regk}")
        issuer = getattr(acdc, "israid", None)
        if issuer is None:
            issuer = acdc.sad.get("i")
        if issuer != self.hab.pre:
            raise ConfigurationError(f"acdc {acdc.said} has issuer {issuer} not {self.hab.pre}")
        if "blinder" in kwa:
            raise ConfigurationError("caller-supplied blinder overrides are not supported")

        blindkwa = {}
        for key in ("raw", "salt", "tier", "bound", "bsn", "bd"):
            if key in kwa:
                blindkwa[key] = kwa.pop(key)

        sn = self.sn + 1
        acdcSaid = acdc.said
        blinder = Blinder.blind(sn=sn, acdc=acdcSaid, state=state, **blindkwa)

        serder = messaging.blindate(regid=self.regk,
                                    prior=self.store.headEvent(self.regk).said,
                                    blid=blinder.said,
                                    sn=sn,
                                    **kwa)
        self.processEvent(serder)
        return blinder, serder


class Registrar:
    """Small facade for V2 registry inception and state updates."""

    def __init__(self, rgy):
        """Create a caller-facing registry helper around a Regery.

        Parameters:
            rgy (Regery): managed registry environment used to resolve and
                operate on registries.

        Returns:
            None
        """
        self.rgy = rgy

    def _registry(self, registry):
        """Resolve a registry object from an instance, key, or local name.

        Parameters:
            registry (Registry | str): registry instance, registry key, or local
                registry alias.

        Returns:
            Registry: resolved registry instance.

        Raises:
            ConfigurationError: if the supplied registry reference cannot be
                resolved.
        """
        if isinstance(registry, Registry):
            return registry
        if registry in self.rgy.regs:
            return self.rgy.regs[registry]
        reg = self.rgy.registryByName(registry)
        if reg is None:
            raise ConfigurationError(f"unknown registry {registry}")
        return reg

    def makeRegistry(self, name, prefix, **kwa):
        """Create and register a named registry for one local habitat.

        Parameters:
            name (str): local alias for the registry.
            prefix (str): qb64 AID prefix of the controlling habitat.
            **kwa: keyword arguments forwarded to ``Regery.makeRegistry``.

        Returns:
            Registry: newly created managed registry.
        """
        return self.rgy.makeRegistry(name=name, prefix=prefix, **kwa)

    def incept(self, registry, **kwa):
        """Create one registry inception event through the facade.

        Parameters:
            registry (Registry | str): registry instance, key, or local alias.
            **kwa: keyword arguments forwarded to ``Registry.make``.

        Returns:
            SerderACDC: created ``rip`` event.
        """
        return self._registry(registry).make(**kwa)

    def issue(self, registry, acdc, state="issued", blind=False, **kwa):
        """Create either a clear or blindable registry update through the facade.

        Parameters:
            registry (Registry | str): registry instance, key, or local alias.
            acdc (SerderACDC): transaction-state ACDC whose registry identifier
                and issuer must match the target registry and its controller.
            state (str): target logical state for the update.
            blind (bool): True means create a ``bup`` blindable update, False
                means create a cleartext ``upd``.
            **kwa: keyword arguments forwarded to ``Registry.update`` or
                ``Registry.blind``.

        Returns:
            tuple: ``(blinder, serder)``. For cleartext updates ``blinder`` is
                None and ``serder`` is the created ``upd`` event. For blindable
                updates ``blinder`` is the created ``Blinder`` and ``serder``
                is the created ``bup`` event.
        """
        reg = self._registry(registry)
        if blind:
            return reg.blind(acdc=acdc, state=state, **kwa)
        return None, reg.update(acdc=acdc, state=state, **kwa)
