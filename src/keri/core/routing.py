# -*- encoding: utf-8 -*-
"""
keri.core.routing module

"""
import datetime
import logging
import re

from hio.help import decking

from . import eventing, coring, serdering
from .. import help, kering
from ..db import dbing
from ..help import helping

logger = help.ogler.getLogger()


class Router:
    """ Reply message router

    Reply message router that accepts registration of route `r` handlers and dispatches
    reply messages to the appropriate handler.

    """

    defaultResourceFunc = "processReply"

    def __init__(self, routes=None):
        """ Initialized instance with optiona list of existing routes

        Parameters:
            routes (list): preregistered routes for this router

        """
        self.routes = routes if routes is not None else list()

    def addRoute(self, routeTemplate, resource, suffix=None):
        """ Add a route between a route template and a resource


        Parameters:
            routeTemplate (str): a route template to use for the resource
            resource (object): the resource instance to associate with the route template
            suffix(str, optional): Optional responder name suffix for this route. If a suffix is provided,
              Router will map reply routes to processReply{suffix}().  In this way, multiple closely-related routes
              can be mapped to the same resource.

        """

        fields, regex = compile_uri_template(routeTemplate)
        self.routes.append(Route(regex=regex, fields=fields, resource=resource, suffix=suffix))

    def dispatch(self, serder, saider, cigars, tsgs):
        """

        Parameters:
            serder:
            saider:
            cigars:
            tsgs:

        Returns:

        """
        ked = serder.ked
        # Dispatch based on route
        r = ked["r"]
        route, match = self._find(route=r)
        if route is None:
            raise kering.ValidationError(f"No resource is registered to handle route {r}")

        fname = self.defaultResourceFunc
        if route.suffix is not None:
            fname += route.suffix

        kwargs = match.groupdict()
        for name in route.fields:
            if name not in kwargs:
                raise kering.ValidationError(f"parameter {name} not found in route {r}")

        fn = getattr(route.resource, fname, self.processRouteNotFound)
        fn(serder=serder, saider=saider, route=r, cigars=cigars, tsgs=tsgs, **kwargs)

    def _find(self, route):
        """ Linear seach thru added routes, returning the first one that matchs

        Searches through the registered routes until a regex in one of the routes matches
        the provided route and returns the Route object along with the re.Match object.

        Parameters:
            route (str): the route from the `r` of the reply message

        Returns:
            Route: the Route object with the resource that is registered to process this rpy message
            re.Match:  the regular expression match that contains the grouping of matched parameters.

        """
        for r in self.routes:
            if res := r.regex.search(route):
                return r, res

        return None, None

    def processRouteNotFound(self, *, serder, saider, route,
                             cigars=None, tsgs=None, **kwargs):
        """ Default handler for processing reply message with an unregistered route

        Parameters:
            serder (Serder): reply event message
            saider (Saider): SAIDer of the sender
            route (str): route ('r') of the event message
            cigars (Optional(list)): list of non-transferable signature tuples
            tsgs (Optional(list)): list of transferable signature tuples
            **kwargs (dict) additional keyword args

        """

        raise kering.ConfigurationError(f"Resource registered for route {route} in {coring.Ilks.rpy}"
                                        f"does not contain the correct processReply method")


class Revery:
    """ Reply message event processor

    """

    TimeoutRPE = 3600  # seconds to timeout reply message escrows

    def __init__(self, db, rtr=None, cues=None, lax=True, local=False):
        """

        Parameters:
            db:
            cues:
            lax:
            local:
        """
        self.db = db
        self.rtr = rtr if rtr is not None else Router()
        self.cues = cues if cues is not None else decking.Deck()
        self.lax = True if lax else False  # promiscuous mode
        self.local = True if local else False  # local vs nonlocal restrictions

    @property
    def prefixes(self):
        """
        Returns .db.prefixes
        """
        return self.db.prefixes

    def processReply(self, serder, cigars=None, tsgs=None):
        """
         Process one reply message with either attached nontrans signing couples
         in cigars or attached trans indexed sig groups in tsgs. Process logic
         is route dependent and dispatched by route.

         Parameters:
             serder (Serder): instance of reply message
             cigars (list): of Cigar instances that contain nontrans signing couple
                           signature in .raw and public key in .verfer
             tsgs (list): tuples (quadruples) of form
                 (prefixer, seqner, diger, [sigers]) where:
                 prefixer is pre of trans endorser
                 seqner is sequence number of trans endorser's est evt for keys for sigs
                 diger is digest of trans endorser's est evt for keys for sigs
                 [sigers] is list of indexed sigs from trans endorser's keys from est evt

         BADA (Best Available Data Acceptance) model for each reply message.
         Latest-Seen-Signed Pairwise comparison of new update reply compared to
         old already accepted reply from same source for same route (same data).
         Accept new reply (update) if new reply is later than old reply where:
             1) Later means date-time-stamp of new is greater than old
         If non-trans signer then also (AND)
             2) Later means sn (sequence number) of last (if forked) Est evt that
                provides keys for signature(s) of new is greater than or equal to
                sn of last Est evt that provides keys for signature(s) of new.

         If nontrans and last Est Evt is not yet accepted then escrow.
         If nontrans and partially signed then escrow.

         Escrow process logic is route dependent and is dispatched by route,
         i.e. route is address of buffer with route specific handler of escrow.
        """
        #for k in eventing.RPY_LABELS:
            #if k not in serder.ked:
                #raise kering.ValidationError(f"Missing element={k} from {coring.Ilks.rpy}"
                                             #f" msg={serder.ked}.")
        # fetch from serder to process
        ked = serder.ked

        # verify said of reply
        saider = coring.Saider(qb64=ked["d"])
        if not saider.verify(sad=ked, prefixed=True):
            raise kering.ValidationError(f"Invalid said = {saider.qb64} for reply "
                                         f"msg={ked}.")

        self.rtr.dispatch(serder=serder, saider=saider, cigars=cigars, tsgs=tsgs)

    def acceptReply(self, serder, saider, route, aid, osaider=None,
                    cigars=None, tsgs=None):
        """ Applies Best Available Data Acceptance policy to reply and signatures

        Returns:
            bool: True is successfully accepted. False otherwise

        Parameters:
            serder (Serder): instance of reply msg (SAD)
            saider (Saider): instance  from said in serder (SAD)
            osaider (Saider): instance of saider for previous reply if any
            route (str): reply route
            aid (str): identifier prefix qb64 of authorizing attributable ID
            cigars (list): of Cigar instances that contain nontrans signing couple
                          signature in .raw and public key in .verfer
            tsgs (list): tuples (quadruples) of form
                (prefixer, seqner, diger, [sigers]) where:
                prefixer is pre of trans endorser
                seqner is sequence number of trans endorser's est evt for keys for sigs
                diger is digest of trans endorser's est evt for keys for sigs
                [sigers] is list of indexed sigs from trans endorser's keys from est evt

        BADA (Best Available Data Acceptance) model for each reply message.
        Latest-Seen-Signed Pairwise comparison of new update reply compared to
        old already accepted reply from same source for same route (same data).
        Accept new reply (update) if new reply is later than old reply where:
            1) If transferable: Later is True
                 A) If sn (sequence number) of last (if forked) Est evt that provides
                 keys for signature(s) of new is greater than sn of last Est evt
                 that provides keys for signature(s) of old.

                 Or

                 B) If sn of new equals sn of old And date-time-stamp of new is
                    greater than old

            2) Else If non-transferable: Later it True
                 If date-time-stamp of new is greater than old

            4) Else Later is False


        If nontrans and last Est Evt is not yet accepted then escrow.
        If nontrans and partially signed then escrow.

        Escrow process logic is route dependent and is dispatched by route,
        i.e. route is address of buffer with route specific handler of escrow.

        """
        # BADA logic.
        accepted = False  # flag to raise UnverifiedReplyError not accepted
        cigars = cigars if cigars is not None else []
        tsgs = tsgs if tsgs is not None else []

        # Is new later than old if old?
        # get date-time raises error if empty or invalid format
        dater = coring.Dater(dts=serder.ked["dt"])
        odater = None
        if osaider:
            odater = self.db.sdts.get(keys=osaider.qb64b)

        for cigar in cigars:  # process each couple to verify sig and write to db
            if cigar.verfer.transferable:  # ignore invalid transferable verfers
                logger.info("Kevery process: skipped invalid transferable verfers"
                            " on reply said=", serder.said)
                continue  # skip invalid transferable

            if not self.lax and cigar.verfer.qb64 in self.prefixes:  # own cig
                if not self.local:  # own cig when not local so ignore
                    logger.info("Kevery process: skipped own attachment"
                                " on nonlocal reply said=", serder.said)
                    logger.debug(f"event=\n{serder.pretty()}\n")

                    continue  # skip own cig attachment on non-local reply msg

            if aid != cigar.verfer.qb64:  # cig not by aid
                logger.info("Kevery process: skipped cig not from aid="
                            "%s on reply said=%s", aid, serder.said)
                logger.debug(f"event=\n{serder.pretty()}\n")
                continue  # skip invalid cig's verfer is not aid

            if odater:  # get old compare datetimes to see if later
                if dater.datetime <= odater.datetime:
                    logger.info("Kevery process: skipped stale update from "
                                "%s of reply said=%s", aid, serder.said)
                    logger.debug(f"event=\n{serder.pretty()}\n")
                    continue  # skip if not later
                    # raise ValidationError(f"Stale update of {route} from {aid} "
                    # f"via {Ilks.rpy}={serder.ked}.")

            if not cigar.verfer.verify(cigar.raw, serder.raw):  # cig not verify
                logger.info("Kevery process: skipped nonverifying cig from "
                            "%s on reply said=%s", cigar.verfer.qb64, serder.said)
                logger.debug(f"event=\n{serder.pretty()}\n")
                continue  # skip if cig not verify

            # All constraints satisfied so update
            self.updateReply(serder=serder, saider=saider, dater=dater, cigar=cigar)
            self.removeReply(saider=osaider)  # remove obsoleted reply artifacts
            accepted = True
            break  # first valid cigar sufficient ignore any duplicates in cigars

        for prefixer, seqner, ssaider, sigers in tsgs:  # iterate over each tsg
            if not self.lax and prefixer.qb64 in self.prefixes:  # own sig
                if not self.local:  # own sig when not local so ignore
                    logger.info("Kevery process: skipped own attachment"
                                " on nonlocal reply said=%s", serder.said)
                    logger.debug(f"event=\n{serder.pretty()}\n")
                    continue  # skip own sig attachment on non-local reply msg

            spre = prefixer.qb64
            if aid != spre:  # sig not by aid
                logger.info("Kevery process: skipped signature not from aid="
                            "%s on reply said=%s", aid, serder.said)
                logger.debug(f"event=\n{serder.pretty()}\n")
                continue  # skip invalid signature is not from aid

            if osaider:  # check if later logic  sn > or sn == and dt >
                if otsgs := eventing.fetchTsgs(db=self.db.ssgs, saider=osaider):
                    _, osqr, _, _ = otsgs[0]  # zeroth should be authoritative

                    if seqner.sn < osqr.sn:  # sn earlier
                        logger.info("Kevery process: skipped stale key state sig"
                                    "from %s sn=%s<%s on reply said=%s",
                                    aid, seqner.sn, osqr.sn, serder.said)
                        logger.debug(f"event=\n{serder.pretty()}\n")
                        continue  # skip if sn earlier

                    if seqner.sn == osqr.sn:  # sn same so check datetime
                        if odater:
                            if dater.datetime <= odater.datetime:
                                logger.info("Kevery process: skipped stale key"
                                            "state sig datetime from %s on reply said=%s",
                                            aid, serder.said)
                                logger.debug(f"event=\n{serder.pretty()}\n")
                                continue  # skip if not later

            # retrieve sdig of last event at sn of signer.
            sdig = self.db.getKeLast(key=dbing.snKey(pre=spre, sn=seqner.sn))
            if sdig is None:
                # create cue here to request key state for sprefixer signer
                # signer's est event not yet in signer's KEL
                logger.info("Kevery process: escrowing without key state for signer"
                            " on reply said=", serder.said)
                self.escrowReply(serder=serder, saider=saider, dater=dater,
                                 route=route, prefixer=prefixer, seqner=seqner,
                                 ssaider=ssaider, sigers=sigers)
                self.cues.append(dict(kin="query", q=dict(pre=spre)))
                continue

            # retrieve last event itself of signer given sdig
            sraw = self.db.getEvt(key=dbing.dgKey(pre=spre, dig=bytes(sdig)))
            # assumes db ensures that sraw must not be none because sdig was in KE
            sserder = serdering.SerderKERI(raw=bytes(sraw))
            if sserder.said != ssaider.qb64:  # signer's dig not match est evt
                raise kering.ValidationError(f"Bad trans indexed sig group at sn = "
                                             f"{seqner.sn} for reply = {serder.ked}.")
            # verify sigs
            if not (sverfers := sserder.verfers):
                raise kering.ValidationError(f"Invalid reply from signer={spre}, no "
                                             f"keys at signer's est. event sn={seqner.sn}.")

            # fetch any escrowed sigs, extract just the siger from each quad
            # want sn in numerical order so use hex
            quadkeys = (saider.qb64, prefixer.qb64, f"{seqner.sn:032x}", ssaider.qb64)
            esigers = self.db.ssgs.get(keys=quadkeys)
            sigers.extend(esigers)
            sigers, valid = eventing.validateSigs(serder=serder,
                                                  sigers=sigers,
                                                  verfers=sverfers,
                                                  tholder=sserder.tholder)
            # no error so at least one verified siger

            if valid:  # meet threshold so save
                # All constraints satisfied so update
                self.updateReply(serder=serder, saider=saider, dater=dater,
                                 prefixer=prefixer, seqner=seqner, diger=ssaider,
                                 sigers=sigers)
                self.removeReply(saider=osaider)  # remove obsoleted reply artifacts
                # remove stale signatures .ssgs for this saider
                # this ensures that zeroth tsg is authoritative
                for prr, snr, dgr, _ in eventing.fetchTsgs(db=self.db.ssgs, saider=saider, snh=seqner.snh):
                    if ((snr.sn < seqner.sn) or
                            (snr.sn == seqner.sn and dgr.qb64 != ssaider.qb64)):
                        self.db.ssgs.trim(keys=(prr.qb64, f"{snr.sn:032h}", dgr.qb64, ""))

                accepted = True

            else:  # not meet threshold so escrow
                self.escrowReply(serder=serder, saider=saider, dater=dater,
                                 route=route, prefixer=prefixer, seqner=seqner,
                                 ssaider=ssaider, sigers=sigers)

        return accepted

    def updateReply(self, *, serder, saider, dater, cigar=None, prefixer=None,
                    seqner=None, diger=None, sigers=None):
        """ Update Reply SAD in database

        Update Reply SAD in database given by by serder and associated databases
        for attached cig couple or sig quadruple.
        Overwrites val at key if already exists.

        Parameters:
            serder (Serder): instance of reply msg (SAD)
            saider (Saider): instance  from said in serder (SAD)
            dater (Dater): instance from date-time in serder (SAD)
            cigar (Cigar): instance that contain nontrans signing couple
                          signature in .raw and public key in .verfer
            prefixer (Prefixer): is pre of trans endorser
            seqner (Seqner): is sequence number of trans endorser's est evt for keys for sigs
            diger (Diger): is digest of trans endorser's est evt for keys for sigs
            sigers (list): of indexed sigs from trans endorser's key from est evt

        """
        keys = (saider.qb64,)
        self.db.sdts.put(keys=keys, val=dater)  # first one idempotent
        self.db.rpys.put(keys=keys, val=serder)  # first one idempotent
        if cigar:
            self.db.scgs.put(keys=keys, vals=[(cigar.verfer, cigar)])
        if sigers:  # want sn in numerical order so use hex
            quadkeys = (saider.qb64, prefixer.qb64, f"{seqner.sn:032x}", diger.qb64)
            self.db.ssgs.put(keys=quadkeys, vals=sigers)

    def removeReply(self, saider):
        """ Remove Reply SAD artifacts given by saider.

        Parameters:
            saider (Saider): instance from said in serder (SAD)

        """
        if saider:
            keys = (saider.qb64,)

            self.db.ssgs.trim(keys=(saider.qb64, ""))  # remove whole branch
            self.db.scgs.rem(keys=keys)
            self.db.rpys.rem(keys=keys)
            self.db.sdts.rem(keys=keys)

    def escrowReply(self, *, serder, saider, dater, route, prefixer, seqner,
                    ssaider, sigers):
        """ Escrow reply by route

        Parameters:
            serder (Serder): instance of reply msg (SAD)
            saider (Saider): instance  from said in serder (SAD)
            dater (Dater): instance from date-time in serder (SAD)
            route (str): reply route
            prefixer (Prefixer): is pre of trans endorser
            seqner (Seqner): is sequence number of trans endorser's est evt for keys for sigs
            ssaider (Saider) is said of trans endorser's est evt for keys for sigs
            sigers (list): is indexed sigs from trans endorser's key from est evt

        """
        if not sigers:
            return  # nothing to escrow
        keys = (saider.qb64,)
        self.db.sdts.put(keys=keys, val=dater)  # first one idempotent
        self.db.rpys.put(keys=keys, val=serder)  # first one idempotent
        quadkeys = (saider.qb64, prefixer.qb64, f"{seqner.sn:032x}", ssaider.qb64)
        self.db.ssgs.put(keys=quadkeys, vals=sigers)
        self.db.rpes.put(keys=(route,), vals=[saider])

    def processEscrowReply(self):
        """ Process escrows for reply messages.

        Escrows are keyed by reply route and val is reply said

        triple (prefixer, seqner, diger)
        quadruple (prefixer, seqner, diger, siger)

        """
        for (route,), saider in self.db.rpes.getItemIter():
            try:
                tsgs = eventing.fetchTsgs(db=self.db.ssgs, saider=saider)

                keys = (saider.qb64,)
                dater = self.db.sdts.get(keys=keys)
                serder = self.db.rpys.get(keys=keys)
                try:
                    if not (dater and serder and tsgs):
                        raise ValueError(f"Missing escrow artifacts at said={saider.qb64}"
                                         f"for route={route}.")

                    # do date math for stale escrow
                    if ((helping.nowUTC() - dater.datetime) >
                            datetime.timedelta(seconds=self.TimeoutRPE)):
                        # escrow stale so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Stale reply escrow "
                                    " at route = %s", route)

                        raise kering.ValidationError(f"Stale reply escrow at route = {route}.")

                    self.processReply(serder=serder, tsgs=tsgs)

                except kering.UnverifiedReplyError as ex:
                    # still waiting on missing prior event to validate
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Kevery unescrow attempt failed: %s", ex.args[0])

                except Exception as ex:  # other error so remove from reply escrow
                    self.db.rpes.rem(keys=(route, ), val=saider)  # remove escrow only
                    self.removeReply(saider)  # remove escrow reply artifacts
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Kevery unescrowed due to error: %s", ex.args[0])
                    else:
                        logger.error("Kevery unescrowed due to error: %s", ex.args[0])

                else:  # unescrow succeded
                    self.db.rpes.rem(keys=(route, ), val=saider)  # remove escrow only
                    logger.info("Kevery unescrow succeeded for reply said=%s",
                                serder.said)
                    logger.debug(f"event=\n{serder.pretty()}\n")

            except Exception as ex:  # log diagnostics errors etc
                self.db.rpes.rem(keys=(route,), val=saider)  # remove escrow only
                self.removeReply(saider)  # remove escrow reply artifacts
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery unescrowed due to error: %s", ex.args[0])
                else:
                    logger.error("Kevery unescrowed due to error: %s", ex.args[0])


class Route:
    """ Route class for registration of reply message handlers

    This class represents a registered route internally to the Revery.
    the properties are created by using the Falcon compile route utility method

    Properties:
        .regex(re): compiled url template regex
        .fields(set): field names for matches in regex
        .resource(object): the handler for this route
        .suffix(Optional(str)): a suffix to be applied to the handler method

    """

    def __init__(self, regex, fields, resource, suffix=None):
        """ Initialize instance of route

        Parameters:
            regex(re): compiled url template regex
            fields(set): field names for matches in regex
            resource(object): the handler for this route
            suffix(Optional(str)): a suffix to be applied to the handler method

        """
        self.regex = regex
        self.fields = fields
        self.resource = resource
        self.suffix = suffix


def compile_uri_template(template):
    """Compile the given URI template string into a pattern matcher.

    This function can be used to construct custom routing engines that
    iterate through a list of possible routes, attempting to match
    an incoming request against each route's compiled regular expression.

    Each field is converted to a named group, so that when a match
    is found, the fields can be easily extracted using
    :py:meth:`re.MatchObject.groupdict`.

    This function does not support the more flexible templating
    syntax used in the default router. Only simple paths with bracketed
    field expressions are recognized. For example::

        /
        /books
        /books/{isbn}
        /books/{isbn}/characters
        /books/{isbn}/characters/{name}

    Also, note that if the template contains a trailing slash character,
    it will be stripped in order to normalize the routing logic.

    Args:
        template(str): The template to compile. Note that field names are
            restricted to ASCII a-z, A-Z, and the underscore character.

    Returns:
        tuple: (template_field_names, template_regex)
    """

    if not isinstance(template, str):
        raise TypeError('uri_template is not a string')

    if not template.startswith('/'):
        raise ValueError("uri_template must start with '/'")

    if '//' in template:
        raise ValueError("uri_template may not contain '//'")

    if template != '/' and template.endswith('/'):
        template = template[:-1]

    # template names should be able to start with A-Za-z
    # but also contain 0-9_ in the remaining portion
    expression_pattern = r'{([a-zA-Z]\w*)}'

    # Get a list of field names
    fields = set(re.findall(expression_pattern, template))

    # Convert Level 1 var patterns to equivalent named regex groups
    escaped = re.sub(r'[\.\(\)\[\]\?\*\+\^\|]', r'\\\g<0>', template)
    pattern = re.sub(expression_pattern, r'(?P<\1>[^/]+)', escaped)
    pattern = r'\A' + pattern + r'\Z'

    return fields, re.compile(pattern, re.IGNORECASE)
