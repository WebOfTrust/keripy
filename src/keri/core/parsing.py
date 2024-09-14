# -*- encoding: utf-8 -*-
"""
keri.core.parsing module

message stream parsing support
"""

import logging

from ..kering import Vrsn_1_0, Vrsn_2_0
from .coring import (Ilks, Seqner, Cigar,
                     Dater, Verfer, Prefixer, Saider, Pather, Matter)
from .counting import Counter, Codens, CtrDex_1_0
from .indexing import (Siger, )
from . import serdering
from .. import help
from .. import kering
from ..kering import Colds, sniff, Vrsn_1_0, Vrsn_2_0

logger = help.ogler.getLogger()


class Parser:
    """
    Parser is stream parser that processes an incoming message stream.
    Each message in the stream is composed of a message body with a message foot
    The message body includes a version string. The message foot is composed of
    composable concatenated attachments encoded in CESR (Composable Event
    Streaming Representation)  CESR supports both binary and text formats where
    text is Base64 URL/Filesafe. The attachements in a CESR foot may be converted
    and round tripped en-masse between binary and text (Base64 URL/File).
    CESR encoding ensures alignment on 24 bit boundaries.

    Only supports current version VERSION

    Has the following public attributes and properties:

    Attributes:
        ims (bytearray): incoming message stream
        framed (bool): True means stream is packet framed
        pipeline (bool): True means use pipeline processor to process
                whenever stream includes pipelined count codes.
        kvy (Kevery): route KEL message types to this instance
        tvy (Tevery): route TEL message types to this instance
        exc (Exchanger): route EXN message types to this instance
        rvy (Revery): reply (RPY) message handler
        vry (Verfifier): credential verifier with wallet storage
        local (bool): True means event source is local (protected) for validation
                         False means event source is remote (unprotected) for validation

    """

    def __init__(self, ims=None, framed=True, pipeline=False, kvy=None,
                 tvy=None, exc=None, rvy=None, vry=None, local=False):
        """
        Initialize instance:

        Parameters:
            ims (bytearray): incoming message stream
            framed (bool): True means ims contains only one msg body plus
                its foot of attachments, not multiple sets of msg body plus foot
            pipeline (bool): True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.
            kvy (Kevery): route KEL message types to this instance
            tvy (Tevery): route TEL message types to this instance
            exc (Exchanger): route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            vry (Verfifier): credential verifier with wallet storage
            local (bool): True means event source is local (protected) for validation
                         False means event source is remote (unprotected) for validation
        """
        self.ims = ims if ims is not None else bytearray()
        self.framed = True if framed else False  # extract until end-of-stream
        self.pipeline = True if pipeline else False  # process as pipelined
        self.kvy = kvy
        self.tvy = tvy
        self.exc = exc
        self.rvy = rvy
        self.vry = vry
        self.local = True if local else False


    @staticmethod
    def extract(ims, klas, cold=Colds.txt):
        """
        Extract and return instance of klas from input message stream, ims, given
        stream state, cold, is txt or bny. Inits klas from ims using qb64b or
        qb2 parameter based on cold.
        """
        if cold == Colds.txt:
            return klas(qb64b=ims, strip=True)
        elif cold == Colds.bny:
            return klas(qb2=ims, strip=True)
        else:
            raise kering.ColdStartError("Invalid stream state cold={}.".format(cold))


    @staticmethod
    def _extractor(ims, klas, cold=Colds.txt, abort=False, gvrsn=Vrsn_1_0):
        """
        Returns generator to extract and return instance of klas from input
        message stream, ims, given stream state, cold, is txt or bny.
        If wait is True then yield when not enough bytes in stream otherwise
        raise ShortageError
        Inits klas from ims using qb64b or qb2 parameter based on cold.
        Yields if not enough bytes in ims to fill out klas instance.

        Parameters:
            ims (bytearray): input message stream (must be strippable)
            klas (Serder | Counter | Matter | Indexer): subclass that is parsable
            cold (Coldage): instance str value
            abort (bool): True means abort if bad pipelined frame Shortage
                          False means do not abort if Shortage just wait for more
            gvrsn (Versionage): instance of genera version of CESR code tables

        Usage:

        instance = self._extractor
        """
        while True:
            try:
                if cold == Colds.txt:
                    return klas(qb64b=ims, strip=True, gvrsn=gvrsn)
                elif cold == Colds.bny:
                    return klas(qb2=ims, strip=True, gvrsn=gvrsn)
                else:
                    raise kering.ColdStartError("Invalid stream state cold={}.".format(cold))
            except kering.ShortageError as ex:
                if abort:  # pipelined pre-collects full frame before extracting
                    raise  # bad pipelined frame so abort by raising error
                yield


    def _sadPathSigGroup(self, ctr, ims, root=None, cold=Colds.txt, pipelined=False):
        """

        Args:
            ctr (Counter): group type counter
            ims (bytearray) of serialized incoming message stream.
                May contain one or more sets each of a serialized message with
                attached cryptographic material such as signatures or receipts.
            root (Pather) optional root path of this group
            cold (str): next charater Coldage type indicayor
            pipelined (bool) True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.

        Returns:

        """
        if ctr.code != CtrDex_1_0.SadPathSigGroups:
            raise kering.UnexpectedCountCodeError("Wrong "
                                                  "count code={}.Expected code={}."
                                                  "".format(ctr.code, CtrDex_1_0.ControllerIdxSigs))

        subpath = yield from self._extractor(ims,
                                             klas=Pather,
                                             cold=cold,
                                             abort=pipelined)
        if root is not None:
            subpath = subpath.root(root=root)

        sctr = yield from self._extractor(ims=ims,
                                          klas=Counter,
                                          cold=cold,
                                          abort=pipelined)
        if sctr.code == CtrDex_1_0.TransIdxSigGroups:
            for prefixer, seqner, saider, isigers in self._transIdxSigGroups(sctr, ims, cold=cold, pipelined=pipelined):
                yield sctr.code, (subpath, prefixer, seqner, saider, isigers)
        elif sctr.code == CtrDex_1_0.ControllerIdxSigs:
            isigers = []
            for i in range(sctr.count):  # extract each attached signature
                isiger = yield from self._extractor(ims=ims,
                                                    klas=Siger,
                                                    cold=cold,
                                                    abort=pipelined)
                isigers.append(isiger)
            yield sctr.code, (subpath, isigers)
        elif sctr.code == CtrDex_1_0.NonTransReceiptCouples:
            for cigar in self._nonTransReceiptCouples(ctr=sctr, ims=ims, cold=cold, pipelined=pipelined):
                yield sctr.code, (subpath, cigar)
        else:
            raise kering.UnexpectedCountCodeError("Wrong "
                                                  "count code={}.Expected code={}."
                                                  "".format(ctr.code, CtrDex_1_0.ControllerIdxSigs))


    def _transIdxSigGroups(self, ctr, ims, cold=Colds.txt, pipelined=False):
        """
        Extract attaced trans indexed sig groups each made of
        triple pre+snu+dig plus indexed sig group
        pre is pre of signer (endorser) of msg
        snu is sn of signer's est evt when signed
        dig is dig of signer's est event when signed
        followed by counter for ControllerIdxSigs with attached
        indexed sigs from trans signer (endorser).

        Parameters:
            ctr (Counter): group type counter
            ims (bytearray) of serialized incoming message stream.
                May contain one or more sets each of a serialized message with
                attached cryptographic material such as signatures or receipts.

            cold (str): next charater Coldage type indicayor
            pipelined (bool) True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.

        Yields:

        """
        for i in range(ctr.count):  # extract each attached groups
            prefixer = yield from self._extractor(ims,
                                                  klas=Prefixer,
                                                  cold=cold,
                                                  abort=pipelined)
            seqner = yield from self._extractor(ims,
                                                klas=Seqner,
                                                cold=cold,
                                                abort=pipelined)
            saider = yield from self._extractor(ims,
                                                klas=Saider,
                                                cold=cold,
                                                abort=pipelined)
            ictr = yield from self._extractor(ims=ims,
                                              klas=Counter,
                                              cold=cold,
                                              abort=pipelined)
            if ictr.code != CtrDex_1_0.ControllerIdxSigs:
                raise kering.UnexpectedCountCodeError("Wrong "
                                                      "count code={}.Expected code={}."
                                                      "".format(ictr.code, CtrDex_1_0.ControllerIdxSigs))
            isigers = []
            for i in range(ictr.count):  # extract each attached signature
                isiger = yield from self._extractor(ims=ims,
                                                    klas=Siger,
                                                    cold=cold,
                                                    abort=pipelined)
                isigers.append(isiger)

            yield prefixer, seqner, saider, isigers


    def _nonTransReceiptCouples(self, ctr, ims, cold=Colds.txt, pipelined=False):
        """
        Extract attached rct couplets into list of sigvers
        verfer property of cigar is the identifier prefix
        cigar itself has the attached signature

        Parameters:
            ctr (Counter): group type counter
            ims (bytearray) of serialized incoming message stream.
                May contain one or more sets each of a serialized message with
                attached cryptographic material such as signatures or receipts.

            cold (str): next charater Coldage type indicayor
            pipelined (bool) True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.

        Yields:

        """
        for i in range(ctr.count):  # extract each attached couple
            verfer = yield from self._extractor(ims=ims,
                                                klas=Verfer,
                                                cold=cold,
                                                abort=pipelined)
            cigar = yield from self._extractor(ims=ims,
                                               klas=Cigar,
                                               cold=cold,
                                               abort=pipelined)
            cigar.verfer = verfer

            yield cigar


    def parse(self, ims=None, framed=None, pipeline=None, kvy=None, tvy=None,
              exc=None, rvy=None, vry=None, local=None, gvrsn=Vrsn_1_0):
        """
        Processes all messages from incoming message stream, ims,
        when provided. Otherwise process messages from .ims
        Returns when ims is empty.
        Convenience executor for .processAllGen when ims is not live, i.e. fixed

        Parameters:
            ims is bytearray of incoming message stream. May contain one or more
                sets each of a serialized message with attached cryptographic
                material such as signatures or receipts.

            framed is Boolean, True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages

            pipeline is Boolean, True means use pipeline processor to process
                ims msgs when stream incpyludes pipelined count codes.

            kvy (Kevery): route KERI KEL message types to this instance
            tvy (Tevery): route TEL message types to this instance
            exc (Exchanger) route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            vry (Verfifier): credential verifier with wallet storage
            local (bool): True means event source is local (protected) for validation
                          False means event source is remote (unprotected) for validation
                          None means use default .local
            gvrsn (Versionage): instance of genera version of CESR code tables

        New Logic:
            Attachments must all have counters so know if txt or bny format for
            attachments. So even when framed==True must still have counters.
        """
        local = local if local is not None else self.local
        local = True if local else False


        parsator = self.allParsator(ims=ims,
                                    framed=framed,
                                    pipeline=pipeline,
                                    kvy=kvy,
                                    tvy=tvy,
                                    exc=exc,
                                    rvy=rvy,
                                    vry=vry,
                                    local=local,
                                    gvrsn=gvrsn)

        while True:
            try:
                next(parsator)
            except StopIteration:
                break


    def parseOne(self, ims=None, framed=True, pipeline=False, kvy=None, tvy=None,
                 exc=None, rvy=None, vry=None, local=None):
        """
        Processes one messages from incoming message stream, ims,
        when provided. Otherwise process message from .ims
        Returns once one message is processed.
        Convenience executor for .processOneGen when ims is not live, i.e. fixed

        Parameters:
            ims is bytearray of serialized incoming message stream.
                May contain one or more sets each of a serialized message with
                attached cryptographic material such as signatures or receipts.

            framed is Boolean, True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages

            pipeline is Boolean, True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.

            kvy (Kevery): route KERI KEL message types to this instance
            tvy (Tevery): route TEL message types to this instance
            exc (Exchanger) route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            local (bool): True means event source is local (protected) for validation
                          False means event source is remote (unprotected) for validation
                          None means use default .local

        New Logic:
            Attachments must all have counters so know if txt or bny format for
            attachments. So even when framed==True must still have counters.
        """
        local = local if local is not None else self.local
        local = True if local else False

        parsator = self.onceParsator(ims=ims,
                                     framed=framed,
                                     pipeline=pipeline,
                                     kvy=kvy,
                                     tvy=tvy,
                                     exc=exc,
                                     rvy=rvy,
                                     vry=vry,
                                     local=local)
        while True:
            try:
                next(parsator)
            except StopIteration:
                break


    def allParsator(self, ims=None, framed=None, pipeline=None, kvy=None,
                    tvy=None, exc=None, rvy=None, vry=None, local=None,
                    gvrsn=Vrsn_1_0):
        """
        Returns generator to parse all messages from incoming message stream,
        ims until ims is exhausted (empty) then returns.
        Generator completes as soon as ims is empty.
        If ims not provided then parse messages from .ims

        Parameters:
            ims is bytearray of incoming message stream. May contain one or more
                sets each of a serialized message with attached cryptographic
                material such as signatures or receipts.

            framed is Boolean, True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages

            pipeline is Boolean, True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.

            kvy (Kevery): route KERI KEL message types to this instance
            tvy (Tevery): route TEL message types to this instance
            exc (Exchanger) route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            vry (Verfifier): credential verifier with wallet storage
            local (bool): True means event source is local (protected) for validation
                          False means event source is remote (unprotected) for validation
                          None means use default .local
            gvrsn (Versionage): instance of genera version of CESR code tables

        New Logic:
            Attachments must all have counters so know if txt or bny format for
            attachments. So even when framed==True must still have counters.
        """
        if ims is not None:  # needs bytearray not bytes since deletes as processes
            if not isinstance(ims, bytearray):
                ims = bytearray(ims)  # so make bytearray copy
        else:
            ims = self.ims  # use instance attribute by default

        framed = framed if framed is not None else self.framed
        pipeline = pipeline if pipeline is not None else self.pipeline
        kvy = kvy if kvy is not None else self.kvy
        tvy = tvy if tvy is not None else self.tvy
        exc = exc if exc is not None else self.exc
        rvy = rvy if rvy is not None else self.rvy
        vry = vry if vry is not None else self.vry
        local = local if local is not None else self.local
        local = True if local else False

        while ims:  # only process until ims empty
            try:
                done = yield from self.msgParsator(ims=ims,
                                                   framed=framed,
                                                   pipeline=pipeline,
                                                   kvy=kvy,
                                                   tvy=tvy,
                                                   exc=exc,
                                                   rvy=rvy,
                                                   vry=vry,
                                                   local=local,
                                                   gvrsn=gvrsn)

            except kering.SizedGroupError as ex:  # error inside sized group
                # processOneIter already flushed group so do not flush stream
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser msg extraction error: %s", ex.args[0])
                else:
                    logger.error("Parser msg extraction error: %s", ex.args[0])

            except (kering.ColdStartError, kering.ExtractionError) as ex:  # some extraction error
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser msg extraction error: %s", ex.args[0])
                else:
                    logger.error("Parser msg extraction error: %s", ex.args[0])
                del ims[:]  # delete rest of stream to force cold restart

            except (kering.ValidationError, Exception) as ex:  # non Extraction Error
                # Non extraction errors happen after successfully extracted from stream
                # so we don't flush rest of stream just resume
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser msg non-extraction error: %s", ex)
                else:
                    logger.error("Parser msg non-extraction error: %s", ex)
            yield

        return True


    def onceParsator(self, ims=None, framed=None, pipeline=None, kvy=None,
                     tvy=None, exc=None, rvy=None, vry=None, local=None):
        """
        Returns generator to parse one message from incoming message stream, ims.
        If ims not provided parse messages from .ims

        Parameters:
            ims is bytearray of incoming message stream. May contain one or more
                sets each of a serialized message with attached cryptographic
                material such as signatures or receipts.

            framed is Boolean, True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages

            pipeline is Boolean, True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.

            kvy (Kevery): route KERI KEL message types to this instance
            tvy (Tevery): route TEL message types to this instance
            exc (Exchanger) route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            vry (Verfifier): credential verifier with wallet storage
            local (bool): True means event source is local (protected) for validation
                          False means event source is remote (unprotected) for validation
                          None means use default .local

        New Logic:
            Attachments must all have counters so know if txt or bny format for
            attachments. So even when framed==True must still have counters.
        """
        if ims is not None:  # needs bytearray not bytes since deletes as processes
            if not isinstance(ims, bytearray):
                ims = bytearray(ims)  # so make bytearray copy
        else:
            ims = self.ims  # use instance attribute by default

        framed = framed if framed is not None else self.framed
        pipeline = pipeline if pipeline is not None else self.pipeline
        kvy = kvy if kvy is not None else self.kvy
        tvy = tvy if tvy is not None else self.tvy
        exc = exc if exc is not None else self.exc
        rvy = rvy if rvy is not None else self.rvy
        vry = vry if vry is not None else self.vry
        local = local if local is not None else self.local
        local = True if local else False

        done = False
        while not done:
            try:
                done = yield from self.msgParsator(ims=ims,
                                                   framed=framed,
                                                   pipeline=pipeline,
                                                   kvy=kvy,
                                                   tvy=tvy,
                                                   exc=exc,
                                                   rvy=rvy,
                                                   vry=vry,
                                                   local=local)

            except kering.SizedGroupError as ex:  # error inside sized group
                # processOneIter already flushed group so do not flush stream
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery msg extraction error: %s", ex.args[0])
                else:
                    logger.error("Kevery msg extraction error: %s", ex.args[0])

            except (kering.ColdStartError, kering.ExtractionError) as ex:  # some extraction error
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery msg extraction error: %s", ex.args[0])
                else:
                    logger.error("Kevery msg extraction error: %s", ex.args[0])
                del ims[:]  # delete rest of stream to force cold restart

            except (kering.ValidationError, Exception) as ex:  # non Extraction Error
                # Non extraction errors happen after successfully extracted from stream
                # so we don't flush rest of stream just resume
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery msg non-extraction error: %s", ex)
                else:
                    logger.error("Kevery msg non-extraction error: %s", ex)
            finally:
                done = True

        return done


    def parsator(self, ims=None, framed=None, pipeline=None, kvy=None, tvy=None,
                 exc=None, rvy=None, vry=None, local=None):
        """
        Returns generator to continually parse messages from incoming message
        stream, ims. Empty yields when ims is emply. Does not return.
        Useful for always running servers.
        One yield from per each message if any.
        Continually yields while ims is empty, i.e. does not return.
        If ims not provided then parse messages from .ims

        Parameters:
            ims is bytearray of incoming message stream. May contain one or more
                sets each of a serialized message with attached cryptographic
                material such as signatures or receipts.

            framed is Boolean, True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages

            pipeline is Boolean, True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.

            kvy (Kevery): route KERI KEL message types to this instance
            tvy (Tevery): route TEL message types to this instance
            exc (Exchanger) route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            vry (Verifier): credential processor
            local (bool): True means event source is local (protected) for validation
                          False means event source is remote (unprotected) for validation
                          None means use default .local


        New Logic:
            Attachments must all have counters so know if txt or bny format for
            attachments. So even when framed==True must still have counters.
        """
        if ims is not None:  # needs bytearray not bytes since deletes as processes
            if not isinstance(ims, bytearray):
                ims = bytearray(ims)  # so make bytearray copy
        else:
            ims = self.ims  # use instance attribute by default

        framed = framed if framed is not None else self.framed
        pipeline = pipeline if pipeline is not None else self.pipeline
        kvy = kvy if kvy is not None else self.kvy
        tvy = tvy if tvy is not None else self.tvy
        exc = exc if exc is not None else self.exc
        rvy = rvy if rvy is not None else self.rvy
        vry = vry if vry is not None else self.vry
        local = local if local is not None else self.local
        local = True if local else False

        while True:  # continuous stream processing never stop
            try:
                done = yield from self.msgParsator(ims=ims,
                                                   framed=framed,
                                                   pipeline=pipeline,
                                                   kvy=kvy,
                                                   tvy=tvy,
                                                   exc=exc,
                                                   rvy=rvy,
                                                   vry=vry,
                                                   local=local)

            except kering.SizedGroupError as ex:  # error inside sized group
                # processOneIter already flushed group so do not flush stream
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser msg extraction error: %s", ex.args[0])
                else:
                    logger.error("Parser msg extraction error: %s", ex.args[0])

            except (kering.ColdStartError, kering.ExtractionError) as ex:  # some extraction error
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser msg extraction error: %s", ex.args[0])
                else:
                    logger.error("Parser msg extraction error: %s", ex.args[0])
                del ims[:]  # delete rest of stream to force cold restart

            except (kering.ValidationError, Exception) as ex:  # non Extraction Error
                # Non extraction errors happen after successfully extracted from stream
                # so we don't flush rest of stream just resume
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser msg non-extraction error: %s", ex.args[0])
                else:
                    logger.error("Parser msg non-extraction error: %s", ex.args[0])
            yield

        return True  # should never return


    def msgParsator(self, ims=None, framed=True, pipeline=False,
                    kvy=None, tvy=None, exc=None, rvy=None, vry=None,
                    local=None, gvrsn=Vrsn_1_0):
        """
        Returns generator that upon each iteration extracts and parses msg
        with attached crypto material (signature etc) from incoming message
        stream, ims, and dispatches processing of message with attachments.

        Uses .ims when ims is not provided.

        Iterator yields when not enough bytes in ims to finish one msg plus
        attachments. Returns (which raises StopIteration) when finished.

        Parameters:
            ims (bytearray) of serialized incoming message stream.
                May contain one or more sets each of a serialized message with
                attached cryptographic material such as signatures or receipts.

            framed (bool) True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages

            pipeline (bool) True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.

            kvy (Kevery) route KERI KEL message types to this instance
            tvy (Tevery) route TEL message types to this instance
            exc (Exchanger) route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            vry (Verifier) ACDC credential processor
            local (bool): True means event source is local (protected) for validation
                          False means event source is remote (unprotected) for validation
                          None means use default .local
            gvrsn (Versionage): instance of genera version of CESR code tables

        Logic:
            Currently only support couters on attachments not on combined or
            on message
            Attachments must all have counters so know if txt or bny format for
            attachments. So even when framed==True must still have counter.
            Do While loop
               sniff to set up first extraction
                  raise exception and flush full tream if stream start is counter
                  must be message
               extract message
               sniff for counter
               if group counter extract and discard but keep track of count
               so if error while processing attachments then only need to flush
               attachment count not full stream.


        """
        local = local if local is not None else self.local
        local = True if local else False

        serdery = serdering.Serdery(version=kering.Version)

        if ims is None:
            ims = self.ims

        while not ims:
            yield

        cold = sniff(ims)  # check for spurious counters at front of stream
        if cold in (Colds.txt, Colds.bny):  # not message error out to flush stream
            # replace with pipelining here once CESR message format supported.
            raise kering.ColdStartError("Expecting message counter tritet={}"
                                        "".format(cold))
        # Otherwise its a message cold start

        while True:  # extract, deserialize, and strip message from ims
            try:
                serder = serdery.reap(ims=ims)  # can set version here
            except kering.ShortageError as ex:  # need more bytes
                yield
            else: # extracted and stripped successfully
                break  # break out of while loop

        sigers = []  # list of Siger instances of attached indexed controller signatures
        wigers = []  # list of Siger instance of attached indexed witness signatures
        cigars = []  # List of cigars to hold nontrans rct couplets
        # List of tuples from extracted transferable receipt (vrc) quadruples
        trqs = []  # each converted quadruple is (prefixer, seqner, diger, siger)
        # List of tuples from extracted transferable indexed sig groups
        tsgs = []  # each converted group is tuple of (i,s,d) triple plus list of sigs
        # List of tuples from extracted signer seals sig groups
        ssgs = []  # each converted group is the identifier prefix plus list of sigs
        # List of tuples from extracted first seen replay couples
        frcs = []  # each converted couple is (seqner, dater)
        # List of tuples from extracted source seal couples (delegator or issuer)
        sscs = []  # each converted couple is (seqner, diger) for delegating or issuing event
        # List of tuples from extracted source seal triples (issuer or issuance tel event)
        ssts = []  # each converted couple is (seqner, diger) for delegating or issuing event
        # List of tuples from extracted SAD path sig groups from transferable identifiers
        sadtsgs = []  # each converted group is tuple of (path, i, s, d) quad plus list of sigs
        # List of tuples from extracted SAD path sig groups from non-trans identifiers
        sadcigs = []  # each converted group is path plus list of non-trans sigs
        pathed = []  # grouped attachments targetting a subpath
        essrs = []  # group texter
        pipelined = False  # all attachments in one big pipeline counted group
        # extract and deserialize attachments
        try:  # catch errors here to flush only counted part of stream
            # extract attachments must start with counter so know if txt or bny.
            while not ims:
                yield
            cold = sniff(ims)  # expect counter at front of attachments
            if cold != Colds.msg:  # not new message so process attachments
                ctr = yield from self._extractor(ims=ims, klas=Counter, cold=cold)
                if ctr.code == CtrDex_1_0.AttachmentGroup:  # pipeline ctr?
                    pipelined = True
                    # compute pipelined attached group size based on txt or bny
                    pags = ctr.count * 4 if cold == Colds.txt else ctr.count * 3
                    while len(ims) < pags:  # wait until rx full pipelned group
                        yield

                    pims = ims[:pags]  # copy out substream pipeline group
                    del ims[:pags]  # strip off from ims
                    ims = pims  # now just process substream as one counted frame

                    if pipeline:
                        pass  # pass extracted ims to pipeline processor
                        return

                    ctr = yield from self._extractor(ims=ims,
                                                     klas=Counter,
                                                     cold=cold,
                                                     abort=pipelined)

                # iteratively process attachment counters (all non pipelined)
                while True:  # do while already extracted first counter is ctr
                    if ctr.code == CtrDex_1_0.ControllerIdxSigs:
                        for i in range(ctr.count):  # extract each attached signature
                            siger = yield from self._extractor(ims=ims,
                                                               klas=Siger,
                                                               cold=cold,
                                                               abort=pipelined)
                            sigers.append(siger)

                    elif ctr.code == CtrDex_1_0.WitnessIdxSigs:
                        for i in range(ctr.count):  # extract each attached signature
                            wiger = yield from self._extractor(ims=ims,
                                                               klas=Siger,
                                                               cold=cold,
                                                               abort=pipelined)
                            wigers.append(wiger)

                    elif ctr.code == CtrDex_1_0.NonTransReceiptCouples:
                        # extract attached rct couplets into list of sigvers
                        # verfer property of cigar is the identifier prefix
                        # cigar itself has the attached signature
                        for cigar in self._nonTransReceiptCouples(ctr=ctr,
                                                                  ims=ims,
                                                                  cold=cold,
                                                        pipelined=pipelined):
                            cigars.append(cigar)

                    elif ctr.code == CtrDex_1_0.TransReceiptQuadruples:
                        # extract attaced trans receipt vrc quadruple
                        # spre+ssnu+sdig+sig
                        # spre is pre of signer of vrc
                        # ssnu is sn of signer's est evt when signed
                        # sdig is dig of signer's est event when signed
                        # sig is indexed signature of signer on this event msg

                        for i in range(ctr.count):  # extract each attached quadruple
                            prefixer = yield from self._extractor(ims,
                                                                  klas=Prefixer,
                                                                  cold=cold,
                                                                  abort=pipelined)
                            seqner = yield from self._extractor(ims,
                                                                klas=Seqner,
                                                                cold=cold,
                                                                abort=pipelined)
                            saider = yield from self._extractor(ims,
                                                                klas=Saider,
                                                                cold=cold,
                                                                abort=pipelined)
                            siger = yield from self._extractor(ims=ims,
                                                               klas=Siger,
                                                               cold=cold,
                                                               abort=pipelined)
                            trqs.append((prefixer, seqner, saider, siger))

                    elif ctr.code == CtrDex_1_0.TransIdxSigGroups:
                        # extract attaced trans indexed sig groups each made of
                        # triple pre+snu+dig plus indexed sig group
                        # pre is pre of signer (endorser) of msg
                        # snu is sn of signer's est evt when signed
                        # dig is dig of signer's est event when signed
                        # followed by counter for ControllerIdxSigs with attached
                        # indexed sigs from trans signer (endorser).
                        for (prefixer, seqner, saider, isigers) in \
                                self._transIdxSigGroups(ctr, ims, cold=cold,
                                                        pipelined=pipelined):
                            tsgs.append((prefixer, seqner, saider, isigers))

                    elif ctr.code == CtrDex_1_0.TransLastIdxSigGroups:
                        # extract attaced signer seal indexed sig groups each made of
                        # identifier pre plus indexed sig group
                        # pre is pre of signer (endorser) of msg
                        # followed by counter for ControllerIdxSigs with attached
                        # indexed sigs from trans signer (endorser).
                        for i in range(ctr.count):  # extract each attached groups
                            prefixer = yield from self._extractor(ims,
                                                                  klas=Prefixer,
                                                                  cold=cold,
                                                                  abort=pipelined)
                            ictr = yield from self._extractor(ims=ims,
                                                                    klas=Counter,
                                                                    cold=cold,
                                                                    abort=pipelined)
                            if ictr.code != CtrDex_1_0.ControllerIdxSigs:
                                raise kering.UnexpectedCountCodeError("Wrong "
                                                                      "count code={}.Expected code={}."
                                                                      "".format(ictr.code, CtrDex_1_0.ControllerIdxSigs))
                            isigers = []
                            for i in range(ictr.count):  # extract each attached signature
                                isiger = yield from self._extractor(ims=ims,
                                                                    klas=Siger,
                                                                    cold=cold,
                                                                    abort=pipelined)
                                isigers.append(isiger)
                            ssgs.append((prefixer, isigers))

                    elif ctr.code == CtrDex_1_0.FirstSeenReplayCouples:
                        # extract attached first seen replay couples
                        # snu+dtm
                        # snu is fn (first seen ordinal) of event
                        # dtm is dt of event
                        for i in range(ctr.count):  # extract each attached quadruple
                            firner = yield from self._extractor(ims,
                                                                klas=Seqner,
                                                                cold=cold,
                                                                abort=pipelined)
                            dater = yield from self._extractor(ims,
                                                               klas=Dater,
                                                               cold=cold,
                                                               abort=pipelined)
                            frcs.append((firner, dater))

                    elif ctr.code == CtrDex_1_0.SealSourceCouples:
                        # extract attached first seen replay couples
                        # snu+dig
                        # snu is sequence number  of event
                        # dig is digest of event
                        for i in range(ctr.count):  # extract each attached quadruple
                            seqner = yield from self._extractor(ims,
                                                                klas=Seqner,
                                                                cold=cold,
                                                                abort=pipelined)
                            saider = yield from self._extractor(ims,
                                                                klas=Saider,
                                                                cold=cold,
                                                                abort=pipelined)
                            sscs.append((seqner, saider))

                    elif ctr.code == CtrDex_1_0.SealSourceTriples:
                        # extract attached anchoring source event information
                        # pre+snu+dig
                        # pre is prefix of event
                        # snu is sequence number  of event
                        # dig is digest of event
                        for i in range(ctr.count):  # extract each attached quadruple
                            prefixer = yield from self._extractor(ims,
                                                                  klas=Prefixer,
                                                                  cold=cold,
                                                                  abort=pipelined)
                            seqner = yield from self._extractor(ims,
                                                                klas=Seqner,
                                                                cold=cold,
                                                                abort=pipelined)
                            saider = yield from self._extractor(ims,
                                                                klas=Saider,
                                                                cold=cold,
                                                                abort=pipelined)
                            ssts.append((prefixer, seqner, saider))

                    elif ctr.code == CtrDex_1_0.SadPathSigGroups:
                        path = yield from self._extractor(ims,
                                                          klas=Pather,
                                                          cold=cold,
                                                          abort=pipelined)
                        for i in range(ctr.count):
                            ictr = yield from self._extractor(ims=ims,
                                                              klas=Counter,
                                                              cold=cold,
                                                              abort=pipelined)
                            for code, sigs in self._sadPathSigGroup(ctr=ictr,
                                                                    ims=ims,
                                                                    root=path,
                                                                    cold=cold,
                                                                    pipelined=pipelined):
                                if code == CtrDex_1_0.TransIdxSigGroups:
                                    sadtsgs.append(sigs)
                                else:
                                    sadcigs.append(sigs)

                    elif ctr.code == CtrDex_1_0.PathedMaterialGroup:  # pathed ctr?
                        # compute pipelined attached group size based on txt or bny
                        pags = ctr.count * 4 if cold == Colds.txt else ctr.count * 3
                        while len(ims) < pags:  # wait until rx full pipelned group
                            yield

                        pims = ims[:pags]  # copy out substream pipeline group
                        del ims[:pags]  # strip off from ims
                        pathed.append(pims)

                    elif ctr.code == CtrDex_1_0.BigPathedMaterialGroup:  # pathed ctr?
                        # compute pipelined attached group size based on txt or bny
                        pags = ctr.count * 4 if cold == Colds.txt else ctr.count * 3
                        while len(ims) < pags:  # wait until rx full pipelned group
                            yield

                        pims = ims[:pags]  # copy out substream pipeline group
                        del ims[:pags]  # strip off from ims
                        pathed.append(pims)

                    elif ctr.code == CtrDex_1_0.ESSRPayloadGroup:
                        for i in range(ctr.count):
                            texter = yield from self._extractor(ims,
                                                                klas=Matter,
                                                                cold=cold,
                                                                abort=pipelined)
                            essrs.append(texter)


                    else:
                        raise kering.UnexpectedCountCodeError("Unsupported count"
                                                              " code={}.".format(ctr.code))

                    if pipelined:  # process to end of stream (group)
                        if not ims:  # end of pipelined group frame
                            break

                    elif framed:
                        # because not all in one pipeline group, each attachment
                        # group may switch stream state txt or bny
                        if not ims:  # end of frame
                            break
                        cold = sniff(ims)
                        if cold == Colds.msg:  # new message so attachments done
                            break  # finished attachments since new message
                    else:  # process until next message
                        # because not all in one pipeline group, each attachment
                        # group may switch stream state txt or bny
                        while not ims:
                            yield  # no frame so must wait for next message
                        cold = sniff(ims)  # ctr or msg
                        if cold == Colds.msg:  # new message
                            break  # finished attachments since new message

                    ctr = yield from self._extractor(ims=ims, klas=Counter, cold=cold)

        except kering.ExtractionError as ex:
            if pipelined:  # extracted pipelined group is preflushed
                raise kering.SizedGroupError("Error processing pipelined size"
                                             "attachment group of size={}.".format(pags))
            raise  # no pipeline group so can't preflush, must flush stream

        if isinstance(serder, serdering.SerderKERI):
            ilk = serder.ilk  # dispatch abased on ilk

            if ilk in [Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt]:  # event msg
                firner, dater = frcs[-1] if frcs else (None, None)  # use last one if more than one
                # when present assumes this is source seal of delegating event in delegator's KEL
                delseqner, delsaider = sscs[-1] if sscs else (None, None)  # use last one if more than one
                if not sigers:
                    raise kering.ValidationError("Missing attached signature(s) for evt "
                                                 "= {}.".format(serder.ked))
                try:
                    kvy.processEvent(serder=serder,
                                     sigers=sigers,
                                     wigers=wigers,
                                     delseqner=delseqner,
                                     delsaider=delsaider,
                                     firner=firner,
                                     dater=dater,
                                     local=local)

                    if cigars:
                        kvy.processAttachedReceiptCouples(serder, cigars,
                                                          firner=firner, local=local)
                    if trqs:
                        kvy.processAttachedReceiptQuadruples(serder, trqs,
                                                             firner=firner, local=local)

                except AttributeError as ex:
                    raise kering.ValidationError("No kevery to process so dropped msg"
                                                 "= {}.".format(serder.pretty())) from ex

            elif ilk in [Ilks.rct]:  # event receipt msg (nontransferable)
                if not (cigars or wigers or tsgs):
                    raise kering.ValidationError("Missing attached signatures on receipt"
                                                 "msg = {}.".format(serder.ked))

                try:
                    if cigars:
                        kvy.processReceipt(serder=serder, cigars=cigars,
                                           local=local)

                    if wigers:
                        kvy.processReceiptWitness(serder=serder, wigers=wigers,
                                                  local=local)

                    if tsgs:
                        kvy.processReceiptTrans(serder=serder, tsgs=tsgs,
                                                local=local)

                except AttributeError:
                    raise kering.ValidationError("No kevery to process so dropped msg"
                                                 "= {}.".format(serder.pretty()))

            elif ilk in (Ilks.rpy,):  # reply message
                if not (cigars or tsgs):
                    raise kering.ValidationError("Missing attached endorser signature(s) "
                                                 "to reply msg = {}.".format(serder.pretty()))

                try:
                    if cigars:  # process separately so do not clash on errors
                        rvy.processReply(serder, cigars=cigars)  # nontrans

                    if tsgs:  # process separately so do not clash on errors
                        rvy.processReply(serder, tsgs=tsgs)  # trans

                except AttributeError as e:
                    raise kering.ValidationError("No revery to process so dropped msg"
                                                 "= {}.".format(serder.pretty())) from e

            elif ilk in (Ilks.qry,):  # query message
                args = dict(serder=serder)
                if ssgs:
                    pre, sigers = ssgs[-1] if ssgs else (None, None)  # use last one if more than one
                    args["source"] = pre
                    args["sigers"] = sigers

                elif cigars:
                    args["cigars"] = cigars

                else:
                    raise kering.ValidationError("Missing attached requester signature(s) "
                                                 "to key log query msg = {}.".format(serder.pretty()))

                route = serder.ked["r"]
                if route in ["logs", "ksn", "mbx"]:
                    try:
                        kvy.processQuery(**args)
                    except AttributeError as e:
                        raise kering.ValidationError("No kevery to process so dropped msg"
                                                     "= {} from e = {}".format(serder.pretty(), e))

                elif route in ["tels", "tsn"]:
                    try:
                        tvy.processQuery(**args)
                    except AttributeError as e:
                        raise kering.ValidationError("No tevery to process so dropped msg"
                                                     "= {} from {}.".format(serder.pretty(), e))

                else:
                    raise kering.ValidationError("Invalid resource type {} so dropped msg"
                                                 "= {}.".format(route, serder.pretty()))

            elif ilk in (Ilks.exn,):
                args = dict(serder=serder)
                if pathed:
                    args["pathed"] = pathed

                if essrs:
                    args["essrs"] = essrs

                try:
                    if cigars:
                        exc.processEvent(cigars=cigars, **args)

                    if tsgs:
                        exc.processEvent(tsgs=tsgs, **args)

                except AttributeError:
                    raise kering.ValidationError("No Exchange to process so dropped msg"
                                                 "= {}.".format(serder.pretty()))

            elif ilk in (Ilks.vcp, Ilks.vrt, Ilks.iss, Ilks.rev, Ilks.bis, Ilks.brv):
                # TEL msg
                # this transaction event seal in Issuer's KEL (controller of Issuer AID)
                seqner, saider = sscs[-1] if sscs else (None, None)  # use last one if more than one
                try:
                    tvy.processEvent(serder=serder, seqner=seqner, saider=saider, wigers=wigers)

                except AttributeError as e:
                    raise kering.ValidationError("No tevery to process so dropped msg"
                                                 "= {}.".format(serder.pretty()))
            else:
                raise kering.ValidationError("Unexpected message ilk = {} for evt ="
                                             " {}.".format(ilk, serder.pretty()))

        elif isinstance(serder, serdering.SerderACDC):
            ilk = serder.ilk  # dispatch based on ilk

            if ilk is None:  # default for ACDC
                try:
                    prefixer, seqner, saider = ssts[-1] if ssts else (None, None, None)  # use last one if more than one
                    vry.processCredential(creder=serder, prefixer=prefixer, seqner=seqner, saider=saider)
                except AttributeError as e:
                    raise kering.ValidationError("No verifier to process so dropped credential"
                                                 "= {}.".format(serder.pretty()))
            else:
                raise kering.ValidationError("Unexpected message ilk = {} for evt ="
                                             " {}.".format(ilk, serder.pretty()))

        else:
            raise kering.ValidationError("Unexpected protocol type = {} for event message ="
                                         " {}.".format(serder.proto, serder.pretty()))

        return True  # done state
