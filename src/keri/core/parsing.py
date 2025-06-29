# -*- encoding: utf-8 -*-
"""
keri.core.parsing module

message stream parsing support
"""
import copy
import logging
from dataclasses import asdict
from collections import deque
from base64 import urlsafe_b64decode as decodeB64
from base64 import urlsafe_b64encode as encodeB64

from .. import kering
from ..kering import (Colds, sniff, Vrsn_1_0, Vrsn_2_0,
                      ShortageError, ColdStartError)
from .coring import (Ilks, Seqner, Cigar,
                     Dater, Verfer, Prefixer, Saider, Texter)
from .counting import (Counter, Codens, CtrDex_1_0, CtrDex_2_0, GenDex,
                       UniDex_1_0, UniDex_2_0)
from .indexing import (Siger, )
from . import serdering
from .. import help



logger = help.ogler.getLogger()


class Parser:
    """Parser is stream parser that processes an incoming message stream.
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
        piped (bool): True means use pipeline processor to process
                whenever stream includes pipelined count codes.
        kvy (Kevery): route KEL message types to this instance
        tvy (Tevery): route TEL message types to this instance
        exc (Exchanger): route EXN message types to this instance
        rvy (Revery): reply (RPY) message handler
        vry (Verfifier): credential verifier with wallet storage
        local (bool): True means event source is local (protected) for validation
                         False means event source is remote (unprotected) for validation

    Properties:
        genus (str): genus portion of default CESR code table protocol genus code
        version (Versionage): current CESR protocol genus version in context
        methods (dict): method names for counter extraction, keyed by count code name
        codes (CtrDex): selected by .version from (CtrDex_1_0, CtrDex_2_0)
        sucodes (SUDex): selected by .version from  (SUDex_1_0, SUDex_2_0)
        mucodes (MUDex): selected by .version from  (MUDex_1_0, MUDex_2_0)


    Hidden:
        _version (Versionage): value for .version property
        _genus (str): value for .genus property

        _methods (dict): value for .methods property
        _codes (CtrDex): value for .codes property
        _sucodes (SUDex): value for .sucodes property
        _mucodes (MUDex): value for .mucodes property

    """
    Codes = Counter.Codes  # code tables from Counter
    SUCodes = Counter.SUCodes # special universal code tables from Counter
    MUCodes = Counter.MUCodes # message universal code tables from Counter
    Methods = copy.deepcopy(Counter.Codes)  # make deep copy so not mutate Counter
    for minor in Methods.values():  # assign None as default val for all possible code names
        for key in minor:
            minor[key] = {key: None for key in asdict(minor[key])}

    # reassign method name val for those code names that have a supporting method
    Methods[1][0][Codens.ControllerIdxSigs] = "_ControllerIdxSigs1"
    Methods[2][0][Codens.ControllerIdxSigs] = "_ControllerIdxSigs2"
    Methods[2][0][Codens.BigControllerIdxSigs] = "_ControllerIdxSigs2"

    Methods[1][0][Codens.WitnessIdxSigs] = "_WitnessIdxSigs1"
    Methods[2][0][Codens.WitnessIdxSigs] = "_WitnessIdxSigs2"
    Methods[2][0][Codens.BigWitnessIdxSigs] = "_WitnessIdxSigs2"

    Methods[1][0][Codens.NonTransReceiptCouples] = "_NonTransReceiptCouples1"
    Methods[2][0][Codens.NonTransReceiptCouples] = "_NonTransReceiptCouples2"
    Methods[2][0][Codens.BigNonTransReceiptCouples] = "_NonTransReceiptCouples2"

    Methods[1][0][Codens.TransReceiptQuadruples] = "_TransReceiptQuadruples1"
    Methods[2][0][Codens.TransReceiptQuadruples] = "_TransReceiptQuadruples2"
    Methods[2][0][Codens.BigTransReceiptQuadruples] = "_TransReceiptQuadruples2"

    Methods[1][0][Codens.TransIdxSigGroups] = "_TransIdxSigGroups1"
    Methods[2][0][Codens.TransIdxSigGroups] = "_TransIdxSigGroups2"
    Methods[2][0][Codens.BigTransIdxSigGroups] = "_TransIdxSigGroups2"

    Methods[1][0][Codens.TransLastIdxSigGroups] = "_TransLastIdxSigGroups1"
    Methods[2][0][Codens.TransLastIdxSigGroups] = "_TransLastIdxSigGroups2"
    Methods[2][0][Codens.BigTransLastIdxSigGroups] = "_TransLastIdxSigGroups2"

    Methods[1][0][Codens.FirstSeenReplayCouples] = "_FirstSeenReplayCouples1"
    Methods[2][0][Codens.FirstSeenReplayCouples] = "_FirstSeenReplayCouples2"
    Methods[2][0][Codens.BigFirstSeenReplayCouples] = "_FirstSeenReplayCouples2"

    Methods[1][0][Codens.PathedMaterialGroup] = "_PathedMaterialGroup"
    Methods[1][0][Codens.BigPathedMaterialGroup] = "_PathedMaterialGroup"
    Methods[2][0][Codens.PathedMaterialGroup] = "_PathedMaterialGroup"
    Methods[2][0][Codens.BigPathedMaterialGroup] = "_PathedMaterialGroup"

    Methods[1][0][Codens.SealSourceTriples] = "_SealSourceTriples1"
    Methods[2][0][Codens.SealSourceTriples] = "_SealSourceTriples2"
    Methods[2][0][Codens.BigSealSourceTriples] = "_SealSourceTriples2"

    Methods[1][0][Codens.SealSourceCouples] = "_SealSourceCouples1"
    Methods[2][0][Codens.SealSourceCouples] = "_SealSourceCouples2"
    Methods[2][0][Codens.BigSealSourceCouples] = "_SealSourceCouples2"

    Methods[1][0][Codens.ESSRPayloadGroup] = "_ESSRPayloadGroup1"
    Methods[1][0][Codens.BigESSRPayloadGroup] = "_ESSRPayloadGroup1"
    Methods[2][0][Codens.ESSRPayloadGroup] = "_ESSRPayloadGroup2"
    Methods[2][0][Codens.BigESSRPayloadGroup] = "_ESSRPayloadGroup2"



    def __init__(self, ims=None, framed=True, piped=False, kvy=None,
                 tvy=None, exc=None, rvy=None, vry=None, local=False,
                 version=Vrsn_2_0):
        """
        Initialize instance:

        Parameters:
            ims (bytearray): incoming message stream
            framed (bool): True means ims contains only one msg body plus
                its foot of attachments, not multiple sets of msg body plus foot
            piped (bool): True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.
            kvy (Kevery): route KEL message types to this instance
            tvy (Tevery): route TEL message types to this instance
            exc (Exchanger): route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            vry (Verfifier): credential verifier with wallet storage
            local (bool): True means event source is local (protected) for validation
                         False means event source is remote (unprotected) for validation
            version (Versionage): instance of version portion of genus version code
                                  for default code table
        """
        self.ims = ims if ims is not None else bytearray()
        self.framed = True if framed else False  # extract until end-of-stream
        self.piped = True if piped else False  # use pipeline processor
        self.kvy = kvy
        self.tvy = tvy
        self.exc = exc
        self.rvy = rvy
        self.vry = vry
        self.local = True if local else False

        self._genus = GenDex.KERI  # only supports KERI
        self.version = version  # provided version may be earlier than supported version
        # version sets  .methods, .codes, .sucodes, and .mucodes


    @property
    def genus(self):
        """Makes .genus read only
        Returns ._genus
        """
        return self._genus


    @property
    def version(self):
        """Makes .version read only default version from genus-version code
        Returns ._version
        """
        return self._version

    @version.setter
    def version(self, version):
        """Property setter for .version

        Parameters:
            version (Versionage|None): version portion of genus-versioncode
                If None do nothing

        """
        if version is not None:
            if version.major not in self.Methods:
                raise kering.InvalidVersionError(f"Unsupported major version="
                                                 f"{version.major}.")

            latest = list(self.Methods[version.major])[-1]  # get latest supported minor version
            if version.minor > latest:
                raise kering.InvalidVersionError(f"Minor version={version.minor} "
                                                 f" exceeds latest supported minor"
                                                 f" version={latest}.")
            self._version = version
            self._methods = self.Methods[version.major][latest]
            self._codes = self.Codes[version.major][latest]
            self._sucodes = self.SUCodes[version.major][latest]
            self._mucodes = self.MUCodes[version.major][latest]

    @property
    def methods(self):
        """Gets methods from .Methods for .version current version in stream context
        Returns:
            methods (dict): method names for counter extraction, keyed by count code name
        """
        return self._methods

    @property
    def codes(self):
        """Makes .codes read only
        Returns:
            _codes (CtrDex): selected by .version from (CtrDex_1_0, CtrDex_2_0)
        """
        return self._codes

    @property
    def sucodes(self):
        """Makes .sucodes read only
        Returns:
            _sucodes (SUDex): selected by .version from (SUDex_1_0, SUDex_2_0)
        """
        return self._sucodes

    @property
    def mucodes(self):
        """Makes .mucodes read only
        Returns:
            _mucodes (MUDex): selected by .version from (MUDex_1_0, MUDex_2_0)
        """
        return self._mucodes


    def extract(self, ims, klas, cold=Colds.txt):
        """Extract and return instance of klas from input message stream, ims, given
        stream state, cold, is txt or bny. Inits klas from ims using qb64b or
        qb2 parameter based on cold.

        Parameters:
            ims (bytearray): input message stream (must be strippable)
            klas (Serder | Counter | Matter | Indexer): subclass that is parsable
            cold (Coldage): instance str value

        """
        if cold == Colds.txt:
            return klas(qb64b=ims, strip=True, version=self.version)
        elif cold == Colds.bny:
            return klas(qb2=ims, strip=True, version=self.version)
        else:
            raise ColdStartError(f"Invalid stream state {cold=}")


    def _extractor(self, ims, klas, cold=Colds.txt, abort=False, strip=True):
        """Returns generator to extract and return instance of klas from input
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
            strip (bool): True means strip extracted instance from ims
                          False means do not strip, so can peek at stream

        Usage:
            yield from self._extractor(ims=ims, klas=Counter)
        """
        while True:
            try:
                if cold == Colds.txt:
                    return klas(qb64b=ims, strip=strip, version=self.version)
                elif cold == Colds.bny:
                    return klas(qb2=ims, strip=strip, version=self.version)
                else:
                    raise ColdStartError(f"Invalid stream state {cold=}")
            except ShortageError as ex:
                if abort:  # pipelined pre-collects full frame before extracting
                    raise  # bad pipelined frame so abort by raising error
                yield


    def parse(self, ims=None, framed=None, piped=None, kvy=None, tvy=None,
              exc=None, rvy=None, vry=None, local=None, version=None):
        """Processes all messages from incoming message stream, ims,
        when provided. Otherwise process messages from .ims
        Returns when ims is empty.
        Convenience executor for .allParsatator when ims is not live, i.e. fixed

        Parameters:
            ims (bytearray): incoming message stream. May contain one or more
                sets each of a serialized message with attached cryptographic
                material such as signatures or receipts.
            framed (bool): True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages
            piped (bool):  True means use pipeline processor to process
                ims msgs when stream incpyludes pipelined count codes.
            kvy (Kevery): route KERI KEL message types to this instance
            tvy (Tevery): route TEL message types to this instance
            exc (Exchanger) route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            vry (Verfifier): credential verifier with wallet storage
            local (bool): True means event source is local (protected) for validation
                          False means event source is remote (unprotected) for validation
                          None means use default .local
            version (Versionage): default version of CESR to use
                                  None means do not change default

        New Logic:
            Attachments must all have counters so know if txt or bny format for
            attachments. So even when framed==True must still have counters.
        """
        local = local if local is not None else self.local
        local = True if local else False


        parsator = self.allParsator(ims=ims,
                                    framed=framed,
                                    piped=piped,
                                    kvy=kvy,
                                    tvy=tvy,
                                    exc=exc,
                                    rvy=rvy,
                                    vry=vry,
                                    local=local,
                                    version=version)

        while True:
            try:
                next(parsator)
            except StopIteration:
                break


    def parseOne(self, ims=None, framed=True, piped=False, kvy=None, tvy=None,
                 exc=None, rvy=None, vry=None, local=None, version=None):
        """Processes one messages from incoming message stream, ims,
        when provided. Otherwise process message from .ims
        Returns once one message is processed.
        Convenience executor for .processOneGen when ims is not live, i.e. fixed

        Parameters:
            ims (bytearray): serialized incoming message stream.
                May contain one or more sets each of a serialized message with
                attached cryptographic material such as signatures or receipts.
            framed (bool) True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages
            piped (bool): True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.
            kvy (Kevery): route KERI KEL message types to this instance
            tvy (Tevery): route TEL message types to this instance
            exc (Exchanger) route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            local (bool): True means event source is local (protected) for validation
                          False means event source is remote (unprotected) for validation
                          None means use default .local
            version (Versionage): default genera version of CESR to use
                                  None means do not change default

        New Logic:
            Attachments must all have counters so know if txt or bny format for
            attachments. So even when framed==True must still have counters.
        """
        local = local if local is not None else self.local
        local = True if local else False

        parsator = self.onceParsator(ims=ims,
                                     framed=framed,
                                     piped=piped,
                                     kvy=kvy,
                                     tvy=tvy,
                                     exc=exc,
                                     rvy=rvy,
                                     vry=vry,
                                     local=local,
                                     version=version)
        while True:
            try:
                next(parsator)
            except StopIteration:
                break


    def allParsator(self, ims=None, framed=None, piped=None, kvy=None,
                    tvy=None, exc=None, rvy=None, vry=None, local=None,
                    version=None):
        """Returns generator to parse all messages from incoming message stream,
        ims until ims is exhausted (empty) then returns.
        Generator completes as soon as ims is empty.
        If ims not provided then parse messages from .ims

        Parameters:
            ims (bytearray): of incoming message stream. May contain one or more
                sets each of a serialized message with attached cryptographic
                material such as signatures or receipts.
            framed (bool): True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages
            piped (bool): True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.
            kvy (Kevery): route KERI KEL message types to this instance
            tvy (Tevery): route TEL message types to this instance
            exc (Exchanger) route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            vry (Verfifier): credential verifier with wallet storage
            local (bool): True means event source is local (protected) for validation
                          False means event source is remote (unprotected) for validation
                          None means use default .local
            version (Versionage): default version of CESR to use
                                None means do not change default

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
        piped = piped if piped is not None else self.piped
        kvy = kvy if kvy is not None else self.kvy
        tvy = tvy if tvy is not None else self.tvy
        exc = exc if exc is not None else self.exc
        rvy = rvy if rvy is not None else self.rvy
        vry = vry if vry is not None else self.vry
        local = local if local is not None else self.local
        local = True if local else False

        while ims:  # only process until ims empty (differs here from parsator)
            try:
                done = yield from self.groupParsator(ims=ims,
                                                   framed=framed,
                                                   piped=piped,
                                                   kvy=kvy,
                                                   tvy=tvy,
                                                   exc=exc,
                                                   rvy=rvy,
                                                   vry=vry,
                                                   local=local,
                                                   version=version)


            except kering.SizedGroupError as ex:  # error inside sized group
                # processOneIter already flushed group so do not flush stream
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser sized group error: %s", ex.args[0])
                else:
                    logger.error("Parser sized group error: %s", ex.args[0])

            except (kering.ColdStartError, kering.ExtractionError) as ex:  # some extraction error
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser msg extraction error: %s", ex.args[0])
                else:
                    logger.error("Parser msg extraction error: %s", ex.args[0])
                del ims[:]  # delete rest of stream to force cold restart

            except (kering.ValidationError, Exception) as ex:  # non Extraction Error
                # Non extraction errors happen after successfully extracted from stream
                # so we don't flush rest of stream just resume
                if logger.isEnabledFor(logging.TRACE):
                    logger.exception("Parser msg non-extraction error: %s", ex)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.error("Parser msg non-extraction error: %s", ex)
            yield

        return True


    def onceParsator(self, ims=None, framed=None, piped=None, kvy=None,
                     tvy=None, exc=None, rvy=None, vry=None, local=None,
                     version=None):
        """Returns generator to parse one message from incoming message stream, ims.
        If ims not provided parse messages from .ims

        Parameters:
            ims (bytearray): incoming message stream. May contain one or more
                sets each of a serialized message with attached cryptographic
                material such as signatures or receipts.
            framed (bool): True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages
            piped (bool): True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.
            kvy (Kevery): route KERI KEL message types to this instance
            tvy (Tevery): route TEL message types to this instance
            exc (Exchanger) route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            vry (Verfifier): credential verifier with wallet storage
            local (bool): True means event source is local (protected) for validation
                          False means event source is remote (unprotected) for validation
                          None means use default .local
            version (Versionage): default version of CESR to use
                                  None means do not change default

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
        piped = piped if piped is not None else self.piped
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
                                                   piped=piped,
                                                   kvy=kvy,
                                                   tvy=tvy,
                                                   exc=exc,
                                                   rvy=rvy,
                                                   vry=vry,
                                                   local=local,
                                                   version=version)

            except kering.SizedGroupError as ex:  # error inside sized group
                # processOneIter already flushed group so do not flush stream
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery sized group error: %s", ex.args[0])
                else:
                    logger.error("Kevery sized group error: %s", ex.args[0])

            except (kering.ColdStartError, kering.ExtractionError) as ex:  # some extraction error
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery msg extraction error: %s", ex.args[0])
                else:
                    logger.error("Kevery msg extraction error: %s", ex.args[0])
                del ims[:]  # delete rest of stream to force cold restart

            except (kering.ValidationError, Exception) as ex:  # non Extraction Error
                # Non extraction errors happen after successfully extracted from stream
                # so we don't flush rest of stream just resume
                if logger.isEnabledFor(logging.TRACE):
                    logger.exception("Kevery msg non-extraction error: %s", ex)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.error("Kevery msg non-extraction error: %s", ex)
            finally:
                done = True

        return done


    def parsator(self, ims=None, framed=None, piped=None, kvy=None, tvy=None,
                 exc=None, rvy=None, vry=None, local=None, version=None):
        """Returns generator to continually parse messages from incoming message
        stream, ims. Empty yields when ims is emply. Does not return.
        Useful for always running servers.
        One yield from per each message if any.
        Continually yields while ims is empty, i.e. does not return.
        If ims not provided then parse messages from .ims

        Parameters:
            ims (bytearray): incoming message stream. May contain one or more
                sets each of a serialized message with attached cryptographic
                material such as signatures or receipts.
            framed (bool): True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages
            piped (bool): True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.
            kvy (Kevery): route KERI KEL message types to this instance
            tvy (Tevery): route TEL message types to this instance
            exc (Exchanger) route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            vry (Verifier): credential processor
            local (bool): True means event source is local (protected) for validation
                          False means event source is remote (unprotected) for validation
                          None means use default .local
            version (Versionage): default version of CESR to use
                                  None means do not change default

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
        piped = piped if piped is not None else self.piped
        kvy = kvy if kvy is not None else self.kvy
        tvy = tvy if tvy is not None else self.tvy
        exc = exc if exc is not None else self.exc
        rvy = rvy if rvy is not None else self.rvy
        vry = vry if vry is not None else self.vry
        local = local if local is not None else self.local
        local = True if local else False

        while True:  # continuous stream processing (differs here from allParsator)
            try:
                done = yield from self.groupParsator(ims=ims,
                                                   framed=framed,
                                                   piped=piped,
                                                   kvy=kvy,
                                                   tvy=tvy,
                                                   exc=exc,
                                                   rvy=rvy,
                                                   vry=vry,
                                                   local=local,
                                                   version=version)


                #done = yield from self.msgParsator(ims=ims,
                                                   #framed=framed,
                                                   #piped=piped,
                                                   #kvy=kvy,
                                                   #tvy=tvy,
                                                   #exc=exc,
                                                   #rvy=rvy,
                                                   #vry=vry,
                                                   #local=local,
                                                   #version=version)

            except kering.SizedGroupError as ex:  # error inside sized group
                # processOneIter already flushed group so do not flush stream
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser sized group error: %s", ex.args[0])
                else:
                    logger.error("Parser sized group error: %s", ex.args[0])

            except (kering.ColdStartError, kering.ExtractionError) as ex:  # some extraction error
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser msg extraction error: %s", ex.args[0])
                else:
                    logger.error("Parser msg extraction error: %s", ex.args[0])
                del ims[:]  # delete rest of stream to force cold restart

            except (kering.ValidationError, Exception) as ex:  # non Extraction Error
                # Non extraction errors happen after successfully extracted from stream
                # so we don't flush rest of stream just resume
                if logger.isEnabledFor(logging.TRACE):
                    logger.exception("Parser msg non-extraction error: %s", ex.args[0])
                if logger.isEnabledFor(logging.DEBUG):
                    logger.error("Parser msg non-extraction error: %s", ex.args[0])
            yield

        return True  # should never return


    def groupParsator(self, ims=None, framed=True, piped=False, kvy=None,
                    tvy=None, exc=None, rvy=None, vry=None, local=None,
                    version=None):
        """Returns generator to parse nested GenericGroups whose outermost nesting
        appears at the top-lever of an incoming message stream.

        If ims not provided then parse messages from .ims

        Parameters:
            ims (bytearray): of incoming message stream. May contain one or more
                sets each of a serialized message with attached cryptographic
                material such as signatures or receipts.
            framed (bool): True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages
            piped (bool): True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.
            kvy (Kevery): route KERI KEL message types to this instance
            tvy (Tevery): route TEL message types to this instance
            exc (Exchanger) route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            vry (Verfifier): credential verifier with wallet storage
            local (bool): True means event source is local (protected) for validation
                          False means event source is remote (unprotected) for validation
                          None means use default .local
            version (Versionage): default version of CESR to use
                                None means do not change default

        """
        if ims is None:
            ims = self.ims

        local = local if local is not None else self.local
        local = True if local else False

        self.version = version  # when not None which sets .methods .codes .mucodes .sucodes

        stack = deque()  # (svrsn, ims) stack of nested substreams framed by generic groegups
        svrsn = None
        eggs = None  # used in preflused error
        done = False
        try:
            while True:  # process stream until done
                while not ims and stack:  # happens when ascending (un-nesting)
                    svrsn, ims = stack.pop()  # un-nest
                    self.version = svrsn  # only changes if svrsn is not None

                if not ims:  # no stream and no stack
                    break

                # check front of stream for GenericGroup to nest down
                cold = sniff(ims)  # check front of stream
                if cold != Colds.msg:  # peek for generic group at front of ims
                    ctr = yield from self._extractor(ims=ims,
                                                     klas=Counter,
                                                     cold=cold,
                                                     abort=framed,
                                                     strip=False)

                    if (ctr.code in (self.sucodes.GenericGroup,
                                     self.sucodes.BigGenericGroup)):
                        del ims[:ctr.byteSize(cold=cold)]  # consume ctr itself
                        # compute enclosing generic group size based on txt or bny
                        eggs = ctr.byteCount(cold=cold)
                        while len(ims) < eggs and not framed:  # framed already in ims
                            yield

                        eims = ims[:eggs]  # copy out substream enclosed attachments
                        del ims[:eggs]  # strip off from ims

                        # peek for version code at front of eims
                        ctr = yield from self._extractor(ims=eims,
                                                        klas=Counter,
                                                        cold=cold,
                                                        abort=framed,
                                                        strip=False)

                        if ctr.code == self.codes.KERIACDCGenusVersion:
                            del eims[:ctr.byteSize(cold=cold)]  # consume ctr itself
                            # get new substream version
                            svrsn = Counter.b64ToVer(ctr.countToB64(l=3))
                        else:
                            svrsn == None  # no change to substream version

                        stack.append((self.version, ims))  # push current version ims
                        self.version = svrsn  # replace with new version if not None
                        ims = eims  # replace ims to nest down one level
                        # top-level nested generics enclose messages plus attachments
                        framed = True

                        if piped:
                            pass  # pass extracted ims to pipeline processor
                            return  # pop stack here instead

                        continue  # captures immediate further nested groups

                # process substream at current nesting level
                try:
                    done = yield from self.msgParsator(ims=ims,
                                                       framed=framed,
                                                       piped=piped,
                                                       kvy=kvy,
                                                       tvy=tvy,
                                                       exc=exc,
                                                       rvy=rvy,
                                                       vry=vry,
                                                       local=local,
                                                       version=self.version)
                except kering.TopLevelStreamError as ex:  # encountered GenericGroup
                    continue  # so returns control here to parse that group

                except (kering.ValidationError, Exception) as ex:  # non Extraction Error
                    # Non extraction errors happen after a message has been
                    # successfully extracted from stream
                    # so we don't flush rest of stream just resume
                    continue


        except kering.ExtractionError as ex:  # maybe this needs to be more granular
            if eggs is not None:  # extracted enclosed message group is preflushed
                raise kering.SizedGroupError(f"Error processing generic group"
                                                 f" of size={eggs}")
            raise  # no enclosing message group so can't preflush, must flush stream

        finally:  # restore version at top level
            while stack:  # when tail end of group has validation error
                svrsn, _ = stack.pop()
                if svrsn:
                    self.version = svrsn
        return done


    def msgParsator(self, ims=None, framed=True, piped=False,
                    kvy=None, tvy=None, exc=None, rvy=None, vry=None,
                    local=None, version=None):
        """Returns generator that upon each iteration extracts and parses msg
        with attached crypto material (signature etc) from incoming message
        stream, ims, and dispatches processing of message with attachments.

        Uses .ims when ims is not provided.

        Iterator yields when not enough bytes in ims to finish one msg plus
        attachments. Returns (which raises StopIteration) when finished.

        Parameters:
            ims (bytearray): serialized incoming message stream.
                May contain one or more sets each of a serialized message with
                attached cryptographic material such as signatures or receipts.
            framed (bool): True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages
            piped (bool): True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.
            kvy (Kevery): route KERI KEL message types to this instance
            tvy (Tevery): route TEL message types to this instance
            exc (Exchanger): route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            vry (Verifier): ACDC credential processor
            local (bool): True means event source is local (protected) for validation
                          False means event source is remote (unprotected) for validation
                          None means use default .local
            version (Versionage): default version of CESR to use.
                                  None means do not change default

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
        if ims is None:
            ims = self.ims

        local = local if local is not None else self.local
        local = True if local else False

        self.version = version  # when not None which sets .codes .mucodes. .sucodes
        verstack = deque()  # version stack append and pop

        # create exts (extracts) keyword args dict with fields:
        # serder (Serder): message instance
        # sigers (list[Siger]): attached indexed controller signatures
        # wigers (list[Siger]): attached indexed witness signatures
        # cigars (list[Cigar]): attached non-transferable from couple (verfer, sig)
        # trqs (list[tuple]): (prefixer, seqner, saider, siger)
        # tsgs (list[tuple]): (prefixer, seqner, saider, [Sigers]) triple plus list of sigs
        # ssgs (list[tuple]): (prefixer,[Sigers]) single plus list of sigs
        # frcs (list[tuple]): (seqner, dater)
        # sscs (list[tuple]): (seqner, saider) issuing or delegating
        # ssts (list[tuple]): (prefixer, seqner, saider) issued or delegated
        # ptds (list[bytes]): pathed streams
        # essrs (list[Texter]): essr encapsulations as Texters
        # local (bool): True if local source controller context for processing
        exts = dict(serder=None, sigers=[], wigers=[], cigars=[], trqs=[],
                    tsgs=[], ssgs=[], frcs=[], sscs=[], ssts=[], ptds=[],
                    essrs=[], local=local)

        serdery = serdering.Serdery(version=kering.Version)


        try:
            while not ims and not framed:
                yield

            emgs = None  # size of enclosing message group if any when is not None
            ctr = None  # no counter to process when not None then extracted need to process

            # Check for genus-version change
            # Note: Genus-Version Counter count code and format is universal
            # accross all genera and all versions of all genera. Therefore any
            # version counter should work for parsing stream genus version
            cold = sniff(ims)  # front of top level of this substream
            if cold != Colds.msg:  # counter found so peek at it
                ctr = yield from self._extractor(ims=ims,
                                                 klas=Counter,
                                                 cold=cold,
                                                 abort=framed,
                                                 strip=False)
                if ctr.code == self.codes.KERIACDCGenusVersion:
                    del ims[:ctr.byteSize(cold=cold)]  # consume ctr itself
                    # change version at top level this persists is not stacked
                    self.version = Counter.b64ToVer(ctr.countToB64(l=3))

            # check for BodyWithAttachmentGroup or non-native message or native message groups
            cold = sniff(ims)  # front of top level of this substream
            if cold != Colds.msg:  # counter found so peek at it
                ctr = yield from self._extractor(ims=ims,
                                         klas=Counter,
                                         cold=cold,
                                         abort=framed,
                                         strip=False)

                if ctr and ctr.code in (self.sucodes.BodyWithAttachmentGroup,
                                       self.sucodes.BigBodyWithAttachmentGroup):
                    del ims[:ctr.byteSize(cold=cold)]  # consume ctr itself
                    # compute enclosing group size based on txt or bny
                    emgs = ctr.byteCount(cold=cold)
                    while len(ims) < emgs and not framed:  # framed already in ims
                        yield

                    eims = ims[:emgs]  # copy out substream enclosed attachments
                    del ims[:emgs]  # strip off from ims
                    ims = eims  # replace since message group includes attachments
                    framed = True  # since includes attachments so pre-extracted

                    if piped:
                        pass  # pass extracted ims to pipeline processor
                        return

                    # peek for version
                    ctr = yield from self._extractor(ims=ims,
                                                     klas=Counter,
                                                     cold=cold,
                                                     abort=framed,
                                                     strip=False)
                    if ctr.code == self.codes.KERIACDCGenusVersion:
                        del ims[:ctr.byteSize(cold=cold)]  # consume ctr itself
                        # change version
                        verstack.append(self.version)  # push current onto stack
                        self.version = Counter.b64ToVer(ctr.countToB64(l=3))
                        # peek at next counter either native or non-native msg group
                        ctr = yield from self._extractor(ims=ims,
                                                        klas=Counter,
                                                        cold=cold,
                                                        abort=framed,
                                                        strip=False)

                # Check for message groups
                if (ctr.code in (self.mucodes.NonNativeBodyGroup,
                                 self.mucodes.BigNonNativeBodyGroup)):
                    del ims[:ctr.byteSize(cold=cold)]  # consume ctr itself
                    # process non-native message group with texter
                    texter = yield from self._extractor(ims=ims,
                                                        klas=Texter,
                                                        cold=cold,
                                                        abort=framed)
                    serder = serdery.reap(ims=texter.raw,
                                          genus=self.genus,
                                          svrsn=self.version)
                    exts['serder'] = serder

                elif (ctr.code in (self.mucodes.FixBodyGroup,
                                   self.mucodes.BigFixBodyGroup)): # native fixed field
                    cbs = ctr.byteSize(cold=cold)  # counter size of counter itself
                    fmgs = ctr.byteCount(cold=cold)  # fixed body content size
                    size = cbs + fmgs  # size of ctr and its content
                    while len(ims) < size and not framed:  # framed already in ims
                        yield  # until full ctr and its content in ims

                    fims = ims[:size]  # copy out ctr and its content
                    del ims[:size]  # strip off from ims

                    if cold == Colds.bny:  # tranform to text domain
                        fims = encodeB64(fims)  # always process event in qb64 text domain
                        size = (size * 4) // 3

                    # fims includes full body with counter but no attachments
                    serder = serdery.reap(ims=fims,
                                          genus=self.genus,
                                          svrsn=self.version,
                                          ctr=ctr,
                                          size=size,
                                          fixed=True)
                    exts['serder'] = serder

                elif (ctr.code in (self.mucodes.MapBodyGroup,
                                   self.mucodes.BigMapBodyGroup)):  # native field map
                    cbs = ctr.byteSize(cold=cold)  # counter size of counter itself
                    mmgs = ctr.byteCount(cold=cold)  # fixed body group size
                    size = cbs + mmgs
                    while len(ims) < size and not framed:  # framed already in ims
                        yield  # until full ctr and its content in ims

                    mims = ims[:size]  # copy out ctr and its content
                    del ims[:size]  # strip off from ims

                    if cold == Colds.bny:  # tranform to text domain
                        mims = encodeB64(mims)  # always process event in qb64 text domain
                        size = (size * 4) // 3

                    # mims includes ctr and its content but no attachments
                    serder = serdery.reap(ims=mims,
                                          genus=self.genus,
                                          svrsn=self.version,
                                          ctr=ctr,
                                          size=size,
                                          fixed=False)
                    exts['serder'] = serder

                elif (ctr.code in (self.sucodes.GenericGroup,
                                   self.sucodes.BigGenericGroup)):
                    # return control to groupParsator
                    raise kering.TopLevelStreamError(f"Got GenericGroup so revisit.")

                else:  # shouldn't be a counter of any other type here
                    raise kering.ColdStartError(f"Expected message counter code,"
                                                f" got code={ctr.code}")

            else:   # Otherwise its JSON, CBOR, or MGPK message at top level
                while True:  # extract, deserialize, and strip message from ims
                    try:
                        serder = serdery.reap(ims=ims,
                                              genus=self.genus,
                                              svrsn=self.version)
                    except kering.ShortageError as ex:  # need more bytes
                        if framed:  # pre-extracted
                            raise  # incomplete frame or group so abort by raising error
                        yield
                    else: # extracted and stripped successfully
                        exts['serder'] = serder
                        break  # break out of while loop

        except kering.ExtractionError as ex:
            if emgs is not None:  # extracted enclosed message group is preflushed
                raise kering.SizedGroupError(f"Error processing enclosing "
                                             f"message group of size={emgs}")
            raise  # no enclosing group so can't preflush, must flush stream


        # Extract and deserialize attachments
        enclosed = False  # True means all attachments enclosed in AttachmentGroup

        try:  # catch errors here to flush only counted part of stream
            # attachments must start with counter so know if txt or bny.
            # if no attachments MUST have at least empty AttachmentGroup
            while not ims and not framed:  # framed has everything already
                yield  # when not framed at least empty AttachmentGroup follows

            cold = sniff(ims)
            if cold != Colds.msg:  # counter so peek at what it is
                ctr = yield from self._extractor(ims=ims,
                                                 klas=Counter,
                                                 cold=cold,
                                                 abort=framed,
                                                 strip=False)
                if ctr.code in (self.codes.AttachmentGroup, self.codes.BigAttachmentGroup):
                    del ims[:ctr.byteSize(cold=cold)]  # consume ctr itself
                    # compute enclosing attachment group size based on txt or bny
                    eags = ctr.byteCount(cold=cold)
                    while len(ims) < eags and not framed:
                        yield
                    eims = ims[:eags]  # copy out substream enclosed attachments
                    del ims[:eags]  # strip off from ims consume contents from ims
                    ims = eims  # now just process substream as one counted frame
                    enclosed = True

                    if piped:
                        pass  # pass extracted ims to pipeline processor
                        return

                    # peek for version change
                    ctr = yield from self._extractor(ims=ims,
                                                     klas=Counter,
                                                     cold=cold,
                                                     abort=enclosed,
                                                     strip=False)
                    if ctr.code == self.codes.KERIACDCGenusVersion:
                        del ims[:ctr.byteSize(cold=cold)]  # consume ctr itself
                        # change version
                        verstack.append(self.version)  # push current onto stack
                        self.version = Counter.b64ToVer(ctr.countToB64(l=3))


                while True:  # iteratively process attachment counters in stride
                    ctr = yield from self._extractor(ims=ims,
                                                     klas=Counter,
                                                     cold=cold,
                                                     abort=framed or enclosed,
                                                     strip=False)

                    # check if group belongs to top level group message in stream
                    if (ctr.code in self.mucodes or ctr.code in self.sucodes or
                        ctr.code == self.codes.KERIACDCGenusVersion):
                        # do not consume leave in stream
                        break  # finished attachments not a valid attachement group

                    del ims[:ctr.byteSize(cold=cold)]  # consume ctr itself

                    try:
                        yield from getattr(self, self.methods[ctr.name])(exts=exts,
                            ims=ims, ctr=ctr, cold=cold, abort=(framed or enclosed))
                    except AttributeError as ex:
                        raise kering.UnexpectedCountCodeError(f"Unsupported count"
                                                f" code={ctr.code}") from ex
                    except Exception as ex:
                        raise  # easier debug with breakpoint here

                    if enclosed:  # attachments framed by enclosing AttachmentGroup
                        # inside of group all contents must be same cold  .txt
                        # or .bny so no need to sniff for new cold here.
                        if not ims:  # end of attachment group
                            break

                    else:  # assumes that if attachments are not enclosed that
                        # framed must be true, which means ims, message plus
                        # attachments all provided at once
                        # ims framed in some way, but not by enclosing AttachmentGroup
                        # not all attachments in one enclosing group, each individual
                        # attachment group may switch stream state txt or bny
                        if not ims:  # end of frame
                            break
                        cold = sniff(ims)
                        if cold == Colds.msg:  # new non-group message so attachments done
                            break  # finished attachments since new message

            #else:  # see next msg but with no attachments on current messge
                # so just proceed to process current message


        except kering.ExtractionError as ex:
            if enclosed:  # extracted enclosed attachment group is preflushed
                raise kering.SizedGroupError(f"Error processing attachment group"
                                             " of size={eags}")
            raise  # no enclosing attachment group so can't preflush, must flush stream

        finally:
            while verstack:  # restore version to what it was
                self.version = verstack.pop()

        if isinstance(serder, serdering.SerderKERI):
            ilk = serder.ilk  # dispatch abased on ilk

            if ilk in [Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt]:  # event msg
                firner, dater = exts['frcs'][-1] if exts['frcs'] else (None, None)  # use last one if more than one
                # when present assumes this is source seal of delegating event in delegator's KEL
                delseqner, delsaider = exts['sscs'][-1] if exts['sscs'] else (None, None)  # use last one if more than one
                if not exts['sigers']: # sigers:
                    msg = f"Missing attached signature(s) for evt = {serder.ked['d']}"
                    logger.info(msg)
                    logger.debug("Event Body = \n%s\n", serder.pretty())
                    raise kering.ValidationError(msg)
                try:
                    exts['firner'] = firner
                    exts['dater'] = dater
                    exts['delseqner'] = delseqner
                    exts['delsaider'] = delsaider

                    kvy.processEvent(**exts)

                    if exts['cigars']:  # cigars
                        kvy.processAttachedReceiptCouples(**exts)

                    if exts['trqs']:  # trqs
                        kvy.processAttachedReceiptQuadruples(**exts)

                except AttributeError as ex:
                    msg = f"No kevery to process so dropped msg={serder.said}"
                    logger.info(msg)
                    logger.debug("Event Body = \n%s\n", serder.pretty())
                    raise kering.ValidationError(msg) from ex

            elif ilk in [Ilks.rct]:  # event receipt msg (nontransferable)
                if not (exts['cigars'] or exts['wigers'] or exts['tsgs']):  # (cigars or wigers or tsgs)
                    msg = f"Missing attached signatures on receipt msg sn={serder.sn} SAID={serder.said}"
                    logger.info(msg)
                    logger.debug("Receipt body=\n%s\n", serder.pretty())
                    raise kering.ValidationError(msg)

                try:

                    kvy.processReceipt(**exts)

                except AttributeError as ex:
                    raise kering.ValidationError(f"No kevery to process so dropped msg"
                                                 f"= {serder.pretty()}.") from ex


            elif ilk in (Ilks.rpy,):  # reply message
                if not (exts['cigars'] or exts['tsgs']):  # (cigars or tsgs)
                    raise kering.ValidationError(f"Missing attached endorser signature(s) "
                                                 f"to reply msg = {serder.pretty()}.")

                try:
                    rvy.processReply(**exts)

                except AttributeError as ex:
                    raise kering.ValidationError(f"No revery to process so dropped msg"
                                                 f"= {serder.pretty()}.") from ex

            elif ilk in (Ilks.qry,):  # query message
                # ToDo neigher kvy.processQuery nor tvy.processQuery actually verify
                if exts['ssgs']:
                    # use last one if more than one
                    pre, sigers = exts['ssgs'][-1] if exts['ssgs'] else (None, None)
                    exts["source"] = pre
                    exts["sigers"] = sigers
                else:
                    exts['sigers'] = []  # just in case sigers provided not by ssgs

                if not (exts['source'] or exts['cigars']):  # need one or the other
                    raise kering.ValidationError(f"Missing attached requester "
                                                 f"source for query"
                                                 f" msg = {serder.pretty()}.")

                route = serder.ked["r"]
                if route in ["logs", "ksn", "mbx"]:
                    try:
                        kvy.processQuery(**exts)
                    except AttributeError as ex:
                        raise kering.ValidationError(f"No kevery to process so "
                                    f" dropped msg={serder.pretty()}") from ex
                    except kering.QueryNotFoundError as ex:  # catch escrow error and log it
                        if logger.isEnabledFor(logging.TRACE):
                            logger.exception("Error processing query = %s", ex)
                            logger.trace("Query Body=\n%s\n", serder.pretty())
                        else:
                            logger.error("Error processing query = %s", ex)

                elif route in ["tels", "tsn"]:
                    try:
                        tvy.processQuery(**exts)
                    except AttributeError as ex:
                        raise kering.ValidationError(f"No tevery to process so dropped msg"
                                                     f"={serder.pretty()}") from ex

                else:
                    raise kering.ValidationError(f"Invalid resource type {route}"
                                                 f"so dropped msg={serder.pretty()}.")

            elif ilk in (Ilks.exn,):
                if not (exts['cigars'] or exts['tsgs']):
                    raise kering.ValidationError(f"Missing attached exchanger "
                                        f"signatures for msg={serder.pretty()}")

                try:
                    exc.processEvent(**exts)

                except AttributeError as ex:
                    raise kering.ValidationError(f"No Exchange to process so "
                                    f"dropped msg={serder.pretty()}.") from ex

            elif ilk in (Ilks.vcp, Ilks.vrt, Ilks.iss, Ilks.rev, Ilks.bis, Ilks.brv):
                # TEL msg
                # get transaction event seal ref to Issuer's KEL
                # use last one if more than one
                seqner, saider = exts['sscs'][-1] if exts['sscs'] else (None, None)
                exts['seqner'] = seqner
                exts['saider'] = saider
                try:
                    tvy.processEvent(**exts)

                except AttributeError as ex:
                    raise kering.ValidationError(f"No tevery to process so dropped msg"
                                                 f"={serder.pretty()}.") from ex
            else:
                raise kering.ValidationError(f"Unexpected message {ilk=} for evt="
                                             f"{serder.pretty()}")

        elif isinstance(serder, serdering.SerderACDC):
            ilk = serder.ilk  # dispatch based on ilk

            if ilk is None:  # default for ACDC
                try:
                    # use last one if more than one
                    prefixer, seqner, saider = exts['ssts'][-1] if exts['ssts'] else (None, None, None)
                    exts['prefixer'] = prefixer
                    exts['seqner'] = seqner
                    exts['saider'] = saider
                    vry.processACDC(**exts)
                    #vry.processACDC(serder=serder, prefixer=prefixer, seqner=seqner, saider=saider)
                except AttributeError as ex:
                    raise kering.ValidationError(f"No verifier to process so "
                                        f"dropped ACDC={serder.pretty()}") from ex
            else:
                raise kering.ValidationError(f"Unexpected message ilk = {ilk} "
                                             f"for evt={serder.pretty()}")

        else:
            raise kering.ValidationError(f"Unexpected protocol type={serder.proto}"
                                         f" for event message={serder.pretty()}.")

        return True  # done state

    # Group parse/extract methods for dispatch based on CESR version
    def _ControllerIdxSigs1(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv1 ControllerIdxSigs group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.


        Returns:
            sigers (list[Siger]): of indexed signature instances

        """
        sigers = []
        for i in range(ctr.count):  # extract each attached signature
            siger = yield from self._extractor(ims=ims,
                                               klas=Siger,
                                               cold=cold,
                                               abort=abort)
            sigers.append(siger)
        try:
            exts['sigers'].extend(sigers)
        except KeyError:
            exts['sigers'] = sigers



    def _ControllerIdxSigs2(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv2 ControllerIdxSigs group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            sigers (list[Siger]): of indexed signature instances

        """
        gs = ctr.byteCount(cold=cold) # ctr.count * 4 if cold == Colds.txt else ctr.count * 3
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        sigers = []
        while gims:   # extract each attached signature and strip from gims
            sigers.append(self.extract(ims=gims, klas=Siger, cold=cold))
        try:
            exts['sigers'].extend(sigers)
        except KeyError:
            exts['sigers'] = sigers


    def _WitnessIdxSigs1(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv1 WitnessIdxSigs group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.


        Returns:
            wigers (list[Siger]): of indexed signature instances

        """
        wigers = []
        for i in range(ctr.count):  # extract each attached signature
            wiger = yield from self._extractor(ims=ims,
                                               klas=Siger,
                                               cold=cold,
                                               abort=abort)
            wigers.append(wiger)
        try:
            exts['wigers'].extend(wigers)
        except KeyError:
            exts['wigers'] = wigers


    def _WitnessIdxSigs2(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv2 WitnessIdxSigs group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            wigers (list[Siger]): of indexed signature instances

        """
        gs = ctr.byteCount(cold=cold)
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        wigers = []
        while gims:   # extract each attached signature and strip from gims
            wigers.append(self.extract(ims=gims, klas=Siger, cold=cold))
        try:
            exts['wigers'].extend(wigers)
        except KeyError:
            exts['wigers'] = wigers


    def _NonTransReceiptCouples1(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv1 NonTransReceiptCouples group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            cigars (list[Cigar]): of signature instances with assigned verfer

        """
        cigars = []
        for i in range(ctr.count):  # extract each attached couple
            verfer = yield from self._extractor(ims=ims,
                                               klas=Verfer,
                                               cold=cold,
                                               abort=abort)
            cigar = yield from self._extractor(ims=ims,
                                               klas=Cigar,
                                               cold=cold,
                                               abort=abort)

            cigar.verfer = verfer

            cigars.append(cigar)
        try:
            exts['cigars'].extend(cigars)
        except KeyError:
            exts['cigars'] = cigars


    def _NonTransReceiptCouples2(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv2 NonTransReceiptCouples group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            cigars (list[Cigar]): of signature instances with assigned verfer

        """
        gs = ctr.byteCount(cold=cold)
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        cigars = []
        while gims:   # extract each attached couple and strip from gims
            verfer = self.extract(ims=gims, klas=Verfer, cold=cold)
            cigar = self.extract(ims=gims, klas=Cigar, cold=cold)
            cigar.verfer = verfer
            cigars.append(cigar)
        try:
            exts['cigars'].extend(cigars)
        except KeyError:
            exts['cigars'] = cigars


    def _TransReceiptQuadruples1(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv1 TransReceiptQuadruples group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            trqs (list[tuple]): [(prefixer,seqner,saider,siger)]

        extract attaced trans receipt vrc quadruple
        spre+ssnu+sdig+sig
        spre is pre of signer of vrc
        ssnu is sn of signer's est evt when signed
        sdig is dig of signer's est event when signed
        sig is indexed signature of signer on this event msg

        """
        trqs = []
        for i in range(ctr.count):  # extract each attached quadruple
            prefixer = yield from self._extractor(ims=ims,
                                                  klas=Prefixer,
                                                  cold=cold,
                                                  abort=abort)
            seqner = yield from self._extractor(ims=ims,
                                                klas=Seqner,
                                                cold=cold,
                                                abort=abort)
            saider = yield from self._extractor(ims=ims,
                                                klas=Saider,
                                                cold=cold,
                                                abort=abort)
            siger = yield from self._extractor(ims=ims,
                                               klas=Siger,
                                               cold=cold,
                                               abort=abort)
            trqs.append((prefixer, seqner, saider, siger))
        try:
            exts['trqs'].extend(trqs)
        except KeyError:
            exts['trqs'] = trqs


    def _TransReceiptQuadruples2(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv2 TransReceiptQuadruples group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            trqs (list[tuple]): [(prefixer,seqner,saider,siger)]

        extract attaced trans receipt vrc quadruple
        spre+ssnu+sdig+sig
        spre is pre of signer of vrc
        ssnu is sn of signer's est evt when signed
        sdig is dig of signer's est event when signed
        sig is indexed signature of signer on this event msg

        """
        gs = ctr.byteCount(cold=cold)
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        trqs = []
        while gims:   # extract each attached quadruple and strip from gims
            prefixer = self.extract(ims=gims, klas=Prefixer, cold=cold)
            seqner = self.extract(ims=gims, klas=Seqner, cold=cold)
            saider = self.extract(ims=gims, klas=Saider, cold=cold)
            siger = self.extract(ims=gims, klas=Siger, cold=cold)
            trqs.append((prefixer, seqner, saider, siger))
        try:
            exts['trqs'].extend(trqs)
        except KeyError:
            exts['trqs'] = trqs


    def _TransIdxSigGroups1(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv1 TransIdxSigGroups group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
             tsgs (list[tuple]): [(prefixer,seqner,saider,[isigers])]

        """
        tsgs = []
        for i in range(ctr.count):  # extract each attached group
            prefixer = yield from self._extractor(ims=ims,
                                                  klas=Prefixer,
                                                  cold=cold,
                                                  abort=abort)
            seqner = yield from self._extractor(ims=ims,
                                                klas=Seqner,
                                                cold=cold,
                                                abort=abort)
            saider = yield from self._extractor(ims=ims,
                                                klas=Saider,
                                                cold=cold,
                                                abort=abort)
            ictr = yield from self._extractor(ims=ims,
                                              klas=Counter,
                                              cold=cold,
                                              abort=abort)
            if ictr.code != CtrDex_1_0.ControllerIdxSigs:
                raise kering.UnexpectedCountCodeError(f"Expected count code="
                            f"{CtrDex_1_0.ControllerIdxSigs}, got code={ictr.code}")
            isigers = []
            for i in range(ictr.count):  # extract each signature in idx cnt
                isiger = yield from self._extractor(ims=ims,
                                               klas=Siger,
                                               cold=cold,
                                               abort=abort)
                isigers.append(isiger)
            tsgs.append((prefixer, seqner, saider, isigers))
        try:
            exts['tsgs'].extend(tsgs)
        except KeyError:
            exts['tsgs'] = tsgs


    def _TransIdxSigGroups2(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv2 TransIdxSigGroups group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            tsgs (list[tuple]): [(prefixer,seqner,saider,[isigers])]

        """
        gs = ctr.byteCount(cold=cold)
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        tsgs = []
        isigers = []
        while gims:   # extract each attached group and strip from gims
            prefixer = self.extract(ims=gims, klas=Prefixer, cold=cold)
            seqner = self.extract(ims=gims, klas=Seqner, cold=cold)
            saider = self.extract(ims=gims, klas=Saider, cold=cold)
            ictr = self.extract(ims=gims, klas=Counter, cold=cold)
            if ictr.code != CtrDex_2_0.ControllerIdxSigs:
                raise kering.UnexpectedCountCodeError(f"Expected count code="
                            f"{CtrDex_2_0.ControllerIdxSigs}, got code={ictr.code}")
            igs = ictr.byteCount(cold=cold)
            # already extracted enclosing group bytes so igs must be < len(gims)
            if len(gims) < igs:  # should not happen unless malformed counter
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            igims = gims[:igs]
            del gims[:igs]  # strip igims from gims
            isigers = []
            while igims:
                isiger = self.extract(ims=igims, klas=Siger, cold=cold)
                isigers.append(isiger)
            tsgs.append((prefixer, seqner, saider, isigers))  # tuple
        try:
            exts['tsgs'].extend(tsgs)
        except KeyError:
            exts['tsgs'] = tsgs


    def _TransLastIdxSigGroups1(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv1 TransLastIdxSigGroups group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            ssgs (list[tuple]): [(prefixer, [isigers])]

        """
        ssgs = []
        for i in range(ctr.count):  # extract each attached group
            prefixer = yield from self._extractor(ims=ims,
                                                  klas=Prefixer,
                                                  cold=cold,
                                                  abort=abort)
            ictr = yield from self._extractor(ims=ims,
                                              klas=Counter,
                                              cold=cold,
                                              abort=abort)
            if ictr.code != CtrDex_1_0.ControllerIdxSigs:
                raise kering.UnexpectedCountCodeError(f"Expected count code="
                            f"{CtrDex_1_0.ControllerIdxSigs}, got code={ictr.code}")
            isigers = []
            for i in range(ictr.count):  # extract each signature in idx cnt
                isiger = yield from self._extractor(ims=ims,
                                               klas=Siger,
                                               cold=cold,
                                               abort=abort)
                isigers.append(isiger)
            ssgs.append((prefixer, isigers))
        try:
            exts['ssgs'].extend(ssgs)
        except KeyError:
            exts['ssgs'] = ssgs


    def _TransLastIdxSigGroups2(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv2 TransLastIdxSigGroups group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            ssgs (list[tuple]): [(prefixer, [isigers])]

        """
        gs = ctr.byteCount(cold=cold)
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        ssgs = []
        isigers = []
        while gims:   # extract each attached group strip from gims
            prefixer = self.extract(ims=gims, klas=Prefixer, cold=cold)
            ictr = self.extract(ims=gims, klas=Counter, cold=cold)
            if ictr.code != CtrDex_2_0.ControllerIdxSigs:
                raise kering.UnexpectedCountCodeError(f"Expected count code="
                            f"{CtrDex_2_0.ControllerIdxSigs}, got code={ictr.code}")
            igs = ictr.byteCount(cold=cold)
            # already extracted enclosing group bytes so igs must be < len(gims)
            if len(gims) < igs:  # should not happen unless malformed counter
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            igims = gims[:igs]
            del gims[:igs]  # strip igims from gims
            isigers = []
            while igims:
                isiger = self.extract(ims=igims, klas=Siger, cold=cold)
                isigers.append(isiger)
            ssgs.append((prefixer, isigers))  # tuple
        try:
            exts['ssgs'].extend(ssgs)
        except KeyError:
            exts['ssgs'] = ssgs


    def _FirstSeenReplayCouples1(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv1 FirstSeenReplayCouples group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            frcs (list[tuple]): [(firner, dater)]
        """
        frcs = []
        for i in range(ctr.count):  # extract each attached group
            firner = yield from self._extractor(ims=ims,
                                                klas=Seqner,
                                                cold=cold,
                                                abort=abort)
            dater = yield from self._extractor(ims=ims,
                                                klas=Dater,
                                                cold=cold,
                                                abort=abort)
            frcs.append((firner, dater))
        try:
            exts['frcs'].extend(frcs)
        except KeyError:
            exts['frcs'] = frcs


    def _FirstSeenReplayCouples2(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv2 FirstSeenReplayCouples group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            frcs (list[tuple]): [(firner, dater)]

        """
        gs = ctr.byteCount(cold=cold)
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        frcs = []
        while gims:   # extract each attached group and strip from gims
            firner = self.extract(ims=gims, klas=Seqner, cold=cold)
            dater = self.extract(ims=gims, klas=Dater, cold=cold)
            frcs.append((firner, dater))
        try:
            exts['frcs'].extend(frcs)
        except KeyError:
            exts['frcs'] = frcs


    def _SealSourceCouples1(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv1 SealSourceCouples group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            sscs (list[tuple]): [(seqner, saider)]
        """
        sscs = []
        for i in range(ctr.count):  # extract each attached group
            seqner = yield from self._extractor(ims=ims,
                                                klas=Seqner,
                                                cold=cold,
                                                abort=abort)
            saider = yield from self._extractor(ims=ims,
                                                klas=Saider,
                                                cold=cold,
                                                abort=abort)
            sscs.append((seqner, saider))
        try:
            exts['sscs'].extend(sscs)
        except KeyError:
            exts['sscs'] = sscs


    def _SealSourceCouples2(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv2 SealSourceCouples group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            sscs (list[tuple]): [(seqner, saider)]

        """
        gs = ctr.byteCount(cold=cold)
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        sscs = []
        while gims:   # extract each attached group and strip from gims
            seqner = self.extract(ims=gims, klas=Seqner, cold=cold)
            saider = self.extract(ims=gims, klas=Saider, cold=cold)
            sscs.append((seqner, saider))
        try:
            exts['sscs'].extend(sscs)
        except KeyError:
            exts['sscs'] = sscs


    def _SealSourceTriples1(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv1 SealSourceTriples group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            ssts (list[tuple]): [(prefixer, seqner, saider)]
        """
        ssts = []
        for i in range(ctr.count):  # extract each attached group
            prefixer = yield from self._extractor(ims=ims,
                                                  klas=Prefixer,
                                                  cold=cold,
                                                  abort=abort)
            seqner = yield from self._extractor(ims=ims,
                                                klas=Seqner,
                                                cold=cold,
                                                abort=abort)
            saider = yield from self._extractor(ims=ims,
                                                klas=Saider,
                                                cold=cold,
                                                abort=abort)
            ssts.append((prefixer, seqner, saider))
        try:
            exts['ssts'].extend(ssts)
        except KeyError:
            exts['ssts'] = ssts


    def _SealSourceTriples2(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv2 SealSourceTriples group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            ssts (list[tuple]): [(prefixer, seqner, saider)]

        """
        gs = ctr.byteCount(cold=cold)
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        ssts = []
        while gims:   # extract each attached group and strip from gims
            prefixer = self.extract(ims=gims, klas=Prefixer, cold=cold)
            seqner = self.extract(ims=gims, klas=Seqner, cold=cold)
            saider = self.extract(ims=gims, klas=Saider, cold=cold)
            ssts.append((prefixer, seqner, saider))
        try:
            exts['ssts'].extend(ssts)
        except KeyError:
            exts['ssts'] = ssts


    def _PathedMaterialGroup(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESR v1 and v2 PathedMaterialGroup group both
        big and small sized groups. Since v1 counts quadlets/triples the logic is
        the same for both v1 and v2. The contexts of a pathed material group
        MUST be a CESR attachment sub-stream i.e. primitives or groups of primitives.
        It may not include any top-level messages expecially not any messages
        as JSON, CBOR, MGPK

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            pims (list[bytes]): [gims]

        """
        gs = ctr.byteCount(cold=cold)
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        try:
            exts['ptds'].extend([gims])
        except KeyError:
            exts['ptds'] = [gims]


    def _ESSRPayloadGroup1(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv1 ESSRPayloadGroup group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            essrs (list[Texter]): [texter]
        """
        essrs = []
        for i in range(ctr.count):  # extract each attached group
            texter = yield from self._extractor(ims=ims,
                                                klas=Texter,
                                                cold=cold,
                                                abort=abort)
            essrs.append(texter)
        try:
            exts['essrs'].extend(essrs)
        except KeyError:
            exts['essrs'] = essrs


    def _ESSRPayloadGroup2(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv2 ESSRPayloadGroup group

        Parameters:
            exts (dict): of extracted group elements for keyword args.
            ims (bytearray): of serialized incoming message stream.
            ctr (Counter): instance of CESR v1 Counter of code .ControllerIdxSigs
            cold (Coldage): assumes str value is either Colds.txt or Colds.bny
            abort (bool): True means abort if not enough bytes in ims. Use when
                            this group is enclosed in another group that has
                            already been extracted from stream
                          False yield if not enough bytes in ims. Use when this
                            group is at top level of stream not enclosed in
                            another already extracted group.

        Returns:
            essrs (list[Texter]): [texter]

        """
        gs = ctr.byteCount(cold=cold)
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        essrs = []
        while gims:   # extract each attached group and strip from gims
            texter = self.extract(ims=gims, klas=Texter, cold=cold)
            essrs.append(texter)
        try:
            exts['essrs'].extend(essrs)
        except KeyError:
            exts['essrs'] = essrs

