# -*- encoding: utf-8 -*-
"""
keri.core.parsing module

message stream parsing support
"""
import copy
import logging
from dataclasses import dataclass, field, astuple, asdict
from collections import deque, namedtuple
from base64 import urlsafe_b64encode as encodeB64

from hio.help import ogler

from ..kering import (Colds, sniff, Vrsn_2_0, Ilks,
                      UnexpectedCountCodeError, MaterialError, ValidationError,
                      QueryNotFoundError, ExtractionError, ShortageError,
                      ColdStartError, InvalidVersionError,
                      SizedGroupError, TopLevelStreamError)

from .coring import (Seqner, Cigar, Diger, Noncer, Labeler, Number, Verser,
                     Dater, Verfer, Prefixer, Saider, Texter)
from .indexing import Siger
from .counting import Counter, Codens, CtrDex_1_0, CtrDex_2_0, GenDex
from .serdering import Serdery, Serder, SerderKERI, SerderACDC
from .structing import (SealSource, SealEvent, SealKind, BlindState, BoundState,
                        TypeMedia, FirstSeen, TransReceipts, TransSigs,
                        TransLastSigs)

logger = ogler.getLogger()


# ToDo  ptds pathed material couples currently just returns bytes as CESR substream
# of primitives with leading primitive the path as pather.qb64 or .qb2.
# should change this to a tuple where the first element is the pather, and the
# second element is a list of primitives not the substream



@dataclass()
class MsgParseDom:
    """Fields extracted when parsing a message substream where substream is
    a message plus attachments. The attachments include a nests field which is
    a list of nested (embedded) message substreams.

    asdict(MsgParseDom) creates dict suitable for **keyword expansion to pass
    as parameters to message processing
    """
    serder: Serder = None  # message instance SerderKERI or SerderACDC
    sigers: list[Siger] = field(default_factory=list)  # ControllerIdxSigs
    wigers: list[Siger] = field(default_factory=list)  # WitnessIdxSigs
    cigars: list[Cigar] = field(default_factory=list)  # NonTransReceiptCouples cigar with verfer from (pre+sig)
    rsgs:   list[TransReceipts] = field(default_factory=list)  # TransReceiptIdxSigGroups (prefixer, number, diger, [sigers])
    tsgs:   list[TransSigs] = field(default_factory=list)  # TransIdxSigGroups (prefixer, number, diger, [sigers])
    lsgs:   list[TransLastSigs] = field(default_factory=list)  # TransLastIdxSigGroups (prefixer,[sigers]) (was tsgs)
    frcs:   list[FirstSeen] = field(default_factory=list)  # FirstSeenReplayCouples (number, dater)
    sscs:   list[SealSource] = field(default_factory=list)  # SealSourceCouples (number, diger) sealing or sealed event
    ssts:   list[SealEvent] = field(default_factory=list)  # SealSourceTriples (prefixer, number, diger) sealing or sealed event
    tdcs:   list[SealKind] = field(default_factory=list)  # TypedDigestSealCouples SealKind (verser, diger)
    bsqs:   list[BlindState] = field(default_factory=list)  # BlindedStateQuadruples BlindState (diger, noncer, noncer, labeler)
    bsss:   list[BoundState] = field(default_factory=list)  # BoundStateSextuples BoundState (diger, noncer, noncer, labeler, number, noncer)
    tmqs:   list[TypeMedia] = field(default_factory=list)  # TypedMediaQuadruples TypeMedia (diger, noncer, labeler, texter)
    essrs:  list[Texter] = field(default_factory=list)  # ESSR encapsulations as Texters
    ptds:   list[bytes] = field(default_factory=list)  # PathedMaterialCouples (path, text) -> concat path+text
    nests:  list[dict] = field(default_factory=list)  # asdict(MsgParseDOM) instance dicts recursively nested
    local:  bool = True  # local source controller context for processing

    def __iter__(self):
        return iter(asdict(self))



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
                whenever stream includes pipelineable group count codes.
        kvy (Kevery): route KEL message types to this instance
        tvy (Tevery): route TEL message types to this instance
        exc (Exchanger): route EXN message types to this instance
        rvy (Revery): reply (RPY) message handler
        vry (``Verfifier``): credential verifier with wallet storage
        local (bool): True means event source is local (protected) for validation
                         False means event source is remote (unprotected) for validation

    Properties:
        genus (str): genus portion of default CESR code table protocol genus code
        version (Versionage): current CESR protocol genus version in context
        methods (dict): method names for counter extraction, keyed by count code name
        codes (CtrDex): selected by .version from (CtrDex_1_0, CtrDex_2_0)
        sucodes (SUDex): selected by .version from  (SUDex_1_0, SUDex_2_0)
        mucodes (MUDex): selected by .version from  (MUDex_1_0, MUDex_2_0)
        bucodes (BUDex): selected by .version from  (BUDex_1_0, BUDex_2_0)


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
    BUCodes = Counter.BUCodes # message universal code tables from Counter
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

    Methods[1][0][Codens.TransReceiptIdxSigGroups] = "_TransReceiptIdxSigGroups1"
    Methods[2][0][Codens.TransReceiptIdxSigGroups] = "_TransReceiptIdxSigGroups2"
    Methods[2][0][Codens.BigTransReceiptIdxSigGroups] = "_TransReceiptIdxSigGroups2"

    Methods[1][0][Codens.TransIdxSigGroups] = "_TransIdxSigGroups1"
    Methods[2][0][Codens.TransIdxSigGroups] = "_TransIdxSigGroups2"
    Methods[2][0][Codens.BigTransIdxSigGroups] = "_TransIdxSigGroups2"

    Methods[1][0][Codens.TransLastIdxSigGroups] = "_TransLastIdxSigGroups1"
    Methods[2][0][Codens.TransLastIdxSigGroups] = "_TransLastIdxSigGroups2"
    Methods[2][0][Codens.BigTransLastIdxSigGroups] = "_TransLastIdxSigGroups2"

    Methods[1][0][Codens.FirstSeenReplayCouples] = "_FirstSeenReplayCouples1"
    Methods[2][0][Codens.FirstSeenReplayCouples] = "_FirstSeenReplayCouples2"
    Methods[2][0][Codens.BigFirstSeenReplayCouples] = "_FirstSeenReplayCouples2"

    Methods[1][0][Codens.SealSourceTriples] = "_SealSourceTriples1"
    Methods[2][0][Codens.SealSourceTriples] = "_SealSourceTriples2"
    Methods[2][0][Codens.BigSealSourceTriples] = "_SealSourceTriples2"

    Methods[1][0][Codens.SealSourceCouples] = "_SealSourceCouples1"
    Methods[2][0][Codens.SealSourceCouples] = "_SealSourceCouples2"
    Methods[2][0][Codens.BigSealSourceCouples] = "_SealSourceCouples2"

    Methods[2][0][Codens.TypedDigestSealCouples] = "_TypedDigestSealCouples"
    Methods[2][0][Codens.BigTypedDigestSealCouples] = "_TypedDigestSealCouples"

    Methods[2][0][Codens.BlindedStateQuadruples] = "_BlindedStateQuadruples"
    Methods[2][0][Codens.BigBlindedStateQuadruples] = "_BlindedStateQuadruples"

    Methods[2][0][Codens.BoundStateSextuples] = "_BoundStateSextuples"
    Methods[2][0][Codens.BigBoundStateSextuples] = "_BoundStateSextuples"

    Methods[2][0][Codens.TypedMediaQuadruples] = "_TypedMediaQuadruples"
    Methods[2][0][Codens.BigTypedMediaQuadruples] = "_TypedMediaQuadruples"

    Methods[1][0][Codens.PathedMaterialCouples] = "_PathedMaterialCouples"
    Methods[1][0][Codens.BigPathedMaterialCouples] = "_PathedMaterialCouples"
    Methods[2][0][Codens.PathedMaterialCouples] = "_PathedMaterialCouples"
    Methods[2][0][Codens.BigPathedMaterialCouples] = "_PathedMaterialCouples"

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
            vry (``Verfifier``): credential verifier with wallet storage
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
                raise InvalidVersionError(f"Unsupported major version="
                                                 f"{version.major}.")

            latest = list(self.Methods[version.major])[-1]  # get latest supported minor version
            if version.minor > latest:
                raise InvalidVersionError(f"Minor version={version.minor} "
                                                 f" exceeds latest supported minor"
                                                 f" version={latest}.")
            self._version = version
            self._methods = self.Methods[version.major][latest]
            self._codes = self.Codes[version.major][latest]
            self._sucodes = self.SUCodes[version.major][latest]
            self._mucodes = self.MUCodes[version.major][latest]
            self._bucodes = self.BUCodes[version.major][latest]


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


    @property
    def bucodes(self):
        """Makes .bucodes read only
        Returns:
            _bucodes (BUDex): selected by .version from (BUDex_1_0, BUDex_2_0)
        """
        return self._bucodes


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
              exc=None, rvy=None, vry=None, local=None, version=None,
              processive=True):
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
                ims msgs when stream incpyludes pipelineable count codes.
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
            processive (bool): True means process messages as they are parsed
                               False means do not process parse only, useful for
                                   testing and debugging

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
                                    version=version,
                                    processive=processive)

        while True:
            try:
                next(parsator)
            except StopIteration as ex:
                result = ex.value
                break

        return result


    def parseOne(self, ims=None, framed=True, piped=False, kvy=None, tvy=None,
                 exc=None, rvy=None, vry=None, local=None, version=None,
                 processive=True):
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
                ims msgs when stream includes pipelineable count codes.
            kvy (Kevery): route KERI KEL message types to this instance
            tvy (Tevery): route TEL message types to this instance
            exc (Exchanger) route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            local (bool): True means event source is local (protected) for validation
                          False means event source is remote (unprotected) for validation
                          None means use default .local
            version (Versionage): default genera version of CESR to use
                                  None means do not change default
            processive (bool): True means process messages as they are parsed
                               False means do not process parse only, useful for
                                   testing and debugging


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
                                     version=version,
                                     processive=processive)
        while True:
            try:
                next(parsator)
            except StopIteration as ex:
                result = ex.value
                break

        return result


    def allParsator(self, ims=None, framed=None, piped=None, kvy=None,
                    tvy=None, exc=None, rvy=None, vry=None, local=None,
                    version=None, processive=True):
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
                ims msgs when stream includes pipelineable count codes.
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
            processive (bool): True means process messages as they are parsed
                               False means do not process parse only, useful for
                                   testing and debugging


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

        result = None
        while ims:  # only process until ims empty (differs here from parsator)
            try:
                result = yield from self.groupParsator(ims=ims,
                                                        framed=framed,
                                                        piped=piped,
                                                        kvy=kvy,
                                                        tvy=tvy,
                                                        exc=exc,
                                                        rvy=rvy,
                                                        vry=vry,
                                                        local=local,
                                                        version=version,
                                                        processive=processive)

            except SizedGroupError as ex:  # error inside sized group
                # processOneIter already flushed group so do not flush stream
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser sized group error: %s", ex)
                else:
                    logger.error("Parser sized group error: %s", ex)

            except (ColdStartError, ExtractionError) as ex:  # some extraction error
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser msg extraction error: %s", ex)
                else:
                    logger.error("Parser msg extraction error: %s", ex)
                del ims[:]  # delete rest of stream to force cold restart

            except (ValidationError, Exception) as ex:  # non Extraction Error
                # Non extraction errors happen after successfully extracted from stream
                # so we don't flush rest of stream just resume
                if logger.isEnabledFor(logging.TRACE):
                    logger.exception("Parser msg non-extraction error: %s", ex)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.error("Parser msg non-extraction error: %s", ex)
            yield

        return result  # debug parsing when not processive


    def onceParsator(self, ims=None, framed=None, piped=None, kvy=None,
                     tvy=None, exc=None, rvy=None, vry=None, local=None,
                     version=None, processive=True):
        """Returns generator to parse one message from incoming message stream, ims.
        If ims not provided parse messages from .ims

        Parameters:
            ims (bytearray): incoming message stream. May contain one or more
                sets each of a serialized message with attached cryptographic
                material such as signatures or receipts.
            framed (bool): True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages
            piped (bool): True means use pipeline processor to process
                ims msgs when stream includes pipelineable count codes.
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
            processive (bool): True means process messages as they are parsed
                               False means do not process parse only, useful for
                                   testing and debugging


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

        result = None
        while True:
            try:
                exts = yield from self.msgParsator(ims=ims,
                                                      framed=framed,
                                                      piped=piped,
                                                      local=local,
                                                      version=version)

            except SizedGroupError as ex:  # error inside sized group
                # processOneIter already flushed group so do not flush stream
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery sized group error: %s", ex)
                else:
                    logger.error("Kevery sized group error: %s", ex)

            except (ColdStartError, ExtractionError, Exception) as ex:  # some extraction error
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery msg extraction error: %s", ex)
                else:
                    logger.error("Kevery msg extraction error: %s", ex)
                del ims[:]  # delete rest of stream to force cold restart

            if processive:
                try:
                    result = self.msgProcess(exts=asdict(exts),
                                            kvy=kvy,
                                            tvy=tvy,
                                            exc=exc,
                                            rvy=rvy,
                                            vry=vry)

                except (ValidationError, Exception) as ex:  # non Extraction Error
                    # Non extraction errors happen after successfully extracted from stream
                    # so we don't flush rest of stream just resume
                    if logger.isEnabledFor(logging.TRACE):
                        logger.exception("Kevery msg non-extraction error: %s", ex)
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.error("Kevery msg non-extraction error: %s", ex)
                finally:
                    result = True
                    break
            else:
                result = exts
                break

        return result


    def parsator(self, ims=None, framed=None, piped=None, kvy=None, tvy=None,
                 exc=None, rvy=None, vry=None, local=None, version=None,
                 processive=True):
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
                ims msgs when stream includes pipelineable count codes.
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
            processive (bool): True means process messages as they are parsed
                               False means do not process parse only, useful for
                                   testing and debugging


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

        result = None
        while True:  # continuous stream processing (differs here from allParsator)
            try:
                result = yield from self.groupParsator(ims=ims,
                                                   framed=framed,
                                                   piped=piped,
                                                   kvy=kvy,
                                                   tvy=tvy,
                                                   exc=exc,
                                                   rvy=rvy,
                                                   vry=vry,
                                                   local=local,
                                                   version=version,
                                                   processive=processive)


            except SizedGroupError as ex:  # error inside sized group
                # processOneIter already flushed group so do not flush stream
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser sized group error: %s", ex)
                else:
                    logger.error("Parser sized group error: %s", ex)

            except (ColdStartError, ExtractionError) as ex:  # some extraction error
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser msg extraction error: %s", ex)
                else:
                    logger.error("Parser msg extraction error: %s", ex)
                del ims[:]  # delete rest of stream to force cold restart

            except (ValidationError, Exception) as ex:  # non Extraction Error
                # Non extraction errors happen after successfully extracted from stream
                # so we don't flush rest of stream just resume
                if logger.isEnabledFor(logging.TRACE):
                    logger.exception("Parser msg non-extraction error: %s", ex)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.error("Parser msg non-extraction error: %s", ex)
            yield

        return result  # should never return


    def groupParsator(self, ims=None, framed=True, piped=False, kvy=None,
                    tvy=None, exc=None, rvy=None, vry=None, local=None,
                    version=None, processive=True):
        """Returns generator to parse nested GenericGroups whose outermost nesting
        appears at the top-level of an incoming message stream.

        If ims not provided then parse messages from .ims

        Parameters:
            ims (bytearray): of incoming message stream. May contain one or more
                sets each of a serialized message with attached cryptographic
                material such as signatures or receipts.
            framed (bool): True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages
            piped (bool): True means use pipeline processor to process
                ims msgs when stream includes pipelineable count codes.
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
            processive (bool): True means process messages as they are parsed
                               False means do not process parse only, useful for
                                   testing and debugging


        """
        if ims is None:
            ims = self.ims

        local = local if local is not None else self.local
        local = True if local else False

        self.version = version  # when not None which sets .methods .codes .mucodes .sucodes

        stack = deque()  # (svrsn, ims) stack of nested substreams framed by generic groups
        svrsn = None
        eggs = None  # used in preflused error
        result = None
        results = []
        try:
            while True:  # process stream until done
                while not ims and stack:  # happens when ascending (un-nesting)
                    svrsn, ims = stack.pop()  # un-nest
                    self.version = svrsn  # only changes if svrsn is not None

                if not ims:  # no stream
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

                # extract substream at current nesting level
                try:
                    exts = yield from self.msgParsator(ims=ims,
                                                          framed=framed,
                                                          piped=piped,
                                                          local=local,
                                                          version=self.version)

                except TopLevelStreamError as ex:  # encountered GenericGroup
                    # before getting a message so need to nest down into new
                    # generic group which has been not extracted yet
                    # this is the normal way to handle it, so do not log
                    continue  # control thrown here to parse new generic group

                except (ExtractionError, Exception) as ex:  # error while extracting
                    raise ExtractionError from ex

                # process successful extraction at current nexting level)
                if processive:
                    try:
                        result = self.msgProcess(exts=asdict(exts),
                                                kvy=kvy,
                                                tvy=tvy,
                                                exc=exc,
                                                rvy=rvy,
                                                vry=vry)

                    except (ValidationError, Exception) as ex:  # post Extraction Error
                        # Validation errors happen in msgProcess which is called
                        # after a message+attachments has been successfully extracted
                        # from stream so we drop extraction without flushing rest
                        # of stream but resume extracting next message.
                        if logger.isEnabledFor(logging.TRACE):
                            logger.exception("GroupParsator error post extraction of"
                                             "msg+atc : %s", ex)
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.error("GroupParsator error post extraction of "
                                         "msg+atc : %s", ex)

                        continue
                else:
                    results.append(exts)


        except ExtractionError as ex:  # maybe this needs to be more granular
            if logger.isEnabledFor(logging.TRACE):
                logger.exception("GroupParsator error during extraction"
                                             " of msg+atc : %s", ex)
            if logger.isEnabledFor(logging.DEBUG):
                logger.error("GroupParsator error during extraction of "
                                         "msg+atc : %s", ex)
            if eggs is not None:  # extracted enclosed message group is preflushed
                raise SizedGroupError(f"Error processing generic group"
                                                 f" of size={eggs}")
            raise  # no enclosing message group so can't preflush, must flush stream

        finally:  # restore version at top level
            while stack:  # when tail end of group has validation error
                svrsn, _ = stack.pop()
                if svrsn:
                    self.version = svrsn
        return result if processive else results


    def msgParsator(self, ims=None, framed=True, piped=False, local=None,
                       version=None):
        """Returns generator that upon each iteration extracts and parses msg
        with attached crypto material (signature etc) from incoming message
        stream, ims. Upon completion returns extracted parsed msg substream as
        dictionary where substream is msg plus attachments which attachments
        may include nested (embedded) msg substreams. Use `yield from`` to call.
        This enables msgParsator to `yield` while waiting for input from ims when
        not framed and then eventually the `yield from` completes by returning
        dict of parsed msg substream

        Uses .ims when ims is not provided.

        Iterator yields when not enough bytes in ims to finish one msg plus
        attachments. Returns (which raises StopIteration) when finished.

        Returns::
            exts (dict): parsed msg+attachments substream. Result is suitable
                           for ** expansion as keywords to subsequent processing
                           of the msg substream. The dict is the asdict() of
                           MsgParseDom dataclass
                serder (Serder): message instance SerderKERI or SerderACDC
                sigers (list[Siger]): ControllerIdxSigs
                wigers (list[Siger]): WitnessIdxSigs
                cigars (list[Cigar]): NonTransReceiptCouples cigar with verfer from (pre+sig)
                rsgs   (list[TransReceipts]): TransReceiptIdxSigGroups (prefixer, number, diger, [sigers])
                tsgs   (list[TransSigs]):TransIdxSigGroups (prefixer, number, diger, [sigers])
                lsgs   (list[TransLastSigs]): TransLastIdxSigGroups (prefixer,[sigers]) (was tsgs)
                frcs   (list[FirstSeen]): FirstSeenReplayCouples (number, dater)
                sscs   (list[SealSource]): SealSourceCouples (number, diger) sealing or sealed event
                ssts   (list[SealEvent]): SealSourceTriples (prefixer, number, diger) sealing or sealed event
                tdcs   (list[SealKind]): TypedDigestSealCouples SealKind (verser, diger)
                bsqs   (list[BlindState]): BlindedStateQuadruples BlindState (diger, noncer, noncer, labeler)
                bsss   (list[BoundState]): BoundStateSextuples BoundState (diger, noncer, noncer, labeler, number, noncer)
                tmqs   (list[TypeMedia]): TypedMediaQuadruples TypeMedia (diger, noncer, labeler, texter)
                essrs  (list[Texter]): ESSR encapsulations as Texters
                ptds   (list[bytes]): PathedMaterialCouples (path, text) -> concat path+text
                nests  (list[dict]): asdict(MsgParseDOM) instance dicts recursively nested
                local  (bool): True means treat as local source controller context for processing
                               False means treat as remote controller context for processing



        Parameters::
            ims (bytearray): serialized incoming message stream.
                May contain one or more sets each of a serialized message with
                attached cryptographic material such as signatures or receipts.
            framed (bool): True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages
            piped (bool): True means use pipeline processor to process
                ims msgs when stream includes pipelineable count codes.
            local (bool): True means event source is local (protected) for validation
                          False means event source is remote (unprotected) for validation
                          None means use default .local
            version (``Versionage``): default version of CESR to use.
                                  None means do not change default

        Logic::
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

        self.version = version  # sets .codes .mucodes. .sucodes when not None otherwise does nothing
        verstack = deque()  # version stack append and pop
        exts = MsgParseDom() # asdict(MsgParseDom())
        exts.local = local

        serdery = Serdery(version=self.version)


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

            enclosed = False  # True means all attachments enclosed in
                               # BodyPlusAttachmentGroup or AttachmentGroup

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
                    enclosed = True  # attachments enclosed in group

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
                    exts.serder = serder

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
                    exts.serder = serder

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
                    exts.serder = serder

                elif (ctr.code in (self.sucodes.GenericGroup,
                                   self.sucodes.BigGenericGroup)):
                    # throw back control to groupParsator to nest into new generic group
                    raise TopLevelStreamError(f"Got GenericGroup so revisit.")

                else:  # shouldn't be a counter of any other type here
                    raise ColdStartError(f"Expected message counter code,"
                                                f" got code={ctr.code}")

            else:   # Otherwise its JSON, CBOR, or MGPK message at top level
                while True:  # extract, deserialize, and strip message from ims
                    try:
                        serder = serdery.reap(ims=ims,
                                              genus=self.genus,
                                              svrsn=self.version)
                    except ShortageError as ex:  # need more bytes
                        if framed:  # pre-extracted
                            raise  # incomplete frame or group so abort by raising error
                        yield
                    else: # extracted and stripped successfully
                        exts.serder = serder
                        break  # break out of while loop

        except ExtractionError as ex:
            if emgs is not None:  # extracted enclosed message group is preflushed
                raise SizedGroupError(f"Error processing enclosing "
                                             f"message group of size={emgs}")
            raise  # no enclosing group so can't preflush, must flush stream


        # Extract and deserialize attachments
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
                                                     strip=False)  # peek at ctr

                    ## check if group belongs to top level group message in stream
                    #if (ctr.code in self.mucodes or ctr.code in self.sucodes or
                        #ctr.code == self.codes.KERIACDCGenusVersion):
                        ## do not consume because it belongs with new msg
                        #break  # not a valid attachment so done with attachments to this msg


                    # check if group belongs to top level genus code or group or
                    # tunneled message in stream

                    if ((ctr.code == self.codes.KERIACDCGenusVersion) or
                            (ctr.code in (self.sucodes.GenericGroup,
                                      self.sucodes.BigGenericGroup) or
                            (ctr.code in self.mucodes and
                             ctr.code not in self.bucodes))):

                        if enclosed: # invalid codes inside of attachment enclosure
                            raise SizedGroupError(f"Unexpected group code={ctr.code}"
                                                  f" in enclosed attachment")

                        # do not consume ctr because it starts a new top level
                        # stream, group or tunnel
                        break  # done with attachments to this msg


                    # Check for nested msg substreams, misplace code, or regular attachments
                    if (ctr.code in (self.sucodes.AttachmentGroup,
                                     self.sucodes.BigAttachmentGroup)):
                        # nested attachment group which is invalid here
                        # so flush group contents from stream
                        cbs = ctr.byteSize(cold=cold)  # counter size of counter itself
                        fmgs = ctr.byteCount(cold=cold)  # fixed body content size
                        size = cbs + fmgs  # size of ctr and its content
                        while len(ims) < size and not framed:  # framed already in ims
                            yield  # until full ctr and its content in ims

                        del ims[:size]  # strip ctr and its content from ims

                    elif (ctr.code in (self.sucodes.BodyWithAttachmentGroup,
                                       self.sucodes.BigBodyWithAttachmentGroup) or
                            ctr.code in self.bucodes):

                        if not enclosed:  # starting new msg ends attachments
                            # do not consume ctr because it starts a new top level
                            # stream, group or tunnel
                            break  # done with attachments to this msg

                        # enclosed so group belongs to nested message substream
                        # extract as nested msg+atc and append to exts.nests
                        subexts = yield from self.msgParsator(ims=ims,
                                                              framed=framed,
                                                              piped=piped,
                                                              local=local,
                                                              version=self.version)

                        exts.nests.append(subexts)

                    else:  # regular attachment counter code so extract
                        del ims[:ctr.byteSize(cold=cold)]  # consume ctr itself

                        try:
                            yield from getattr(self, self.methods[ctr.name])(exts=exts,
                                ims=ims, ctr=ctr, cold=cold, abort=(framed or enclosed))
                        except AttributeError as ex:
                            raise UnexpectedCountCodeError(f"Unsupported count"
                                                    f" code={ctr.code}") from ex
                        except Exception as ex:
                            raise  # easier debug with breakpoint here

                    if enclosed:  # attachments enclosed by group which frames
                        # AttachmentGroup or BodyPlusAttachmentGroup
                        # inside group all contents must be same cold  .txt
                        # or .bny so no need to sniff for new cold here.
                        if not ims:  # end of attachment group
                            break

                    else:  # assumes that if attachments are not enclosed that
                        # framed must be true, which means ims, message plus
                        # attachments all provided at once at top level
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


        except ExtractionError as ex:
            if enclosed:  # extracted enclosed attachment group is preflushed
                raise SizedGroupError(f"Error processing attachment group"
                                             " of size={eags}")
            raise  # no enclosing attachment group so can't preflush, must flush stream

        finally:
            while verstack:  # restore version to what it was
                self.version = verstack.pop()


        return exts  # parsed substream as dict of MsgParseDom



    def msgProcess(self, exts, kvy, tvy, exc, rvy, vry):
        """Processes message + attachemnts contained in exts with respect to
        contexts in kvy, tvy,exc, rvy, and vry.

        Uses .ims when ims is not provided.

        Iterator yields when not enough bytes in ims to finish one msg plus
        attachments. Returns (which raises StopIteration) when finished.

        Parameters:
            exts (dict): parsed msg+attachments substream. Result is suitable
                           for ** expansion as keywords to subsequent processing
                           of the msg substream. The dict is the asdict() of
                           MsgParseDom dataclass
                serder (Serder): message instance SerderKERI or SerderACDC
                sigers (list[Siger]): ControllerIdxSigs
                wigers (list[Siger]): WitnessIdxSigs
                cigars (list[Cigar]): NonTransReceiptCouples cigar with verfer from (pre+sig)
                rsgs   (list[TransReceipts]): TransReceiptIdxSigGroups (prefixer, number, diger, [sigers])
                tsgs   (list[TransSigs]):TransIdxSigGroups (prefixer, number, diger, [sigers])
                lsgs   (list[TransLastSigs]): TransLastIdxSigGroups (prefixer,[sigers]) (was tsgs)
                frcs   (list[FirstSeen]): FirstSeenReplayCouples (number, dater)
                sscs   (list[SealSource]): SealSourceCouples (number, diger) sealing or sealed event
                ssts   (list[SealEvent]): SealSourceTriples (prefixer, number, diger) sealing or sealed event
                tdcs   (list[SealKind]): TypedDigestSealCouples SealKind (verser, diger)
                bsqs   (list[BlindState]): BlindedStateQuadruples BlindState (diger, noncer, noncer, labeler)
                bsss   (list[BoundState]): BoundStateSextuples BoundState (diger, noncer, noncer, labeler, number, noncer)
                tmqs   (list[TypeMedia]): TypedMediaQuadruples TypeMedia (diger, noncer, labeler, texter)
                essrs  (list[Texter]): ESSR encapsulations as Texters
                ptds   (list[bytes]): PathedMaterialCouples (path, text) -> concat path+text
                nests  (list[dict]): asdict(MsgParseDOM) instance dicts recursively nested
                local  (bool): True means treat as local source controller context for processing
                               False means treat as remote controller context for processing

            kvy (Kevery): route KERI KEL message types to this instance
            tvy (Tevery): route TEL message types to this instance
            exc (Exchanger): route EXN message types to this instance
            rvy (Revery): reply (RPY) message handler
            vry (Verifier): ACDC credential processor


        Logic::

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
        serder = exts['serder']

        if isinstance(serder, SerderKERI):
            ilk = serder.ilk  # dispatch abased on ilk

            if kvy is not None and serder.pvrsn.major >= Vrsn_2_0.major and ilk in (
                Ilks.qry, Ilks.rpy, Ilks.exn, Ilks.xip, Ilks.pro, Ilks.bar
            ):
                kwa = dict(exts)
                kwa['rvy'] = rvy
                kwa['exc'] = exc
                kwa['tvy'] = tvy
                try:
                    kvy.processMsg(kwa=kwa)
                except AttributeError as ex:
                    raise ValidationError(f"Error while processing msg in Kevery"
                                                f"= {serder.pretty()}.") from ex
                return

            if ilk in [Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt]:  # event msg
                firner, dater = exts['frcs'][-1] if exts['frcs'] else (None, None)  # use last one if more than one
                # when present assumes this is source seal of delegating event in delegator's KEL
                delsner, delsger = exts['sscs'][-1] if exts['sscs'] else (None, None)  # use last one if more than one
                if not exts['sigers']: # sigers:
                    msg = f"Missing attached signature(s) for evt = {serder.ked['d']}"
                    logger.info(msg)
                    logger.debug("Event Body = \n%s\n", serder.pretty())
                    raise ValidationError(msg)
                try:
                    exts['firner'] = firner  # first seen number
                    exts['dater'] = dater
                    exts['delsner'] = Number(num=delsner.sn) if delsner is not None else None
                    exts['delsger'] = delsger

                    kvy.processEvent(**exts)

                    if exts['cigars']:  # cigars
                        kvy.processAttachedReceiptCouples(**exts)

                    if exts['rsgs']:  # rsgs  TransReceiptIdxSigGroups (was trqs)
                        kvy.processAttachedReceiptSigGroups(**exts)

                except AttributeError as ex:
                    msg = f"No kevery to process so dropped msg={serder.said}"
                    logger.info(msg)
                    logger.debug("Event Body = \n%s\n", serder.pretty())
                    raise ValidationError(msg) from ex

            elif ilk in [Ilks.rct]:  # event receipt msg (nontransferable)
                if not (exts['cigars'] or exts['wigers'] or exts['tsgs'] or exts['rsgs']):
                    msg = f"Missing attached signatures on receipt msg sn={serder.sn} SAID={serder.said}"
                    logger.info(msg)
                    logger.debug("Receipt body=\n%s\n", serder.pretty())
                    raise ValidationError(msg)

                try:
                    kvy.processReceipt(**exts)

                except AttributeError as ex:
                    raise ValidationError(f"No kevery to process so dropped msg"
                                                 f"= {serder.pretty()}.") from ex


            elif ilk in (Ilks.rpy,):  # reply message
                if not (exts['cigars'] or exts['tsgs']):  # (cigars or tsgs)
                    raise ValidationError(f"Missing attached endorser signature(s) "
                                                 f"to reply msg = {serder.pretty()}.")

                try:
                    rvy.processReply(**exts)

                except AttributeError as ex:
                    raise ValidationError(f"No revery to process so dropped msg"
                                                 f"= {serder.pretty()}.") from ex

            elif ilk in (Ilks.qry,):  # query message
                # ToDo neigher kvy.processQuery nor tvy.processQuery actually verify
                if exts['lsgs']:
                    # use last one if more than one
                    pre, sigers = exts['lsgs'][-1] if exts['lsgs'] else (None, None)
                    exts["source"] = pre
                    exts["sigers"] = sigers
                else:
                    exts['sigers'] = []  # just in case sigers provided not by lsgs

                if not (exts['source'] or exts['cigars']):  # need one or the other
                    raise ValidationError(f"Missing attached requester "
                                                 f"source for query"
                                                 f" msg = {serder.pretty()}.")

                route = serder.ked["r"]
                if route in ["logs", "ksn", "mbx"]:
                    try:
                        kvy.processQuery(**exts)
                    except AttributeError as ex:
                        raise ValidationError(f"No kevery to process so "
                                    f" dropped msg={serder.pretty()}") from ex
                    except QueryNotFoundError as ex:  # catch escrow error and log it
                        if logger.isEnabledFor(logging.TRACE):
                            logger.exception("Error processing query = %s", ex)
                            logger.trace("Query Body=\n%s\n", serder.pretty())
                        else:
                            logger.error("Error processing query = %s", ex)

                elif route in ["tels", "tsn"]:
                    try:
                        tvy.processQuery(**exts)
                    except AttributeError as ex:
                        raise ValidationError(f"No tevery to process so dropped msg"
                                                     f"={serder.pretty()}") from ex

                else:
                    raise ValidationError(f"Invalid resource type {route}"
                                                 f"so dropped msg={serder.pretty()}.")

            elif ilk in (Ilks.exn,):
                if not (exts['cigars'] or exts['tsgs']):
                    raise ValidationError(f"Missing attached exchanger "
                                        f"signatures for msg={serder.pretty()}")

                try:
                    exc.processEvent(**exts)

                except AttributeError as ex:
                    raise ValidationError(f"No Exchange to process so "
                                    f"dropped msg={serder.pretty()}.") from ex

            elif ilk in (Ilks.vcp, Ilks.vrt, Ilks.iss, Ilks.rev, Ilks.bis, Ilks.brv):
                # TEL msg
                # get transaction event seal ref to Issuer's KEL
                # use last one if more than one
                number, diger = exts['sscs'][-1] if exts['sscs'] else (None, None)
                exts['seqner'] = number
                exts['saider'] = diger
                try:
                    tvy.processEvent(**exts)

                except AttributeError as ex:
                    raise ValidationError(f"No tevery to process so dropped msg"
                                                 f"={serder.pretty()}.") from ex
            else:
                raise ValidationError(f"Unexpected message {ilk=} for evt="
                                             f"{serder.pretty()}")

        elif isinstance(serder, SerderACDC):
            ilk = serder.ilk  # dispatch based on ilk

            if ilk is None:  # default for ACDC
                try:
                    # use last one if more than one
                    prefixer, number, diger = exts['ssts'][-1] if exts['ssts'] else (None, None, None)
                    exts['prefixer'] = prefixer
                    exts['seqner'] = number
                    exts['saider'] = diger
                    vry.processACDC(**exts)
                except AttributeError as ex:
                    raise ValidationError(f"No verifier to process so "
                                        f"dropped ACDC={serder.pretty()}") from ex
            else:
                raise ValidationError(f"Unexpected message ilk = {ilk} "
                                             f"for evt={serder.pretty()}")

        else:
            raise ValidationError(f"Unexpected protocol type={serder.proto}"
                                         f" for event message={serder.pretty()}.")

        return True  # done


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
            exts.sigers.extend(sigers)
        except KeyError:
            exts.sigers = sigers



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
            exts.sigers.extend(sigers)
        except KeyError:
            exts.sigers = sigers


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
            exts.wigers.extend(wigers)
        except KeyError:
            exts.wigers = wigers


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
            exts.wigers.extend(wigers)
        except KeyError:
            exts.wigers = wigers


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
            exts.cigars.extend(cigars)
        except KeyError:
            exts.cigars = cigars


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
            exts.cigars.extend(cigars)
        except KeyError:
            exts.cigars = cigars


    def _TransReceiptIdxSigGroups1(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv1 TransReceiptIdxSigGroups group

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
            rsgs (list[tuple]): [(prefixer,number,diger,[isigers])]

         extract attaced trans receipt idx sig groups
        spre+ssnu+sdig+[sigs]
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
        rsgs = []
        isigers = []
        while gims:   # extract each attached group and strip from gims
            prefixer = self.extract(ims=gims, klas=Prefixer, cold=cold)
            number = self.extract(ims=gims, klas=Number, cold=cold)
            diger = self.extract(ims=gims, klas=Diger, cold=cold)
            ictr = self.extract(ims=gims, klas=Counter, cold=cold)

            if ictr.code != CtrDex_1_0.ControllerIdxSigs:
                raise UnexpectedCountCodeError(f"Expected count code="
                            f"{CtrDex_1_0.ControllerIdxSigs}, got code={ictr.code}")

            isigers = []
            for i in range(ictr.count):  # extract each signature in idx cnt
                isiger = self.extract(ims=gims, klas=Siger, cold=cold)
                isigers.append(isiger)

            rsgs.append((prefixer, number, diger, isigers))

        try:
            exts.rsgs.extend(rsgs)
        except KeyError:
            exts.rsgs = rsgs


    def _TransReceiptIdxSigGroups2(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv2 TransReceiptIdxSigGroups

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
            rsgs (list[tuple]): [(prefixer,number,diger,[isigers])]

        extract attaced trans receipt idx sig groups
        spre+ssnu+sdig+[sigs]
        spre is pre of signer of vrc
        ssnu is sn of signer's est evt when signed
        sdig is dig of signer's est event when signed
        [sigs] is list of indexed signature of signer

        When attached to event or routed mesag signature on msg attached
        When attached to receipt msg signature on event referenced in receipt

        """
        gs = ctr.byteCount(cold=cold)
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        rsgs = []
        isigers = []
        while gims:   # extract each attached group and strip from gims
            prefixer = self.extract(ims=gims, klas=Prefixer, cold=cold)
            number = self.extract(ims=gims, klas=Number, cold=cold)
            diger = self.extract(ims=gims, klas=Diger, cold=cold)
            ictr = self.extract(ims=gims, klas=Counter, cold=cold)
            if ictr.code != CtrDex_2_0.ControllerIdxSigs:
                raise UnexpectedCountCodeError(f"Expected count code="
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
            rsgs.append((prefixer, number, diger, isigers))  # tuple
        try:
            exts.rsgs.extend(rsgs)
        except KeyError:
            exts.rsgs = rsgs



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
            tsgs (list[tuple]): [(prefixer,number,diger,[isigers])]

        """
        tsgs = []
        for i in range(ctr.count):  # extract each attached group
            prefixer = yield from self._extractor(ims=ims,
                                                  klas=Prefixer,
                                                  cold=cold,
                                                  abort=abort)
            number = yield from self._extractor(ims=ims,
                                                klas=Number,
                                                cold=cold,
                                                abort=abort)
            diger = yield from self._extractor(ims=ims,
                                                klas=Diger,
                                                cold=cold,
                                                abort=abort)
            ictr = yield from self._extractor(ims=ims,
                                              klas=Counter,
                                              cold=cold,
                                              abort=abort)
            if ictr.code != CtrDex_1_0.ControllerIdxSigs:
                raise UnexpectedCountCodeError(f"Expected count code="
                            f"{CtrDex_1_0.ControllerIdxSigs}, got code={ictr.code}")
            isigers = []
            for i in range(ictr.count):  # extract each signature in idx cnt
                isiger = yield from self._extractor(ims=ims,
                                               klas=Siger,
                                               cold=cold,
                                               abort=abort)
                isigers.append(isiger)
            tsgs.append((prefixer, number, diger, isigers))
        try:
            exts.tsgs.extend(tsgs)
        except KeyError:
            exts.tsgs = tsgs


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
            tsgs (list[tuple]): [(prefixer,number,diger,[isigers])]

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
            number = self.extract(ims=gims, klas=Number, cold=cold)
            diger = self.extract(ims=gims, klas=Diger, cold=cold)
            ictr = self.extract(ims=gims, klas=Counter, cold=cold)
            if ictr.code != CtrDex_2_0.ControllerIdxSigs:
                raise UnexpectedCountCodeError(f"Expected count code="
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
            tsgs.append((prefixer, number, diger, isigers))  # tuple
        try:
            exts.tsgs.extend(tsgs)
        except KeyError:
            exts.tsgs = tsgs


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
            lsgs (list[tuple]): [(prefixer, [isigers])]

        """
        lsgs = []
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
                raise UnexpectedCountCodeError(f"Expected count code="
                            f"{CtrDex_1_0.ControllerIdxSigs}, got code={ictr.code}")
            isigers = []
            for i in range(ictr.count):  # extract each signature in idx cnt
                isiger = yield from self._extractor(ims=ims,
                                               klas=Siger,
                                               cold=cold,
                                               abort=abort)
                isigers.append(isiger)
            lsgs.append((prefixer, isigers))
        try:
            exts.lsgs.extend(lsgs)
        except KeyError:
            exts.lsgs = lsgs


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
            lsgs (list[tuple]): [(prefixer, [isigers])]

        """
        gs = ctr.byteCount(cold=cold)
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        lsgs = []
        isigers = []
        while gims:   # extract each attached group strip from gims
            prefixer = self.extract(ims=gims, klas=Prefixer, cold=cold)
            ictr = self.extract(ims=gims, klas=Counter, cold=cold)
            if ictr.code != CtrDex_2_0.ControllerIdxSigs:
                raise UnexpectedCountCodeError(f"Expected count code="
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
            lsgs.append((prefixer, isigers))  # tuple
        try:
            exts.lsgs.extend(lsgs)
        except KeyError:
            exts.lsgs = lsgs


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
            frcs (list[tuple]): [(number, dater)]  first seen sn
        """
        frcs = []
        for i in range(ctr.count):  # extract each attached group
            firner = yield from self._extractor(ims=ims,
                                                klas=Number,
                                                cold=cold,
                                                abort=abort)
            dater = yield from self._extractor(ims=ims,
                                                klas=Dater,
                                                cold=cold,
                                                abort=abort)
            frcs.append((firner, dater))
        try:
            exts.frcs.extend(frcs)
        except KeyError:
            exts.frcs = frcs


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
            frcs (list[tuple]): [(number, dater)]  first seen sn

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
            firner = self.extract(ims=gims, klas=Number, cold=cold)
            dater = self.extract(ims=gims, klas=Dater, cold=cold)
            frcs.append((firner, dater))
        try:
            exts.frcs.extend(frcs)
        except KeyError:
            exts.frcs = frcs


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
            sscs (list[tuple]): [(seqner, number)]
        """
        sscs = []
        for i in range(ctr.count):  # extract each attached group
            number = yield from self._extractor(ims=ims,
                                                klas=Number,
                                                cold=cold,
                                                abort=abort)
            diger = yield from self._extractor(ims=ims,
                                                klas=Diger,
                                                cold=cold,
                                                abort=abort)
            sscs.append((number, diger))
        try:
            exts.sscs.extend(sscs)
        except KeyError:
            exts.sscs = sscs


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
            sscs (list[tuple]): [(seqner, number)]

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
            number = self.extract(ims=gims, klas=Number, cold=cold)
            diger = self.extract(ims=gims, klas=Diger, cold=cold)
            sscs.append((number, diger))
        try:
            exts.sscs.extend(sscs)
        except KeyError:
            exts.sscs = sscs


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
            number = yield from self._extractor(ims=ims,
                                                klas=Number,
                                                cold=cold,
                                                abort=abort)
            diger = yield from self._extractor(ims=ims,
                                                klas=Diger,
                                                cold=cold,
                                                abort=abort)
            ssts.append((prefixer, number, diger))
        try:
            exts.ssts.extend(ssts)
        except KeyError:
            exts.ssts = ssts


    def _SealSourceTriples2(self, exts, ims, ctr, cold, abort):
        """Generator to extract and strip CESRv2 SealSourceTriples group

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
            number = self.extract(ims=gims, klas=Number, cold=cold)
            diger = self.extract(ims=gims, klas=Diger, cold=cold)
            ssts.append((prefixer, number, diger))
        try:
            exts.ssts.extend(ssts)
        except KeyError:
            exts.ssts = ssts


    def _TypedDigestSealCouples(self, exts, ims, ctr, cold, abort):
        """Generator to extract CESRv2 TypedDigestSealCouples group

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
            tdcs (list[tuple]): [(verser, diger)]

        """
        gs = ctr.byteCount(cold=cold)
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        tdcs = []
        while gims:   # extract each attached group and strip from gims
            verser = self.extract(ims=gims, klas=Verser, cold=cold)
            diger = self.extract(ims=gims, klas=Diger, cold=cold)
            tdcs.append((verser, diger))
        try:
            exts.tdcs.extend(tdcs)
        except KeyError:
            exts.tdcs = tdcs


    def _BlindedStateQuadruples(self, exts, ims, ctr, cold, abort):
        """Generator to extract and strip CESRv2 BlindedStateQuadruples group

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
            bsqs (list[tuple]): [(diger, noncer, acdcer, stater)]

        """
        gs = ctr.byteCount(cold=cold)
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        bsqs = []
        while gims:   # extract each attached group and strip from gims
            diger = self.extract(ims=gims, klas=Diger, cold=cold)
            noncer = self.extract(ims=gims, klas=Noncer, cold=cold) # Noncer may be empty code
            acdcer = self.extract(ims=gims, klas=Noncer, cold=cold)  # Noncer may be empty code
            stater = self.extract(ims=gims, klas=Labeler, cold=cold) # Labeler may be empty code
            bsqs.append((diger, noncer, acdcer, stater))
        try:
            exts.bsqs.extend(bsqs)
        except KeyError:
            exts.bsqs = bsqs


    def _BoundStateSextuples(self, exts, ims, ctr, cold, abort):
        """Generator to extract and strip CESRv2 BoundStateSextuples group

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
            bsss (list[tuple]): [(diger, noncer, acdcer, stater, number, eventer)]

        """
        gs = ctr.byteCount(cold=cold)
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        bsss = []
        while gims:   # extract each attached group and strip from gims
            diger = self.extract(ims=gims, klas=Diger, cold=cold)
            noncer = self.extract(ims=gims, klas=Noncer, cold=cold) # Noncer may be empty code
            acdcer = self.extract(ims=gims, klas=Noncer, cold=cold)  # Noncer may be empty code
            stater = self.extract(ims=gims, klas=Labeler, cold=cold) # Labeler may be empty code
            number = self.extract(ims=gims, klas=Number, cold=cold) # Labeler may be empty code
            eventer = self.extract(ims=gims, klas=Noncer, cold=cold)  # Noncer may be empty code
            bsss.append((diger, noncer, acdcer, stater, number, eventer))
        try:
            exts.bsss.extend(bsss)
        except KeyError:
            exts.bsss = bsss


    def _TypedMediaQuadruples(self, exts, ims, ctr, cold, abort):
        """Generator to extract and strip CESRv2 TypedMediaQuadruples group

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
            tmqs (list[tuple]): [(diger, noncer, labeler, texter)]

        """
        gs = ctr.byteCount(cold=cold)
        while len(ims) < gs:
            if abort:  # assumes already full frame extracted unexpected problem
                raise ShortageError(f"Unexpected stream shortage on enclosed "
                                    f"group code={ctr.qb64}")
            yield  # wait until have full group size

        gims = ims[:gs]  # copy out group sized substream
        del ims[:gs]  # strip off from ims
        tmqs = []
        while gims:   # extract each attached group and strip from gims
            diger = self.extract(ims=gims, klas=Diger, cold=cold)
            noncer = self.extract(ims=gims, klas=Noncer, cold=cold) # Noncer may be empty code
            labeler = self.extract(ims=gims, klas=Labeler, cold=cold)
            texter = self.extract(ims=gims, klas=Texter, cold=cold)
            tmqs.append((diger, noncer, labeler, texter))
        try:
            exts.tmqs.extend(tmqs)
        except KeyError:
            exts.tmqs = tmqs


    def _PathedMaterialCouples(self, exts, ims, ctr, cold, abort):
        """Generator to extract  and strip CESR v1 and v2 PathedMaterialCouples
        Includes both big and small sized groups.
        Since v1 counts quadlets/triples the logic is the same for both v1 and v2.
        The contexts of a pathed material group
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
            exts.ptds.extend([gims])
        except KeyError:
            exts.ptds = [gims]


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
            exts.essrs.extend(essrs)
        except KeyError:
            exts.essrs = essrs


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
            exts.essrs.extend(essrs)
        except KeyError:
            exts.essrs = essrs
