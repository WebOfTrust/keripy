
from keri import kering
from keri.help import helping

from typing import NamedTuple
from keri import help
from hio.base import Doer
import json
from hio.help import decking
from keri.core.serdering import Serder
from keri.kering import Ilks

logger = help.ogler.getLogger()

class MessageType(NamedTuple):
    """Named tuple for KERI message types, not yet used."""
    QRY: str = "qry"
    RPY: str = "rpy"
    PRO: str = "pro"
    BAR: str = "bar"
    EXN: str = "exn"


MESSAGE_TYPES = MessageType()

class TimelinessCache:
    """TimelinessCache is responsible for preventing replay attacks in KERI/KRAM by ensuring
    messages are timely and processed in a strictly monotonically ordered fashion.

    It maintains:
    1. A Lagging Window Size Table - to determine validity windows for different message types
    2. A Replay Cache Table - to store timestamps of previously validated messages
    """
    #change to float time, 3 seconds, 1 second
    def __init__(self, db, defaultWindowSize=300_000_000, defaultDriftSkew=60_000_000, cues=None, msgs=None):
        """Initialize the TimelinessCache.

        Parameters:
            db: Database instance that contains the IoSetSuber at db.time
            defaultWindowSize (int): Default window size in microseconds
            defaultDriftSkew (int): Default drift skew in microseconds
        """
        self.defaultWindowSize = defaultWindowSize
        self.defaultDriftSkew = defaultDriftSkew

        self.db = db

    def setWindowParameters(self, aid, windowSize=None, driftSkew=None, messageType=None):
        """Set window parameters for given autonomic identifier and message type.
        """
        windowSize = windowSize or self.defaultWindowSize
        driftSkew = driftSkew or self.defaultDriftSkew

        # Serialize the tuple as JSON bytes for storage
        windowTuple = (windowSize, driftSkew)
        serialized = json.dumps(windowTuple).encode('utf-8')

        self.db.kram.pin(aid, [serialized])


    def getWindowParameters(self, aid, messageType=None):
        """Get window parameters for given autonomic identifier and message type.
        Falls back to default values if no entry exists for the aid.

        Parameters:
            aid (str): autonomic identifier
            messageType (str | None): message type identifier. None for now, but will
                be used to determine the window size for a given message type

        Returns:
            tuple: (windowSize, driftSkew) as integers in microseconds
        """
        try:
            # Try to get the stored parameters
            storedData = self.db.kram.getLast(aid)
            if storedData is not None:
                # Deserialize from JSON bytes
                windowTuple = json.loads(storedData.decode('utf-8'))
                return windowTuple[0], windowTuple[1]
        except Exception:
            pass

        # Fallback to defaults
        return self.defaultWindowSize, self.defaultDriftSkew


    def _constructCacheKey(self, serder):
        """Construct the key for the Replay Cache Table.

        Parameters:
            serder: The SerderKERI instance containing the message

        Returns:
            str: The key for the Replay Cache Table
        """
        sad = serder.sad
        sourceAid = sad.get("i", "")  # 'i' for identifier in KERI messages
        # messageType = serder.ilk  # Use serder.ilk for message type

        # return (sourceAid, messageType)
        return sourceAid

    def _getCachedTimestamp(self, key):
        """Get the cached timestamp for a key from the Replay Cache Table.

        Parameters:
            key (str): The cache key

        Returns:
            int | None: The cached timestamp in microseconds or None if not found
        """
        try:
            storedTimestamp = self.db.time.getLast(key)
            if storedTimestamp is not None:
                return int(storedTimestamp)
        except Exception as e:
            print(e)
            pass
        return None

    def _storeTimestamp(self, key, timestamp):
        """Store a timestamp in the Replay Cache Table.

        Parameters:
            key (str): The cache key
            timestamp (int): The timestamp to store in microseconds
        """
        timestampStr = str(timestamp)

        self.db.time.pin(key, [timestampStr])

    def checkMessageTimeliness(self, serder):
        """Check if a message is timely and not a replay.

        Parameters:
            serder: The Serder instance containing the message

        Returns:
            tuple: (isValid, reason) where:
                isValid (bool): True if the message is timely and not a replay
                reason (str): A description of why the message was accepted or rejected
        """
        if not serder.verify():
            return False, "Invalid message structure"

        sad = serder.sad

        sourceAid = sad.get("i", None)
        messageType = serder.ilk or None
        timestamp = sad.get("dt", None)

        if not all([sourceAid, messageType, timestamp]):
            return False, "Missing required message fields"

        windowSize, driftSkew = self.getWindowParameters(sourceAid, messageType)

        # Convert both timestamps to microseconds since epoch for comparison
        currentTime = helping.fromIso8601(helping.nowIso8601())
        currentTimeMicros = int(currentTime.timestamp() * 1_000_000)

        messageTime = helping.fromIso8601(timestamp)
        messageTimeMicros = int(messageTime.timestamp() * 1_000_000)

        if (messageTimeMicros < currentTimeMicros - driftSkew - windowSize or
                messageTimeMicros > currentTimeMicros + driftSkew):
            raise kering.ValidationError(f"Message is out of time window {serder.pretty()}")

        cacheKey = self._constructCacheKey(serder)

        cachedTimestamp = self._getCachedTimestamp(cacheKey)

        if cachedTimestamp is None:
            self._storeTimestamp(cacheKey, messageTimeMicros)
            # Message accepted, new entry
            return True

        if messageTimeMicros > cachedTimestamp:
            self._storeTimestamp(cacheKey, messageTimeMicros)
            # Message accepted, updated cached entry
            return True

        if messageTimeMicros == cachedTimestamp:
            # QUESTION: Should we be accepting messages here?
            return False, ""

        raise kering.ValidationError(f"Message is out of order {serder.pretty()}")

    def pruneCache(self):
        """Prune stale entries from the Replay Cache Table.

        Returns:
            int: The number of pruned entries
        """
        prunedCount = 0
        currentTime = int(helping.fromIso8601(helping.nowIso8601()).timestamp()) * 1_000_000

        for key, timestampStr in self.db.time.getItemIter():
            try:

                timestamp = int(timestampStr)

                windowSize, driftSkew = self.getWindowParameters(key)

                if timestamp < currentTime - driftSkew - windowSize:
                    self.db.time.rem(key)
                    prunedCount += 1

            except Exception:
                continue

        return prunedCount

    def processKrms(self):
        for said, serder in self.db.krms.getFullItemIter():
            try:
                # assumes serder is a SerderKERI, more processing may be needed or addition of klas to db.krms
                if self.checkMessageTimeliness(serder):
                    self.db.exns.pin(said, serder)
                    self.db.krms.rem(said)
            except kering.ValidationError as e:
                logger.error(f"Invalid message: {e}")
            self.pruneCache()

class KramDoer(Doer):
    """KramDoer is a Doer that manages the KRAM database."""
    def __init__(self, db):
        self.db = db

        self.tc = TimelinessCache(self.db)

        super(KramDoer, self).__init__()

    def recur(self, tyme):
        self.tc.processKrms()



