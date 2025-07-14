import time

from keri.help import helping

from typing import Tuple, Optional, NamedTuple

from hio.base import Doer

from keri.core.serdering import Serder
from keri.kering import Ilks


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

    def __init__(self, db, defaultWindowSize=300_000_000, defaultDriftSkew=60_000_000):
        """Initialize the TimelinessCache.

        Parameters:
            db: Database instance that contains the IoSetSuber at db.time
            defaultWindowSize (int): Default window size in microseconds
            defaultDriftSkew (int): Default drift skew in microseconds
        """
        self.defaultWindowSize = defaultWindowSize
        self.defaultDriftSkew = defaultDriftSkew

        # Will eventually be used with MessageType named tuple to set the window size for a given message type
        self._windowParamsTable = {}

        # Database access
        self.db = db

    def getWindowParameters(self, aid, messageType=None):
        """Get window parameters for given autonomic identifier and message type.
        Eventually this method will reference a table of window parameters.

        Parameters:
            aid (str): autonomic identifier
            messageType (str | None): message type identifier. None for now, but will
                be used to determine the window size for a given message type

        Returns:
            tuple: (windowSize, driftSkew) as integers in microseconds
        """
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

        # QUESTION: Do we need to cache the whole request
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
            return False, "Message timestamp outside lagging window"

        cacheKey = self._constructCacheKey(serder)

        cachedTimestamp = self._getCachedTimestamp(cacheKey)

        if cachedTimestamp is None:
            self._storeTimestamp(cacheKey, messageTimeMicros)
            return True, "Message accepted, new entry"

        if messageTimeMicros > cachedTimestamp:
            self._storeTimestamp(cacheKey, messageTimeMicros)
            return True, "Message accepted, timestamp updated"

        if messageTimeMicros == cachedTimestamp:
            # QUESTION: Should we be accepting messages here?
            return False, ""

        return False, "Message dropped, older than cached timestamp (replay/out-of-order)"

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

# class TimelinessEscrowDoer(Doer):

# if __name__ == "__main__":
#
#     from keri.core.serdering import Serder
#     pass