# -*- encoding: utf-8 -*-
"""
keri.sit.siting module

Siter functionality

"""

from collections import namedtuple, deque

from .. import Versionage, InvalidCodeError
from ..core import (MtrDex, DigDex, NonceDex, Noncer,  Ilker, Diger, Number)
from ..help import intToB64

Version = Versionage(major=0, minor=0)
MaxSpan = 256 # 256 bits or forks == leaf limb span
MaxSpanBytes = 32  # MaxSpan in bytes equivalent

Emptier = Noncer(nonce="")  # empty string
EmptyQb2 = Emptier.qb2
EmptyQb64 = Emptier.qb64


# kith is the data type string of part, i.e. ilk for node and leaf parts
Kithage = namedtuple("Kithage", "node leaf")
Kiths = Kithage(node='nod', leaf="lea")

"""NodeSaidage Doc String
Full Set of Fields (per tree and per part) used to compute node SAID.
Values are Matter instances. The said field is computed using the .qb64 property
of each instance

Per tree/part type field values:
    kith is Ilker instance encoding of node kith, value == Kiths.node
    tuid is Noncer instance encoding the tree unique identifier.
        This default is a CESR encoded crypto strength 16 byte (128 bit) value.
        Because it is CESR encoded other namespacing information can be included
        in a bigger tuid value as long as it includes at least 128 bits of entropy
Per node fields:
    said is Noncer instance digesting NodeSaidage content using SAID protocol
        said filled with dummy values for digest then replaced with computed SAID
        saided data = kith+tuid+saiddummy+span+limb+left+right
    span is Number instance encoding 2 byte int of number of MSbits in node limb
             min 0 for root to max of 255 = MaxSpan-1
    limb is Diger instance encoding of up to 256 bits with limb span MSbits
    left is Noncer instance encoding said of left child (node, leaf or empty)
    right is Noncer instance encoding said of right child (node, leaf or empty)
"""
NodeSaidage = namedtuple("NodeSaidage", "kith tuid said span limb left right")

"""LeafSaidage Doc String
Full Set of Fields (per tree and per part) used to compute leaf SAID.
Values are Matter instances. The said field is computed using the .qb64 property
of each instance

Per tree/part type field values:
    kith is Ilker instance encoding of leaf kith, value == Kiths.leaf
    tuid is Noncer instance encoding the tree unique identifier.
        This default is a CESR encoded crypto strength 16 byte (128 bit) value.
        Because it is CESR encoded other namespacing information can be included
        in a bigger tuid value as long as it includes at least 128 bits of entropy
Per leaf fields:
    said is Noncer instance digesting LeafSaidage content using SAID protocol
        said filled with dummy values for digest then replaced with computed SAID
        saided data = kith+tuid+saiddummy+span+limb
    span is Number instance encoding 2 byte int of number of MSbits in leaf limb
             always 256 == MaxSpan
    limb is Diger instance encoding of 256 bit branch path to leaf with MSbits
        always 256 == MaxSpan
        limb calculated on leaf info said using tree specific digest code so
        limb inhabits same hash space as all other parts of tree.
        Leaf info said may use different digest algo from tree wide digest algo.
        Because limb makes secure committment to leaf info there is no security
        need to store leaf info said per leaf. It may be stored in separate
        field map indexed by limb for convenience.
       """
LeafSaidage = namedtuple("LeafSaidage", "kith tuid said span limb")

"""Nodage Doc String
A Nodage instance holds the per node fields where values use the appropriate
encoding depending on context.
For computation each field value is a Matter instance that enables convenient
access to the corresponding raw value of each instance.
For compact in memory storage each field value is serialized as the corresponding
.qb2 value of each instance.
For archival (disk) storage the field values are serialized as the corresponding
.qb64 value of each instance

Nodage fields:
    span is Number instance encoding 2 byte int of number of MSbits in node limb
        min 0 for root to max of 255 = MaxSpan-1
    limb is Diger instance encoding the 256 bits of which the MS (big endian)
        span bits provide the child forks to node. Depth == limb span MSbits
    left is Noncer instance of left child's Saidage:
        node or leaf or empty (only root node children can be empty)
    right is Noncer instance of right child's Saidage:
        node or leaf or empty (only root node children can be empty)
"""
Nodage = namedtuple("Nodage", "span limb left right", defaults=(EmptyQb2, EmptyQb2))

"""Leafage Doc String
A Leafage instance holds the per leaf fields where values use the appropriate
encoding depending on context.
For computation each field value is a Matter instance that enables convenient
access to the corresponding raw value of each instance.
For compact in memory storage each field value is serialized as the corresponding
.qb2 value of each instance.
For archival (disk) storage the field values are serialized as the corresponding
.qb64 value of each instance

Leafage Fields:
    span is Number instance encoding 2 byte int of number of MSbits in leaf limb
             always 256 == MaxSpan
    limb is Diger instance encoding the 256 bits (big endian) of potential
        child forks to leaf. All 256 bits are meaningful but for any leaf attached
        to a given node only the MS node span+1 are used to address that leaf
        The limb digest is computed on leaf infos said which said is bound to
        actual leaf info. The info said algo may differ from the tree wide algo
        used to compute node and leaf saids.
"""
Leafage = namedtuple("Leafage", "span limb")

"""Partage Doc String
Partage is namedtuple of tree part (node or leaf) of form (said, part).
A Partage instance field values use the appropriate encoding depending on context.
For computation each field value is a Matter instance that enables convenient
access to the corresponding raw value of each instance.
For compact in memory storage each field value is serialized as the corresponding
.qb2 value of each instance.
For archival (disk) storage the field values are serialized as the corresponding
.qb64 value of each instance

Partage fields:
    said is Diger instance of said of full Saidage for part
    part is either a Nodage or Leafage instance as appropriate for part
"""
Partage = namedtuple("Partage", "said part")



class Siter:
    """Siter manages a SAIDed Info Tree (SIT)


    Attributes::
        tuider (Noncer): instance encoding crypto 16 byte4 tree unique identifier
                       this ensures separation of digests within each unique tree.
        code (str): qb64 digest code shared by all node/leaf SAIDs
        root (Partage: instance of root Partage as (root said, rootage)) where
                       values are matter instances:
                       said is Diger instance, part is Nodage instance whose
                           values are Matter instances
        nodes (dict): Nodage instances indexed by node said
        leaves (dict): Leafage instances indexed by leaf said
        infos (dict): leaf info saids as indexed by leaf limb

    ToDo: change .nodes, .leaves, and .infos to have virtual interface
          that supports either in-memory and disk based storage
    """
    Dummy = '#'  # default dummy for computing SAIDs
    Code = MtrDex.Blake3_256  # class default code for computing SAIDs

    @classmethod
    def saidify(cls, saidage, label='said', code=None):
        """Computes said of saidage and returns saidified copy of saidage where
        said field value given by label is replaced with computed said as saider.

        Returns::
            saidage (namedtuple): instance as saidified replacement of saidage

        Parameters::
            saidage (namedtuple): instance from which to compute and replace said
                                  field given by label
            label (str): field to hold said
            code (str|None): digest code for computing said. None means cls.Code


        Eventually when we have a Structor subclass with group code we can
        use a Structor instance to calculate the said
        """

        code = code if code is not None else cls.Code

        dqb64b = {l: v.qb64b for l, v in saidage._asdict().items()}  # get .qb64b of each field
        try:
            # create  dumied said field as bytes
            dqb64b[label] = (cls.Dummy * Noncer._fullSize(code)).encode()
        except KeyError as ex:
            raise ValueError(f"Invalid said field {label=}") from ex

        ser = b''.join(dqb64b.values())  # dummied ser
        saider = Noncer(ser=ser, code=code)
        if saider.code not  in DigDex:  # reforce strict so must be valid digest
            raise InvalidCodeError(f"Unsupported Digest code={saider.code}.")

        rkwa = dict()  # dict for namedtuple replace of said field with saider
        rkwa[label] = saider
        return saidage._replace(**rkwa)


    @staticmethod
    def rightAtSpanInt(limb, span):
        """Returns which side of limb at span where:
        True is right and False is left
        Usually applied to leaf limbs so uses leaf convention:
        Convention MSb at span 1 and LSb at span 256.
        Minimum span allowed is 1 and maximum is 256.
        span is how many bits into limb either node or leaf.
        A leaf is always attached as a child of a parent node. The leaf child
        side is determined by bit position in leave limb that must be greater
        that span of parent node's span

        Returns:
            side (bool): False if bit at span is  0 (side is left)
                         True if bit at span is 1 (side is right)

        Parameters:
            limb (int): 256 bit int where MSbits are forks (0 left, 1 right)
            span (int): get bit at span where:
                            span = 1 is MSb of limb
                            span = 256 is LSb of limb
        """
        if span <= 0:
            raise ValueError(f"Invalid {span=} <= 0>")

        return True if (limb >> (MaxSpan - span) & 1) else False


    @staticmethod
    def rightAtSpan(limber, spanner):
        """Returns which side of limber at spanner where:
        True is right and False is left
        where limber and spanner are Matter primitives.
        Wrapper around Siter.rightAtSpanInt
        Convention MSb at span 1 and LSb at span 256.
        Minimum allowed span is 1 and maximum is 256.

        Returns:
            side (bool): False if bit at span is  0 (side is left)
                         True if bit at span is 1 (side is right)

        Parameters:
            limber (Diger): instance .num is 256 bit int where MSbits
                            are forks (0 left, 1 right)
            spanner (Number): instane .num is span where:
                         span = 1 is MSb of limb
                         span = 256 is LSb of limb
        """
        return Siter.rightAtSpanInt(limb=limber.num, span=spanner.num)


    @staticmethod
    def twigAtSpanInt(limb, span):
        """Returns right shifted masked limb with span MS bits in order
        to match limb prefixes (twigs). Values are ints.

        Returns:
            twig (int|None): right shifted masked limb with span MS bits.
                             None if root with empty twig at span = 0

        Parameters:
            limb (int): 256 bit int where MSbits are forks (0 left, 1 right)
            span (int): number of MS bits in limb to shift and mask where:
                            span = 1 is MSb of limb
                            span = 256 is LSb of limb
        """
        if span < 0:
            raise ValueError(f"Invalid {span=} <= 0>")
        elif span == 0:  # root so empty twig
            return None
        mask = ((1 << span) - 1)
        return ((limb >> (MaxSpan-span)) & mask)


    @staticmethod
    def twigAtSpan(limber, spanner):
        """Returns right shifted masked limb with span MS bits in order
        to match limb prefixes (twigs).
        Values are Matter instances
        Wrapper around Siter.twigAtSpanInt

        Returns:
            twigger (Diger): instance .num right shifted masked limb with
                             span MS bits.

        Parameters:
            limber (Diger): instance .num is 256 bit int where MSbits are forks
                            (0 left, 1 right)
            spanner (Number): instance .num  is number of MS bits in limb to
                              shift and mask where:
                                span = 1 is MSb of limb
                                span = 256 is LSb of limb
        """
        return Number(num=Siter.twigAtSpanInt(limb=limber.num, span=spanner.num))


    @staticmethod
    def fitLeafNodeInt(leaf, node, span):
        """Determines if node limb twig of size span is prefix of leaf limb
        i.e. leaf limb would fit at or below node twig on child branch of node
        Values are int

        Returns::
            fit (bool): True means leaf limb would fit on node. i.e. node twig
                            is prefix of leaf limb so same branch
                        False means leaf limb not fit on node i.e. node twig
                            is not prefix of leaf limb so not same branch
        Parameters::
            leaf (int): limb
            node (int): limb
            span (int): span of node limb used to get node twig.
        """
        return Siter.twigAtSpanInt(node, span) == Siter.twigAtSpanInt(leaf, span)


    @staticmethod
    def fitLeafNode(leafer, noder, spanner):
        """Determines if node limb twig of node of size spanner is prefix of leaf limb
        i.e. leaf limb would fit at or below node twig
        Parameters are Matter instances

        Returns::
            fit (bool): True means leaf limb would fit on node. i.e. node twig
                            is prefix of leaf limb so same branch
                        False means leaf limb not fit on node i.e. node twig
                            is not prefix of leaf limb so not same branch
        Parameters::
            leafer (Diger): limb
            noder (Diger): limb
            spanner (Number): span of node limb used to get node twig
        """
        return Siter.fitLeafNodeInt(leafer.num, noder.num, spanner.num)


    @staticmethod
    def sameLeafNodeSpan(leafer, noder, spanner):
        """Returns span of bits for which prefix for leaf and node limbs are the
        same.  Values are Matter instances

        Returns:
            samer (Number): instance span of prefix for which leaf and node
                            limbs are same
                        O when first bit differs. same is <= span of node

        Parameters:
            leafer (Number): instance limb of leaf with MaxSpan MSbits
            noder (Number): instance limb of node with span MSbits
            spanner (Number): instance span of node limb (max MaxSpan-1, min 0)
        """
        same = self.sameLeafNodeSpanInt(leaf=leafer.num, node=noder.num, span=spanner.num)
        return(Number(num=same))


    @staticmethod
    def forkSpanSwapInt(left, right):
        """Computes and returns tuple (span, swap) where:
        span is int of shallowest fork (bit position) where limbs differ
            (1 is shallest, 256 is deepest)
        swap is boolean True means left and right need to swap at fork
                            because left limb is 1 and right limb is 0 at fork
                        False means left and right do not need to swap at fork
                            because left limb is 0 and right limb is 1 at fork
        Values are ints

        Returns::
            fork (tuple): of form (span, swap) where:
                span is int of shallowest fork (bit position) where
                    limbs differ (1 is shallest, 256 is deepest)
                swap is boolean
                    True means left and right need to swap at fork
                        because left limb is 1 and right limb is 0 at fork
                    False means left and right do not need to swap at fork
                        because left limb is 0 and right limb is 1 at fork

        Parameters::
            left (int): 256 bit limb on left side
            right (int): 256 bit limb on right side
        """
        if left == right:
            raise ValueError(f"Bad pair left={right=}")
        for span in range(1, 257):  # maxrange==256, one less than upper limit
            leftbit = (left >> (MaxSpan - span)) & 1
            rightbit = (right >> (MaxSpan - span)) & 1
            if leftbit != rightbit:  # shallowest fork found at span
                swap = True if leftbit else False
                break

        return (span, swap)


    @staticmethod
    def forkSpanSwap(lefter, righter):
        """Computes and returns tuple (span, swap) where:
        span is int of shallowest fork (bit position) where limbs differ
            (1 is shallest, 256 is deepest)
        swap is boolean True means left and right need to swap at fork
                            because left limb is 1 and right limb is 0 at fork
                        False means left and right do not need to swap at fork
                            because left limb is 0 and right limb is 1 at fork
        Values are matter instances

        Returns::
            fork (tuple): of form (spanner, swap) where:
                spanner is Number of shallowest fork (bit position) where
                    limbs differ (1 is shallest, 256 is deepest)
                swap is boolean
                    True means left and right need to swap at fork
                        because left limb is 1 and right limb is 0 at fork
                    False means left and right do not need to swap at fork
                        because left limb is 0 and right limb is 1 at fork

        Parameters::
            lefter (Diger): instance of 256 bit limb on left side
            righter (Diger): instance of 256 bit limb on right side
        """
        span, swap = Siter.forkSpanSwapInt(lefter.num, righter.num)
        return (Number(num=span), swap)




    def __init__(self, tuid=None, code=MtrDex.Blake3_256, **kwa):
        """Initialize instance

        Parameters::
            tuid (str|bytes|None): qb64 or qb64b of 16 byte tree unique identifier.
                                   None means generate crypto strength value.
                                   Use Noncer to create from raw 16 bytes.
            code (str|bytes): tree wide digest code (qb64 or qb64b) for saids


        """
        self.tuider = Noncer(nonce=tuid)  # None generates crypto random value
        self.code = code if code is not None else self.Code
        self.nodes = dict()
        self.leaves = dict()
        self.infos = dict()


        # make and insert root node in .nodes
        # span is 0, limb is all zeros, left is empty, right is empty
        rootage = Nodage(span=Number(num=0),
                         limb=Diger(raw=bytes(MaxSpanBytes), code=self.code),
                         left=Noncer(nonce=""),
                         right=Noncer(nonce=""))
        self.root = Partage(self.sayNode(rootage), rootage)
        self.pinNode(saider=self.root.said, nodage=self.root.part)


    def sayNode(self, nodage):
        """Computes and returns said of node as Matter primitive where said is
        computed with a NodeSaidage derived from nodage supplemented with per
        tree and per part field values taken from self (Siter instance)
        To 'say' is to 'hash' or to 'digest' the node.

        Returns::
            saider (Diger): instance where said is computed from NodeSaidage
                            derived from nodage as supplemented with tree fields

        Parameters::
            nodage (Nodage): instance of nodage whose field values are Matter
                             instances
        """
        saidage = NodeSaidage(kith=Ilker(ilk=Kiths.node, strict=False),
                              tuid=self.tuider,
                              said=Noncer(nonce=""),
                              span=nodage.span,
                              limb=nodage.limb,
                              left=nodage.left,
                              right=nodage.right)
        saidage = self.saidify(saidage)
        return saidage.said


    def hasNode(self, saider):
        """Checks for node at saider in .nodes

        Abstract interface to .leaves storage of Nodage for each node indexed
        by is said. Interface uses Matter instances for said and Nodage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if saider key in .nodes
                           False otherwise

        Parameters::
            saider (Diger): instance encoding said of Nodage
        """
        return (saider.qb2 in self.nodes)


    def putNode(self, saider, nodage):
        """Puts node given by nodage into .nodes at said given by .saider
        Put is idempotent. If node already exists put does not overwrite it.

        Abstract interface to .nodes storage of Nodage for each node indexed
        by is said. Interface uses Matter instances for said and Nodage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if nodage added to .nodes
                           False if entry at saider said already exists do
                               does not overwrite

        Parameters::
            saider (Diger): instance encoding said of nodage
            nodage (Nodage): instance whose field values are Matter instances

        """
        if saider.qb2 in self.nodes:
            return False  # already in .nodes

        # convert to qb2 for compact storage
        nodage = Nodage(span=nodage.span.qb2,
                        limb = nodage.limb.qb2,
                        left=nodage.left.qb2,
                        right=nodage.right.qb2)
        self.nodes[saider.qb2] = nodage
        return True


    def pinNode(self, saider, nodage):
        """Pins node given by nodage into .nodes at said given by .saider
        Pin is not idempotent. If node already exists pin overwrites it.

        Abstract interface to .nodes storage of Nodage for each node indexed
        by is said. Interface uses Matter instances for said and Nodage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Parameters::
            saider (Diger): instance encoding said of nodage
            nodage (Nodage): instance whose field values are Matter instances

        """
        # convert to qb2 for compact storage
        nodage = Nodage(span=nodage.span.qb2,
                        limb = nodage.limb.qb2,
                        left=nodage.left.qb2,
                        right=nodage.right.qb2)
        self.nodes[saider.qb2] = nodage


    def getNode(self, saider):
        """Gets node from .nodes at said given by saider.

        Abstract interface to .nodes storage of Nodage for each node indexed
        by is said. Interface uses Matter instances for said and Nodage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            nodage (Nodage|None): instance whose values are Matter instances.
                                  None when not found

        Parameters::
            saider (Diger): instance encoding said of nodage

        """
        if nodage := self.nodes.get(saider.qb2):
            # convert to Matter instances for computation
            nodage = Nodage(span=Number(qb2=nodage.span),
                            limb=Diger(qb2=nodage.limb),
                            left=Noncer(qb2=nodage.left),
                            right=Noncer(qb2=nodage.right))
        return nodage


    def isNode(self, saider):
        """Given said returns True if said belongs to node, False otherwise
        Checks for presence in .nodes and that 0 <= span < MaxSpan

        Returns::
            result (bool):  True means said given by saider corresponds to leaf
                            False otherwise
        """
        if (nodage := self.getNode(saider)) is not None:
            if 0 <= nodage.span.num < MaxSpan:
                return True
        return False


    def remNode(self, saider):
        """Removes node from .nodes at said given by saider.

        Abstract interface to .nodes storage of Nodage for each node indexed
        by is said. Interface uses Matter instances for said and Nodage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if entry at saider in .nodes found and removed
                           False if no entry at saider in .nodes

        Parameters::
            saider (Diger): instance encoding said of nodage

        """
        try:
            del self.nodes[saider.qb2]
        except KeyError as ex:
            return False

        return True


    def sayLeaf(self, leafage):
        """Computes and returns said of leaf as Matter primitive where said is
        computed with a LeafSaidage derived from leafage supplemented with per
        tree and per part field values taken from self (Siter instance)
        To 'say' is to 'hash' or to 'digest' the leaf.

        Returns::
            saider (Diger): instance where said is computed from LeafSaidage
                            derived from leafage as supplemented with tree fields

        Parameters::
            leafage (Leafage): instance of leafage whose field values are Matter
                             instances
        """
        saidage = LeafSaidage(kith=Ilker(ilk=Kiths.leaf, strict=False),
                              tuid=self.tuider,
                              said=Noncer(nonce=""),
                              span=leafage.span,
                              limb=leafage.limb)
        saidage = self.saidify(saidage)
        return saidage.said


    def hasLeaf(self, saider):
        """Checks for leaf at saider in .leaves

        Abstract interface to .leaves storage of Leafage for each leaf indexed
        by is said. Interface uses Matter instances for said and Leafage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if leafer key in .leaves
                           False otherwise

        Parameters::
            saider (Diger): instance encoding said of Leafage
        """
        return (saider.qb2 in self.leaves)


    def putLeaf(self, saider, leafage):
        """Puts leaf given by leafage into .leaves at said given by .saider
        Put is idempotent. If leaf already exists put does not overwrite it.

        Abstract interface to .leaves storage of Leafage for each leaf indexed
        by is said. Interface uses Matter instances for said and Leafage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if leafage added to .leaves
                           False if entry at saider said already exists do
                               does not overwrite

        Parameters::
            saider (Diger): instance encoding said of leafage
            leafage (Leafage): instance whose field values are Matter instances

        """
        if saider.qb2 in self.leaves:
            return False  # already in .leaves

        # convert to qb2 for compact storage
        leafage = Leafage(span=leafage.span.qb2,
                        limb = leafage.limb.qb2)
        self.leaves[saider.qb2] = leafage
        return True


    def pinLeaf(self, saider, leafage):
        """Pins leaf given by leafage into .leaves at said given by .saider
        Pin is not idempotent. If leaf already exists pin overwrites it.

        Abstract interface to .leaves storage of Leafage for each leaf indexed
        by is said. Interface uses Matter instances for said and Leafage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Parameters::
            saider (Diger): instance encoding said of leafage
            leafage (Leafage): instance whose field values are Matter instances

        """
        # convert to qb2 for compact storage
        leafage = Leafage(span=leafage.span.qb2,
                          limb = leafage.limb.qb2)
        self.leaves[saider.qb2] = leafage


    def getLeaf(self, saider):
        """Gets leaf from .leaves at said given by saider.

        Abstract interface to .leaves storage of Leafage for each leaf indexed
        by is said. Interface uses Matter instances for said and Leafage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            leafage (Leafage|None): instance whose values are Matter instances.
                                    None when not found

        Parameters::
            saider (Diger): instance encoding said of leafage

        """
        if leafage := self.leaves.get(saider.qb2):
            # convert to Matter instances for computation
            leafage = Leafage(span=Number(qb2=leafage.span),
                              limb=Diger(qb2=leafage.limb))
        return leafage


    def isLeaf(self, saider):
        """Given said returns True if said belongs to leaf, False otherwise
        Checks for presence in .leaves and that span is MaxSpan

        Returns::
            result (bool):  True means said given by saider corresponds to leaf
                            False otherwise
        """
        if (leafage := self.getLeaf(saider)) is not None:
            if leafage.span.num == MaxSpan:
                return True
        return False


    def remLeaf(self, saider):
        """Removes leaf from .leaves at said given by saider.

        Abstract interface to .leaves storage of Leafage for each leaf indexed
        by is said. Interface uses Matter instances for said and Leafage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if entry at saider in .leaves found and removed
                           False if no entry at saider in .leaves

        Parameters::
            saider (Diger): instance encoding said of leafage

        """
        try:
            del self.leaves[saider.qb2]
        except KeyError as ex:
            return False

        return True


    def updateNode(self, node, childer, side=False):
        """Updage node said given new child said childer at side given by right
        remove old node entry in .nodes at old said and pin new node entry at
        new said.  Values are Matter instances

        Raises error if unsuccessful

        Returns::
            new (Partage):  instance (said, nodage) with Matter instance values
                        as new node with updated said and child part of nodage

        Parameters::
            node (Partage): instance old node to be update
            childer (Noncer): instance of new child said
            side (bool):  True means replace right child said
                           False means replace left child said
        """
        if not self.remNode(node.said):  # first remove old node
            raise ValueError(f"Attempt to remove missing node="
                             f"{node.said.qb64}")
        # now replace
        side = 'right' if side else 'left'
        kwa = dict()
        kwa[side] = childer
        nodage = node.part._replace(**kwa)
        saider = self.sayNode(nodage)  # update said of node
        self.pinNode(saider, nodage)  # update .nodes with replacement
        return Partage(saider, nodage)  # return new node


    def forkNode(self, node, left, right, side=False):
        """Attach new forking node to  side (right/left) of node where
        left and right are forking node's left and right children. The limb of
        forking node is set to shallowest common twig of left and right limbs.

        Parameters:
            node (Partage): instance (said, part) of node where:
                            said is Noncer instance of node said
                            part is Nodage instance with Matter instance values
            left (Partage): instance of left child for new forking node
                            (said, part) with Matter instance values.
                            part may be Nodage or Leafage instance
            right (Partage): instance of right child for new forking node
                            (said, part) with Matter instance values.
                            part may be Nodage or Leafage instance
            side (bool):  False means put forking node on left child of node
                          True means put forking node on right child of node

        Returns:
            newnode (Partage): instance (said, part) of updated node where:
                            said (Noncer): instance of new nodes said
                            part is Nodage instance with Matter instance values

        """
        # create new forking node of left and right with limb at shallowest
        # common span of limbs
        span, swap = self.forkSpanSwapInt(left.part.limb.num, right.part.limb.num)
        span = span - 1  # common span is 1 less than diff bit span
        # since common does not matter if we use left or right limb to get twig
        limb = self.twigAtSpanInt(left.part.limb.num, span) << MaxSpan - span
        if swap:  # swap left and right
            save = left
            left = right
            right = save

        # create nodage of new forking node
        nodage = Nodage(span=Number(num=span),
                        limb=Diger(num=limb),
                        left=left.said,
                        right=right.said)
        saider = self.sayNode(nodage)  # update said of forking node
        self.pinNode(saider, nodage)  # update .nodes with forking node
        return self.updateNode(node, saider, side=side)


    def leafFromLimber(self, limber):
        """Create leaf to insert from limber. Computes leaf limb and said.

        Returns::
            leaf (Partage): instance (said, part) where:
                            said is Noncer instance generated from leafage
                            part is Leafage instance with Matter instance values

        Parameters::
            limber (Noncer): instance only per leaf unique value used to generate
                             leafage and then said of leaf
        """
        leafage = Leafage(span=Number(num=256), limb=limber)
        saider = self.sayLeaf(leafage)  # compute leaf said
        return Partage(said=saider, part=leafage)  # matter primitives


    def leafFromLeafer(self, leafer):
        """Create leaf to insert from leafer. Computes leaf limb and said.

        Returns::
            leaf (Partage): instance (said, part) where:
                            said is Noncer instance generated from leafage
                            part is Leafage instance with Matter instance values

        Parameters::
            leafer (Noncer): instance only per leaf unique value of said of info
                             used to generate limber which is then used to
                             generate leafage then used to generate said of leaf
        """
        limber = Noncer(ser=leafer.raw, code=self.code)  # limb for leaf
        return self.leafFromLimber(limber)


    def insert(self, leafer):
        """Insert leafer idempotently

        Returns::
            leaf (Partage|None)): of inserted leaf corresponding to leafer
                When successful insert Partage instance (said, part) where:
                        said is Noncer instance of leaf said
                        part is Leafage instance with Matter instance values
                Otherwise:  None

        Parameters::
            leafer (Noncer): instance encoding of leaf info said which said is
                            digest of actual leaf information. leafer may use
                            a different digest code from .code.
                            Thus a siter is compatible with all external leaf
                            info saids while ensuring for security reasons that
                            all its internal leaf limbs, leaf saids, and node saids
                            use the same digest algorithm give by .code.


        """
        # setup for ._insert
        leaf = self.leafFromLeafer(leafer)
        if self.hasLeaf(leaf.said):
            return None  # already inserted

        # start at root (values as matter primitives) raise error if ._insert fails
        try:
            self.root = self._insert(leaf, self.root)  # new root with inserted leaf
        except ValueError as ex:
            return None
        self.pinLeaf(leaf.said, leaf.part)  # add leaf
        self.infos[leaf.part.limb.qb64] = leafer.qb64  # add ref to leafer to infos
        return leaf



    def _insert(self, leaf, node):
        """Recursive inset of leafer starting at node. Descends tree until finds
        bottom node the recursively climbs back up tree up updating node saids
        as it climbs.  Values are Matter instances


        Returns::
            new (Partage): instance (said, part) of new updated node replacing
                           old node where recursive ._insert began where:
                           said is Noncer instance of node said
                           part is Nodage instance with Matter instance values

        Parameters::
            leaf (Partage): instance (said, part) of leaf to be inserted where:
                            said is leaf said Noncer instance
                            part is Leafage of leaf with Matter instance values

            node (Partage): instance of (said, part) as part of tree to
                            begin/resume recursive insert where:
                            said is node said Noncer instance
                            part is Nodage of node with Matter instance values


        Logic:
            leaf can only attach to child of node on side given by bit in leaf
            limb which bit is located below (greater than) the node span.
            This leaves room for one more nodes to interposed either above or
            below the node to which a leaf is attached. The key is that the
            limb of a given node is set by the deepest common span of its
            child leaves (node and/or leaf). This leaves gaps in the tree where
            virtual missing nodes with empty children would have been. We can
            call these ghost nodes. As long as the gaps between non-ghost nodes
            are stable the ghost nodes themselves do not need to be hashed/digested

            Becaause each node and leaf said is computed over its limb, there
            is no malleability in structure wrt the said (digest/hash) of a node
            or leaf. This prevents a collision attack from missing virtual
            empty nodes. As new leaves are added the new node
            fork created to accomodate the leaf may interpose either above or
            below an existing node. A given node's limb once set remains, but its
            children may change as new leafs and nodes to accomodate the leaves
            are added. The rules for forking nodes are designed to ensure the
            essential property that that same set of nodes no matter the order of
            insertion results in the same root said (digest/hash)

            When a new leaf causes a new fork to be interposed above an existing
            node, the existing node's said does not change. This means saids
            lower in that subtree remain stable. So the only hashes (saids) that
            change are above it in its given branch.  The limb of the new node
            is always set to the deepest common span of its children. This
            leaves a stable gap for any missing ghost nodes above it in the tree.


            When a new leaf causes a new fork to be interposed below  existing
            node then the existing nodes above it must change their saids but
            the nodes below the new node do not. In order for a fork to be
            inserted below a node, the leaf must itself fit below that node.
            The new node always has a limb value that is set to the deepest
            common span of its children. This creates a stable gap for the
            missing ghost nodes.

            Creating stable gaps for missing ghost nodes supports the required
            property of a sparse Merkle tree, that is, that the order of insertion
            of its leaves does not change the final node structure.
            A leaf can only go in one place.

            The act of fixing node limbs, fixes their relative place in the tree.
            The infil above protects the tructure below so new leaves go to the
            same place in the tree no matter the order of insertion.

            This means that when inserting or removing a leaf, the number of
            hashes to update the root is only the depth of real nodes from leaf
            to root not 256 like other sparse merkle trees.  The number of nodes
            in a SIT is log2(L)  where L is the number of leaves inserted.
            This differs from other sparse Merkle trees where the number of
            hashes is log2(M) where M is the maximum number of leaves the tree
            can hold.

            A non optimized SMT merge with precomputed empty nodes for each
            height of the tree of height 256. The Jellyfish SMT collapses
            a single leaf on an empty subtree up to one node holding the subtree
            so its only one hash for the subtree (this skipping hashes that are
            the height of the subtree). Jellyfish however expands all ancester
            nodes on the branch above any node with two non-empty children.
            This makes the average depth a worst case for dense leaf key spaces
            such as sequential leaf keys.

            Nervos, is similar to Jellyfish in that is skips hashes by merging
            non empty nodes upto the highest node with two non-empty children.
            Unlike jellyfish, however, Nervos stores the key prefix with each
            node so that it does not have to expand the ancestors of nodes with
            non-empty children. Any leaf can compare the node prefix to its key
            to skip empty sub-trees between real nodes (those with two non-empty
            children).
            SIT is therefore most similar to Nervos but has simpler logic.
            Whereas SIT builds the tree from the top down and stretches the node
            space to hold leaves. Nervos walks the leaf from the bottom up merging
            virtual nodes until if finds the place to fill in. They end up in
            the same place but Nervos logic is more convoluted. Nervos iterates
            up to 256 times to merge up. Whereas SIT only iterates the number
            of nodes it encounter on the way down. Which is always about
            log2(L) of the number of real leaves.

            Moreover the security of SIT is stronger since in SIT the key prefix
            (limb in SIT) of each real node (i.e. two non-empty children) is
            also hashed with the node, not just for the leaves. This better partitions
            the hash input space (partitioned input space better follows the
            Efficient Sparse Merkle Tree security policy to increase collison
            resistance)

            SIT (and Nervos) stretch the nodes space by filling in or filling out
            nodes as needed. The fill in/out is both above and below existing nodes
            Thus the node space is stretched to fit the leaves.

            SIT starts with a fully shrunken node key space upon insert of a leaf
            while the Nervos logic re-shrinks the node key space upon insert of
            a leaf.

            Because SIT (and Nervos) never expand ancestor nodes of nodes with
            two non-empty childen the number of nodes is always 1 less than
            the number of leaves (except for the corner case where the root has
            one or two empty leaves). This enables the average depth in SIT (Nervos)
            to approach the minimal node depth = log2(L) where L is the number
            of real leaves. Whereas because Jellyfish and other similar algorithms
            expand all nodes above nodes with two non-empty children, the average
            depth is always greater. And sequential keys that lay at bottom
            elevations exponentially explode the average depth. This creates
            a worst case for dense key spaces. Thus the radix compression in
            Jellyfish solves a problem of its own making.
            A problem that SIT does not have.

            To clarify, because SIT shinks the node space to fit the leaf key space,
            even dense leaf key spaces at the botoom elevations do not significantly
            increase the overall average depth beyond that of the average depth
            of the dense sub tree itself as measured from the top of the dense
            subtree not from the top of the full tree. Whereas in algos that
            expand ancestors, the overall average depth is exploded by the
            distance from the top of the tree to the top of the dense sub tree
            at the bottom elevations.

            The shrinking of node key space by SIT (not expanding ancestors)
            minimizes the number of hashes needed for inclusion/exclusion proofs
            becasue the average number of hashes for inclusion/exclusion proofs
            is a function of the average depth of leaves which approaches
            log2(L) where L is the number of real leaves.
        """
        # Walk leaf down appropriate node child branch.
        # assumes node limb is prefix of leaf limb. leaf fits below node.
        # Root limb is empty so always prefix of any leaf limb. leaf fits below root.
        # figure out which side of node, leaf must go
        if self.rightAtSpanInt(leaf.part.limb.num, node.part.span.num + 1):  # go right
            side = True  # set side to right
            # get child on right
            childer = node.part.right   # empty or leaf saider or node saider
        else:  # go left
            side = False  # set side to left
            # get child on left
            childer = node.part.left  # empty or leaf saider or node saider

        if not childer.nonce:  # child is empty (should only happen at root node)
            # attach leaf to side of node, update node and return
            if node.part.span.num != 0:  # not root
                raise ValueError(f"Invalid node={node.said.qb64}, not root "
                                 f"but empty child on {side=}")
            # remove, replace, and return updated node with new child on side
            return self.updateNode(node, leaf.said, side=side)

        if (leafage := self.getLeaf(childer)) is not None:  # child is leaf
            # fork node on side.  set limb of new node to common span before
            # shallowest diff and put leafs on side at diff bit at common span +1
            # update node and return
            child = Partage(childer, leafage)  # make child
            # need to updage forkNode to use common limb not just extension
            return self.forkNode(node, left=leaf, right=child, side=side)


        if (nodage := self.getNode(childer)) is not None:  # child is node
            #  walkdown means span of limb of node is longer than common span
            #  between node and leaf
            # if can walk down on side:
            #          recurse with with child node on side
            # else: cannot walk down past child node:
            #          fork  between node and its child node on side.
            #                above child node and below node.
            #          fork at shallowest span diff of leaf and child node on side
            #          child node should stay on same side of new fork node as it
            #          was on node and leaf should go on other side of new fork node
            #          check if swap says otherwise
            #          update node and return
            #
            child = Partage(childer, nodage)  # make child

            if not self.fitLeafNode(leafer=leaf.part.limb,
                                    noder=child.part.limb,
                                    spanner=child.part.span):  # cannot walk down
                # leaf cannot recurese down child node path
                return self.forkNode(node, left=leaf, right=child, side=side)

            # can recurse down child so recurse
            child = self._insert(leaf=leaf, node=child)  # recursion updates child
            # remove, replace, and return updated node with new child on side
            return self.updateNode(node, child.said, side=side) # right

        raise ValueError(f"Should never get here")


    def trace(self, terse=True, leafive=True):
        """Returns list of leaves in depth first search order.
        Children firt left then right.

        Returns:
            result (tuple): of form (leaves, metrics) where:
                            leaves (list); str rep in depth first order.
                                should be lexocrographic by leaf limb
                                Each entry leaf limb with branch of node twigs
                                and leaf depth = # nodes in branch including root

                            metrics (dict):  of leaves  with fields:
                                depthmax (int): maximum depth among leaves
                                depthmin (int): minimum depth among leaves
                                depthsum (int): sum of leaf depths for depthave
                                depthave (float): average depth for L leaves
                                leafcount (int): count of leaves

        Parameters:
            terse (bool): True means leaf limb and node twig in string are
                            represented as 8 bits of binary for debugging
                          False means leaf limb and node twig in string are
                            represented in hex
            leafive(bool):  True fill leaves list (default)
                             False do not fill leaves list

        """
        leaves = []  # mutable holds leaves in depth first search order
        branch = deque()  # mutable nodes on a given branch to leaf
        branch.appendleft(self.root)
        metrics = dict(depthmax=0, depthmin=0, depthsum=0, depthave=0.0, leafcount=0)  # mutable of leves
        self._trace(self.root, leaves, branch, metrics, terse=terse, leafive=leafive)
        if metrics['leafcount']:
            metrics['depthave'] = metrics['depthsum'] / metrics['leafcount']
        return (leaves, metrics)


    def _trace(self, node, leaves, branch, metrics, terse=True, leafive=True):
        """Recursive descent depth first trace starting at node to find attached
        leaves where chidren are searched first left then right

        Each entry is tuple of (leaf limb, node limb MSb)

        Parameters:
            node (Partage): instance of node at current level of trace
                            has Matter instance values
            leaves (list): append leave as encountered via depth first traversal
                           mutable so can update via recursive calls
            branch (deque): nodes in current branch to leaf
                           mutable so can update via recursive calls
            metrics (dict):  fields are metrics
                            mutable so can update via recursive
                                depthmax (int): maximum depth among leaves
                                depthmin (int): minimum depth among leaves
                                depthsum (int): sum of leaf depths for depthave
                                depthave (float): average depth for L leaves
                                leafcount (int): count of leaves
            terse (bool): True means leaf limb and node twig in string are
                            represented as 8 bits of binary for debugging
                          False means leaf limb and node twig in string are
                            represented in hex
            leafive(bool):  True fill leaves list (default)
                             False do not fill leaves list


        """
        depth = len(branch)
        lefter = node.part.left
        side = 'left'
        if leafive and not lefter.nonce:  # left leaf empty
            leaves.append(f"{side}#{depth}=empty@{self._showtwig(node, terse=terse)}")

        elif (leafage := self.getLeaf(lefter)) is not None: # left leaf
            if leafive:
                shows = '@'.join(self._showtwig(n, terse) for n in branch)
                if terse:
                    #size = min(leafage.span.num, 16)
                    leaves.append(f"{side}#{depth}={(leafage.limb.num>>248):08b}@{shows}")
                else:
                    leaves.append(f"{side}#{depth}={leafage.limb.numh}@{shows}")
            metrics['depthsum'] += depth
            if depth > metrics['depthmax']:
                metrics['depthmax'] = depth
            if metrics['depthmin'] == 0 or metrics['depthmin'] > depth:
                metrics['depthmin'] = depth
            metrics['leafcount'] += 1

        else: #left node so recurse
            nodage = self.getNode(lefter)
            child = Partage(lefter, nodage)
            branch.appendleft(child)
            self._trace(child, leaves, branch, metrics, terse, leafive)
            branch.popleft()


        righter = node.part.right
        side = "right"
        if leafive and not righter.nonce:  # right leaf empty
            leaves.append(f"{side}#{depth}=empty@{self._showtwig(node, terse=terse)}")

        elif (leafage := self.getLeaf(righter)) is not None: # right leaf
            if leafive:
                shows = '@'.join(self._showtwig(n, terse) for n in branch)
                if terse:
                    #size = min(leafage.span.num, 16)
                    leaves.append(f"{side}#{depth}={(leafage.limb.num>>248):08b}@{shows}")
                else:
                    leaves.append(f"{side}#{depth}={leafage.limb.numh}@{shows}")
            metrics['depthsum'] += depth
            if depth > metrics['depthmax']:
                metrics['depthmax'] = depth
            if metrics['depthmin'] == 0 or metrics['depthmin'] > depth:
                metrics['depthmin'] = depth
            metrics['leafcount'] += 1

        else: #right node so recurse
            nodage = self.getNode(righter)
            child = Partage(lefter, nodage)
            branch.appendleft(child)
            self._trace(child, leaves, branch, metrics, terse, leafive)
            branch.popleft()



    def _showtwig(self, node, terse=True):
        """Create string of node twig for trace display purposes

        Returns:
            show (str):  string representation of node twig modified by terse

        Parameters:
            node (Partage): instace whose values are Matter primitive instances
            terse (bool):  True means compact display in bits may cut off longer twigs
                           False means full display in hex
        """
        if (twig := self.twigAtSpanInt(node.part.limb.num, node.part.span.num)) is not None:
            if terse:
                size = min(node.part.span.num, 8)
                show = f"{twig:0{size}b}"
                if size < node.part.span.num:
                    show += "..."
            else:
                show = node.part.limb.numh

        else:
            show = f"root"

        return show

    def shake(self, node):
        """Returns list of leaves from recursive descent traveral of tree attached
        to node.

        Useful for consistency testing of leaves in tree vs. leaves in database
        """


    def _shake(self, node, leaves):
        """Recursive depth first traversal of tree attached to node.
        Populates leaves list with leaves as encountered in traversal
        """
