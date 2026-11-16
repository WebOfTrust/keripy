# -*- encoding: utf-8 -*-
"""
keri.smt.psmting module

Package level shared constants, functions, classes, errors etc

"""
from collections import namedtuple

from .. import Versionage, InvalidCodeError
from ..core import (MtrDex, DigDex, NonceDex, Noncer,  Ilker, Diger, Number)
from ..help import intToB64

Version = Versionage(major=0, minor=0)
MaxDepth = 256 # 256 bits or forks == limb span
MaxDepthBytes = 32  # MaxDepth in bytes equivalent

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
        saided data = kith+tuid+saiddummy+depth+limb+left+right
    depth is Number instance encoding 2 byte int of depth of node
    limb is Diger instance encoding of 256 bit branch path to node with MSbits
        == depth == limb span
    left is Noncer instance encoding said of left child (node, leaf or empty)
    right is Noncer instance encoding said of right child (node, leaf or empty)
"""
NodeSaidage = namedtuple("NodeSaidage", "kith tuid said depth limb left right")

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
        saided data = kith+tuid+saiddummy+depth+limb
    depth is Number instance encoding 2 byte int of potential depth of leaf
        leaf depth is always MaxDepth 256
    limb is Diger instance encoding of 256 bit branch path to leaf with MSbits
        == 256 == MaxDepth == limb span
        limb calculated on leaf info said using tree specific digest code so
        limb inhabits same hash space as all other parts of tree.
        Leaf info said may use different digest algo from tree wide digest algo.
        Because limb makes secure committment to leaf info there is no security
        need to store leaf info said per leaf. It may be stored in separate
        field map indexed by limb for convenience.
       """
LeafSaidage = namedtuple("LeafSaidage", "kith tuid said depth limb")

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
    depth is Number instance NumDex.Short encoding 2 byte int node depth
    limb is Diger instance encoding the 256 bits of which the MS (big endian)
        depth bits provide the child forks to node. Depth == limb span MSbits
    left is Noncer instance of left child's Saidage:
        node or leaf or empty (only root node children can be empty)
    right is Noncer instance of right child's Saidage:
        node or leaf or empty (only root node children can be empty)
"""
Nodage = namedtuple("Nodage", "depth limb left right", defaults=(EmptyQb2, EmptyQb2))

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
    depth is Number instance NumDex.Short encoding 2 byte int leaf depth.
        The leaf depth is always MaxDepth == 256
    limb is Diger instance encoding the 256 bits (big endian) of potential
        child forks to leaf. All 256 bits are meaningful but for any leaf attached
        to a given node only the MS node depth+1 are used to address that leaf
        The limb digest is computed on leaf infos said which said is bound to
        actual leaf info. The info said algo may differ from the tree wide algo
        used to compute node and leaf saids.
"""
Leafage = namedtuple("Leafage", "depth limb")

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
    def extendLimbInt(limb, span=0, side=False):
        """Extends limb  of span (depth) using  bit value given by right and
        returns new limb extended by 1 bit.  Uses int values not Matter instances

        Returns:
            result (tuple): (limb, span) where:
                            limb is extended limb with span+1 MSbits. All other bits
                                masked to 0s.
                            span is span+1

        Parameters:
            limb (int): 256 bit limb path with span MSbits to be extended
            span (int): span (depth) of limb 0-255 MSbits
            side (bool): True means extend with 1 (right child bit)
                         False means extend with 0 (left child bit)

        Usage::
            given limber as Diger instance of limb
            given spanner as Number instance of depth

            limb = Sider.extendLimbInt(limb=limber.num),
                                       span=spanner.num)

            or

            limb = Sider.extendLimbInt(limb=limber.num),
                                       span=spanner.num,
                                       right=True)

            limber = Diger(raw=limb.to_bytes(MaxDepthBytes))
            depther = Number(num=depther.num+1)
        """
        if span >= MaxDepth:
            raise ValueError(f"Invalid {span=} greater than MaxDepth")

        mask = ((1 << span) - 1)  # mask of 1s of length span
        limb = (limb >> (MaxDepth - span)) & mask
        limb = limb << 1  # extend with zero
        if side:
            limb |= 1  # make lsb 1
        span += 1
        return (limb << (MaxDepth - span), span)


    @staticmethod
    def extendLimb(limber, spanner, side=False):
        """Extends limber of span spanner with bit value given by left and
        returns tuple of (limber, spanner) where:
            limber extended by 1 bit and
            spanner incremented by 1.

        Returns:
            result (tuple): of form (limer, spanner) where:
                            limber is Diger instance of extended limb
                            spanner is Number instance of incremented span

        Parameters:
            limber (Diger): instance encoding 256 bit limb path with span MSbits
                            to be extended
            spanner (Number): instance encoding limb span MSbits [0..255]
            side (bool): True means extend with 1 (right child bit)
                         False means extend with 0 (left child bit)

        Usage::
            given limber as Diger instance of limb
            given spanner as Number instance of depth

            limber, spanner = Sider.extendLimb(limber=limber, spanner=spanner)

            limber, spanner = Sider.extendLimb(limber=limber,
                                               spanner=spanner,
                                               right=True)
        """
        code = limber.code  # save to recreate
        limb = limber.num
        span = spanner.num
        limb, span = Siter.extendLimbInt(limb=limb, span=span, side=side)
        limber = Diger(raw=limb.to_bytes(MaxDepthBytes), code=code)
        spanner = Number(num=span)
        return (limber, spanner)


    @staticmethod
    def rightAtSpanInt(limb, span):
        """Returns which side of limb at span (depth) where:
        True is right and False is left
        Usually applied to leaf limbs so uses leaf convention:
        Convention MSb at span 1 and LSb at span 256.
        Minimum leaf depth is 1 and maximum is 256.
        span is how many bits into limb either node or leaf.
        A leaf is always attached as a child of a parent node. The leaf child
        side is determined by bit position in leave limb that must be greater
        that span of parent node's span = parent nodes depth.

        Returns:
            side (bool): False if bit at span is  0 (side is left)
                         True if bit at span is 1 (side is right)

        Parameters:
            limb (int): 256 bit int where MSbits are forks (0 left, 1 right)
            span (int): get bit at span (depth) where:
                            span = 1 is MSb of limb
                            span = 256 is LSb of limb
        """
        if span <= 0:
            raise ValueError(f"Invalid {span=} <= 0>")

        return True if (limb >> (MaxDepth - span) & 1) else False


    @staticmethod
    def rightAtSpan(limber, spanner):
        """Returns which side of limber at spanner where:
        True is right and False is left
        where limber and spanner are Matter primitives.
        Wrapper around Siter.rightAtSpanInt
        Convention MSb at span 1 and LSb at span 256.
        Minimum leaf depth is 1 and maximum is 256.

        Returns:
            side (bool): False if bit at depth is  0 (side is left)
                         True if bit at depth is 1 (side is right)

        Parameters:
            limber (Diger): instance .num is 256 bit int where MSbits
                            are forks (0 left, 1 right)
            depther (Number): instane .num is depth where:
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
        return ((limb >> (MaxDepth-span)) & mask)


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
        """Determines if node limb twig of size span=depth is prefix of leaf limb
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
        for span in range(1, 256):
            leftbit = (left >> (MaxDepth - span)) & 1
            rightbit = (right >> (MaxDepth - span)) & 1
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
        # depth is 0, limb is all zeros, left is empty, right is empty
        rootage = Nodage(depth=Number(num=0),
                         limb=Diger(raw=bytes(MaxDepthBytes), code=self.code),
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
                              depth=nodage.depth,
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
        nodage = Nodage(depth=nodage.depth.qb2,
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
        nodage = Nodage(depth=nodage.depth.qb2,
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
            nodage = Nodage(depth=Number(qb2=nodage.depth),
                            limb=Diger(qb2=nodage.limb),
                            left=Noncer(qb2=nodage.left),
                            right=Noncer(qb2=nodage.right))
        return nodage


    def isNode(self, saider):
        """Given said returns True if said belongs to node, False otherwise
        Checks for presence in .nodes and that 0 <= depth < MaxDepth

        Returns::
            result (bool):  True means said given by saider corresponds to leaf
                            False otherwise
        """
        if (nodage := self.getNode(saider)) is not None:
            if 0 <= nodage.depth.num < MaxDepth:
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
                              depth=leafage.depth,
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
        leafage = Leafage(depth=leafage.depth.qb2,
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
        leafage = Leafage(depth=leafage.depth.qb2,
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
            leafage = Leafage(depth=Number(qb2=leafage.depth),
                              limb=Diger(qb2=leafage.limb))
        return leafage


    def isLeaf(self, saider):
        """Given said returns True if said belongs to leaf, False otherwise
        Checks for presence in .leaves and that depth is MaxDepth

        Returns::
            result (bool):  True means said given by saider corresponds to leaf
                            False otherwise
        """
        if (leafage := self.getLeaf(saider)) is not None:
            if leafage.depth.num == MaxDepth:
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



    def forkNode(self, node, lefter, righter, side=False):
        """Attach new forking node to right/left side of node with

        Parameters:
            node (Partage): instance (said, part) of node where:
                            said is Noncer instance of node said
                            part is Nodage instance with Matter instance values
            lefter (Noncer): instance of left child said for new forking node
            righter (Noncer): instance of right child said for new forking node
            side (bool):  False is left side
                          True is right side

        Returns:
            nodepartage (Partage): instance (said, part) where:
                            said is qb2 of node
                            part is Nodage instance with qb2 values
                            old and new provide left and right as appropriate

        """
        # create new forking node of lefter and righter
        # extend limb of node on side given by side
        limber, spanner = self.extendLimb(node.part.limb, node.part.depth, side=side)
        # create nodage of new forking node
        nodage = Nodage(depth=spanner, limb=limber, left=lefter, right=righter)
        saider = self.sayNode(nodage)  # update said of forking node
        self.pinNode(saider, nodage)  # update .nodes with forking node
        return self.updateNode(node, saider, side=side)

    def leafFromLimber(self, limber):
        """Create leaf to insert from limber. Computes leaf limb and said.

        Returns::
            leaf (Partage): instance (said, part) where:
                            said is Noncer instance generated from leafage
                            part is Leafage instance with Matter instance values
                                depther is Number 256 and limb from limber

        Parameters::
            limber (Noncer): instance only per leaf unique value used to generate
                             leafage and then said of leaf
        """
        leafage = Leafage(depth=Number(num=256), limb=limber)
        saider = self.sayLeaf(leafage)  # compute leaf said
        return Partage(said=saider, part=leafage)  # matter primitives


    def leafFromLeafer(self, leafer):
        """Create leaf to insert from leafer. Computes leaf limb and said.

        Returns::
            leaf (Partage): instance (said, part) where:
                            said is Noncer instance generated from leafage
                            part is Leafage instance with Matter instance values
                                depther is Number 256 and limb from limber

        Parameters::
            leafer (Noncer): instance only per leaf unique value of said of info
                             used to generate limber which is then used to
                             generate leafage then used to generate said of leaf
        """
        limber = Noncer(ser=leafer.raw, code=self.code)  # limb for leaf
        return self.leafFromLimber(limber)


    def insert(self, leafer):
        """Inser leafer idempotently

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

        #limber = Noncer(ser=leafer.raw, code=self.code)  # limb for leaf
        #leaf = self.leafFromLimber
        ## Setup for insert
        ## make leafage from limber
        #leafage = Leafage(depth=Number(num=256), limb=limber)
        #saider = self.sayLeaf(leafage)  # compute leaf said
        #leaf = Partage(said=saider, part=leafage)  # matter primitives

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
            limb which bit is located above the node depth. This leaves room
            for one more nodes to interpose allowing leaf to rebalance to move
            to correct child of interposed node. If leaf limb side bit does not
            exactly match side at depth+1 of node  to which it is attached then
            there is no way to move it later to rebalance. Consequently leaves
            attached to root must always attach to side given by bit at depth=1
            in leaf limb (zero based bit index 0 from left, bit index 255 from right,
            This means that one side of the root may remain empty always until
            a leaf is inserted whose depth 1 bit matches the empty side.
            This means that logic for attaching leaf to empty root is simple.
            Just attach to side given by depth 1 limb bit. Root at depth 0.

        """
        leftIsUnfit = False  # keep track when we have  already found left unfit
        rightIsUnfit = False  # keep track when we have already find right unfit

        if not node.part.left.nonce:  # left child is empty (only if root)
            leftIsUnfit = True
            if node.part.depth.num != 0:  # not root
                raise ValueError(f"Invalid node={node.said.qb64}, not root "
                                 f"but empty left child")

            # see if leaf will attach on empty left child of root
            # if leaf side at depth 1 is left then attach to left child of root
            if not self.rightAtSpanInt(leaf.part.limb.num, 1):  # left it is
                # remove, replace, and return updated node with new left child
                return self.updateNode(node, leaf.said, side=False) # left

        if not node.part.right.nonce:  # right child is empty (only if root)
            rightIsUnfit = True
            # should only happen if node is root
            if node.part.depth.num != 0:  # not root
                raise ValueError(f"Invalid node={node.said.qb64}, not root "
                                 f"but empty right child")

            # see if leaf will attach on empty right child of root
            # if leaf side at depth 1 is right then attach to right child of root
            if self.rightAtSpanInt(leaf.part.limb.num, 1):  # right it is
                # remove, replace, and return updated node with new right child
                return self.updateNode(node, leaf.said, side=True) # right

        if (nodage := self.getNode(node.part.left)): # left child is a node
            leftIsUnfit = True
            # see if leaf belongs on left side of node when left child is node
            if self.fitLeafNode(leaf.part.limb, nodage.limb, nodage.depth):
                # fits so walk down one
                # recurse with left child node as new node
                child = self._insert(leaf, Partage(node.part.left, nodage))
                # remove, replace, and return updated node with new left child
                return self.updateNode(node, child.said, side=False) # left


        if (nodage := self.getNode(node.part.right)): # right child is a node
            rightIsUnfit = True
            # see if leaf belongs on right side of node when right child is node
            if self.fitLeafNode(leaf.part.limb, nodage.limb, nodage.depth):
                # fits so walk down one
                # recurse with right child node as new node
                child = self._insert(leaf, Partage(node.part.right, nodage))
                # remove, replace, and return updated node with new right child
                return self.updateNode(node, child.said, side=True) # right


        """Logic
        When we get here when any side that is a node or empty must be
        unfit seen we have checked boths sides for fit node or empty.
        we track which sides are unfit with leftIsUnfit and rightIsUnfit
        Therefore when we get here we must then do leaf rebalancing logic
        an unfit empty on a side means that the root node child does not
        fit the leaf limb at depth so the leaf must go on other side.
        an unfit node on a side means that the node twig on that side does
        not fit the leaf limb at depth so leaf must go on other side.
        by construction the left and right children of a node can not both be
        unfit as any leaf must match one side or the other be it leaf or node.

        Cases:

           a) right is unfit so left is leaf
           b) left is unfit so right is leaf
           c) neigther right nor left are unfit so both must be leaves
        """

        if rightIsUnfit:  # case a) right unfit, left child is leaf to be forked
            """Logic
            left child is leaf so add node fork on left with old left and
            new leaf as children.  Balance fork so each leaf is on correct side
            """
            # get left child leaf
            if (leafage := self.getLeaf(node.part.left)) is None:
                raise ValueError(f"Missing left leaf at said={node.part.left.qb64} of "
                                 f"node at said={node.said.qb64}")
            child = Partage(node.part.left, leafage)

            # compare limbs of leaf with left child. Raises error if same limb
            spanner, swap = self.forkSpanSwap(lefter=child.part.limb,
                                              righter=leaf.part.limb)
            side = False  # extend limb on left side of node
            # if swap: leaf needs to be on left side of fork, child on right
            # else: leaf needs to be on right side of fork, child on left
            lefter = leaf.said if swap else child.said
            righter = child.said if swap else leaf.said
            return self.forkNode(node, lefter=lefter, righter=righter, side=side)

        if leftIsUnfit:  # case b) left unfit, right child is leaf to be forked
            """Logic
            right child is leaf so add node fork on right with old right and
            new leaf as children.  Balance fork so each leaf is on correct side
            """
            # get right child leaf
            if (leafage := self.getLeaf(node.part.right)) is None:
                raise ValueError(f"Missing right leaf at said={node.part.right.qb64} of "
                                 f"node at said={node.said.qb64}")
            child = Partage(node.part.right, leafage)

            # compare limbs of leaf with right child. Raises error if same limb
            spanner, swap = self.forkSpanSwap(lefter=leaf.part.limb,
                                              righter=child.part.limb)

            side = True  # extend limb on right side of node
            # if swap: child needs to be on left side of fork, leaf on right
            # else: child needs to be on right side of fork, leaf on left
            lefter = child.said if swap else leaf.said
            righter = leaf.said if swap else child.said
            return self.forkNode(node, lefter=lefter, righter=righter, side=side)

        # case c) both children leaves
        """Logic
        both children are leaves so add on best side a node fork of new leaf
        and prior leaf as children.
        Balance fork so each leaf is on correct side of new node.
        Best side to fork is where leaves new and prior first differ at
        the deeper depth. This avoids adding fork that doesnt have enough
        limb bits to fit between old node and it leaves.
        Difference depth on both sides cannot be the same since
        """
        # get both leaves of node
        # get left child leaf
        if (leafage := self.getLeaf(node.part.left)) is None:
            raise ValueError(f"Missing left leaf at said={node.part.left.qb64} of "
                             f"node at said={node.said.qb64}")
        leftChild = Partage(node.part.left, leafage)

        # get right child leaf
        if (leafage := self.getLeaf(node.part.right)) is None:
            raise ValueError(f"Missing right leaf at said={node.part.right.qb64} of "
                             f"node at said={node.said.qb64}")
        rightChild = Partage(node.part.right, leafage)

        # find depth where left and right child differ
        spannerChild, swapChild = self.forkSpanSwap(lefter=leftChild.part.limb,
                                                    righter=rightChild.part.limb)
        if swapChild:
            raise ValueError(f"Misplaced children")

        # compare limbs, leaf with leftChild. Raises error if same limb
        spannerLeft, swapLeft = self.forkSpanSwap(lefter=leftChild.part.limb,
                                                  righter=leaf.part.limb)

        # compare limbs, leaf with rightChild. Raises error if same limb
        spannerRight, swapRight = self.forkSpanSwap(lefter=leaf.part.limb,
                                                    righter=rightChild.part.limb)
        if spannerLeft.num == spannerRight.num:
            pass

        if spannerLeft.num > spannerRight.num:  # leaf and left have deeper fork depth
            # replace left child with new forking node of leaf and old left child
            side = False  # extend limb on left side of node
            if swapLeft:  # leaf needs to be on left side of fork
                lefter = leaf.said
                righter = leftChild.said
            else:  # leaf needs to be on right side of fork
                lefter = leftChild.said
                righter = leaf.said

        elif spannerLeft.num < spannerRight.num:  # leaf and right have deeper fork depth
            # replace right child with new forking node of leaf and old right child
            side = True # extend limb on right side of node
            if swapRight:  # leaf needs to be on right side of fork
                lefter = rightChild.said
                righter = leaf.said
            else:  # leaf needs to be on left side of fork
                lefter = leaf.said
                righter = rightChild.said

        return self.forkNode(node, lefter=lefter, righter=righter, side=side)


    def trace(self):
        """Returns list of leaves in depth first search order.
        Children firt left then right.

        Each entry is string with leaf limb at node twig MSb)
        """
        leaves = []  # mutable will fill in as it traces
        self._trace(self.root, leaves)

        return leaves


    def _trace(self, node, leaves):
        """Recursive descent depth first trace starting at node to find attached
        leaves where chidren are searched first left then right

        Each entry is tuple of (leaf limb, node limb MSb)
        """
        limb = node.part.limb.num
        span = node.part.depth.num
        if (twig := self.twigAtSpanInt(limb, span)) is not None:
            showtwig = f"{twig:0{span}b}"
        else:
            showtwig = f"root"

        lefter = node.part.left
        if not lefter.nonce:  # left leaf empty
            leaves.append(f"left: empty @ {showtwig}")
        elif (leafage := self.getLeaf(lefter)) is not None: # left leaf

            leaves.append(f"left: {(leafage.limb.num>>248):08b} @ {showtwig}")
        else: #left node so recurse
            nodage = self.getNode(lefter)
            self._trace(Partage(lefter, nodage), leaves)

        righter = node.part.right
        if not righter.nonce:  # right leaf empty
            leaves.append(f"right: empty @ {showtwig}")
        elif (leafage := self.getLeaf(righter)) is not None: # right leaf
            leaves.append(f"right: {(leafage.limb.num>>248):08b} @ {showtwig}")
        else: #right node so recurse
            nodage = self.getNode(righter)
            self._trace(Partage(righter, nodage), leaves)



