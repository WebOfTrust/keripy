# -*- encoding: utf-8 -*-
"""
keri.sit.siting module

Siter functionality

"""


from collections import namedtuple, deque

from .. import Versionage, InvalidCodeError
from ..core import (MtrDex, DigDex, NonceDex, Noncer,  Ilker, Diger, Number)
from ..help import intToB64

from .parting import Kiths, NodeSaidage, Nodage, LeafSaidage, Leafage, Partage

Version = Versionage(major=0, minor=0)
MaxSpan = 256 # 256 bits or forks == leaf limb span
MaxSpanBytes = 32  # MaxSpan in bytes equivalent


class Siter:
    """Siter manages a SAIDed Info Tree (SIT) that implements a compact optimized
    sparse Merkle tree compatible with the KERI CESR cryptographically agile
    serializations.

    Provides the property that the same set of leaves results in the same root
    said (hash digest).

    Uses node space stretching technique so that the number of nodes is always
    the theoretical minimum (1 less than the number of leaves except for the case
    where a root node as one or two empty leaves)

    This node space stretching also ensures that the average depth of leaves int
    the tree approaches the theoretical minimum of log2(L) where L is the number
    of leaves. This maximizes performance by minimizing the number of hashes
    (digest operations) and reads for inclusion/exclusion proofs. This is
    particularly beneficial when the leaf key space is dense at low elevations
    as is the case for sequential keys.

    Each new leaf effectively stretches the node space as needed to fill in/out
    the new leaf. Once a node is created is stays in place and other nodes
    are inserted above it or below it in order to hold new leaves. A given
    set of leaves no matter the order of insertion always produces the same
    root said (hash, digest), thus preserving the most important property of
    a sparse Merkle tree.

    Except for the root node, all real nodes have two non-empty children.
    Thus the number of nodes is always 1 less than the number of leaves
    (except when the root has one or more empty leaves). This minimizes the
    number of real nodes to its theoretical limit.

    The keys or indices for each leaf is called its limb. All limbs
    are of length MaxSpan (256). Each node also has a limb whose span is less
    than MaxSpan. Thus any node limb is a prefix to some set of potential
    leaf limbs. The node's limb and span is stored along with its children's
    limbs.

    A new leaf is inserted by climbing down a branch where at each fork
    the leaf follows child nodes whose limb is a prefix of the leaf and if
    not then creates a new forking node to accomodate the leaf.

    When the leaf hits child node with a non-matching prefix then a new
    forking node is inserted above the non-matching node and below the parent
    node of the non-matching node. The new forking node's prefix is set to
    the maximally length common span of the new leaf's limb and the old
    non-matching node's limb. The children of the new forking node are the
    leaf and the old node attached at the appropriate child as determined
    by the bit where their limbs differ. The new forking node replaces the
    old node as a child of the prior partent node.

    When the leaf hits a child leaf attached to a node, then a new forking
    node is created whose prefix is the common span of both leaves. The
    new forking node replaces the old child leaf as the parent node's child
    and the two leaves are attached at the appropriate child as determined by
    the bit where their limbs differ.

    The insert logic is elegantly simple. The tree streches by adding new
    nodes between existing nodes as needed to fit leaves without expanding
    any branches with nodes with one or more empty children. Because each
    node includes its prefix, its position within the virtual sparse Merkle
    tree is fixed. Nodes with different prefixes are placed above or below it.
    This lack of ancestor expansion means that the average depth for any
    given set of leaves is always minimized and for uniformly distributed
    leaf limbs (keys) the average depth always approaches the theoretical
    minimum of log2(L) where L is the number of inserted leaves.  Stretching
    without ancestor expansion means that dense subtrees such as subtrees
    with sequential leaf limbs (keys) that reside at the bottom of the
    leaf limb (key) space, do not explode the average depth of the whole tree.

    Thus the second important property of a SIT is that the number of hashes
    and/or database reads to verify an inclusion/exclusion proof for a leaf
    is always about log2(L) where L is the number of leaves. The maximizes
    performance for the most common operations.


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

    ToDo: XXXX change .nodes, .leaves, and .infos to have virtual interface
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


    @staticmethod
    def verify(proof, kind=True, root=None, leaf=None):
        """verify proof (inclusion/exclusion) with root said for leaf

        Returns::
            result (bool|None):  True if proof verifies of kind for leaf
                                 False if proof does not verify as kind for leaf
                                 None if problem with proof verification
        Parameters::
            proof (iterable[NodeSaidage|LeafSaidage]): of parts of branch from
                    root down to bottom.
            kind (bool): of proof True means inclusion False meams exclusion
            root (Partage|Noncer|Diger|str|None): said polymorphic where:
                    Partage with Matter instance values with root said
                        instance.said.qb64
                    Noncer or Diger then root said is instance.qb64
                    str then root said is in qb64 form
                    None means assume top node of proof is valid root
            leaf (Partage|Noncer): used to get leaf limb to compare for proof
                    when Partage instance with Matter instance values
                        uses instance.part.limb.num
                    when Noncer instance uses instance.num

        NodeSaidage = (kith, tuid, said, span, limb, left, right)
        LeafSaidage = (kith, tuid, said, span, limb)

        """
        try:  # get leafer (limber of leaf limb)
            if isinstance(leaf, Partage):
                leafer = leaf.part.limb
            elif isinstance(leaf, Noncer):  # Noncer is subclass of Diger
                leafer = leaf
            else:
                return None  # bad leaf
        except Exception as ex:
            return None  # bad leaf

        if not leafer.nonce:  # empty leafer so bad verify request
            return None  # bad leaf


        proof = deque(proof)  # make deque so can popleft

        root = deque.popleft(proof)  # saidage of root
        if root.span != 0:
            return None  # invalid root node in proof

        saidage = Siter.saidify(saidage=root)  # verify root node said
        if saidage.said.qb64 != root.said.qb64:
            return None  # invalid root node in proof said does not verify


        # get child on side of root for limb of leaf
        if Siter.rightAtSpanInt(leafer.num, root.span.num + 1):  # go right
            side = True # get child on right side
            childer = root.right   # empty or leaf saider or node saider
        else:  # go left
            side = False # get child on left side
            childer = root.left  # empty or leaf saider or node saider

        if not kind:  # exclusion proof
            if not proof:  # no child so exclusion is because root child is empty
                if childer.nonce:  # not empty so bad proof
                    return None  # bad proof
                return True  # valid exclusion child is empty
            child = proof.popleft()  # saidage of child
        else:  # inclusion proof
            if not proof:  # no included child so bad proof
                return None  # bad proof format
            child = proof.popleft()  # saidage of child


        while proof:
            proof.popleft()







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
        if self.code not in DigDex:
            raise ValueError(f"Invalid digest code={self.code}")
        self.nodes = dict()
        self.leaves = dict()
        self.infos = dict()


        # make and insert root node in .nodes
        # span is 0, limb is all zeros, left is empty, right is empty
        rootage = Nodage(span=Number(num=0),
                         limb=Noncer(raw=bytes(MaxSpanBytes), code=self.code),
                         left=Noncer(nonce=""),
                         right=Noncer(nonce=""))
        self.root = Partage(self.sayNode(rootage), rootage)
        self.pinNode(saider=self.root.said, nodage=self.root.part)


    def saidagize(self, partage, sayit=False):
        """Populates and saidifys an appropriate saidage derived from partage
        as determined by type of partage

        Returns::
            saidage (NodeSaidage|LeafSaidage): instance where said is computed
                    from saidage derived from partage as supplemented with tree
                    fields from .self.

        Parameters::
            partage (Partage): instance with Matter instance field values
            sayit (bool): True means recompute said of resultant saidage
                          False means use said from partage. default False
                            for use case of generating proofs from already
                            saided parts.

        """
        if isinstance(partage.part, Nodage):
            saidage = NodeSaidage(kith=Ilker(ilk=Kiths.node, strict=False),
                                  tuid=self.tuider,
                                  said=partage.said,
                                  span=partage.part.span,
                                  limb=partage.part.limb,
                                  left=partage.part.left,
                                  right=partage.part.right)

        elif isinstance(partage.part, Leafage):
            saidage = LeafSaidage(kith=Ilker(ilk=Kiths.leaf, strict=False),
                                  tuid=self.tuider,
                                  said=partage.said,
                                  span=partage.part.span,
                                  limb=partage.part.limb)

        else:
            raise ValueError(f"Unrecognized {partage=}")

        if sayit:
            saidage = self.saidify(saidage)

        return saidage


    def say(self, sayage):
        """Computes and returns said as Matter primitive of part given by sayage
        (either nodage or leafage) where said is computed with a Saidage derived
        from sayage supplemented with per tree and per part field values taken
        from .self (Siter instance).

        To 'say' is to 'hash' or to 'digest' the part.

        Returns::
            saider (Diger): instance where said is computed from saidage
                            derived from sayage as supplemented with tree fields

        Parameters::
            sayage (Nodage|Leafage): instance of nodage whose field values are Matter
                             instances

        """
        if isinstance(sayage, Nodage):
            return self.sayNode(sayage)
        elif isinstance(sayage, Leafage):
            return self.sayLeaf(sayage)
        else:
            raise ValueError(f"Unrecognized {sayage=}")


    def sayNode(self, nodage):
        """Computes and returns said as Matter primitive of node given by nodage
        where said is computed with a NodeSaidage derived from nodage
        supplemented with per tree and per part field values taken from .self
        (Siter instance).
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
                            limb=Noncer(qb2=nodage.limb),
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


    def hasLeaf(self, saider):
        """Checks for leaf at saider in .leaves

        Abstract interface to .leaves storage of Leafage for each leaf indexed
        by is said. Interface uses Matter instances for said and Leafage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if saider key in .leaves
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
                              limb=Noncer(qb2=leafage.limb))
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
                        limb=Noncer(num=limb, code=self.code),
                        left=left.said,
                        right=right.said)
        saider = self.sayNode(nodage)  # update said of forking node
        self.pinNode(saider, nodage)  # update .nodes with forking node
        return self.updateNode(node, saider, side=side)


    def leafFromLeafer(self, leafer):
        """Create leaf to insert from leafer (limber) of leaf limb.
        Creates limb from leafage from limb given by leafer

        Returns::
            leaf (Partage): instance (said, part) where:
                            said is Noncer instance generated from leafage
                            part is Leafage instance with Matter instance values

        Parameters::
            leafer (Noncer): instance only per leaf limb unique value used to
                             generate leafage and then said of leaf
        """
        leafage = Leafage(span=Number(num=256), limb=leafer)
        saider = self.sayLeaf(leafage)  # compute leaf said
        return Partage(said=saider, part=leafage)  # matter primitives


    def leafFromInfoer(self, infoer):
        """Create leaf to insert from infoer. Computes leaf limb and said.

        Returns::
            leaf (Partage): instance (said, part) where:
                            said is Noncer instance generated from leafage
                            part is Leafage instance with Matter instance values

        Parameters::
            infoer (Noncer): instance of unique said of info source for leaf
                    used to generate leaf's limb as leafer which is then
                    used to generate leafage then used to generate said of leaf
        """
        leafer = Noncer(ser=infoer.raw, code=self.code)  # limb for leaf
        if not leafer.nonce:  # empty leafer
            raise ValueError(f"Invalid infoer limb={leafer.qb64} empty")
        return self.leafFromLeafer(leafer)


    def insert(self, infoer):
        """Insert leaf corresponding to infoer idempotently into tree

        Returns::
            leaf (Partage|None)): of inserted leaf corresponding to infoer
                When insert successful, Partage instance (said, part) where:
                        said is Noncer instance of leaf said
                        part is Leafage instance with Matter instance values
                Otherwise:  None

        Parameters::
            infoer (Noncer): instance encoding of external source info said for
                        the derived leaf which external said is digest of actual
                        leaf information.
                        The infoer (said) digest code may differ from .code.
                        Thus a Siter instance is compatible with all external
                        info saids for its leaves while ensuring partitioning
                        of a common digest space for all its internal saids
                        including leaf limbs, leaf saids, and node saids.

        """
        # setup for ._insert
        # return None if ._insert fails
        try:
            leaf = self.leafFromInfoer(infoer)
        except Exception as ex:  # invalid leafer maybe empty
            return None  # not insertable

        if self.hasLeaf(leaf.said):
            return None  # already inserted

        # start at root (values as matter primitives) raise error if ._insert fails
        try:
            self.root = self._insert(leaf, self.root)  # new root with inserted leaf
        except ValueError as ex:
            return None
        self.pinLeaf(leaf.said, leaf.part)  # add leaf
        self.infos[leaf.part.limb.qb64] = infoer.qb64  # add ref to leafer to infos
        return leaf



    def _insert(self, leaf, node):
        """Recursive insert of leaf starting at node. The act of insertion of
        a new leaf effectively stretches the node space as needed to fill in/out
        the new leaf. Once a node is created is stays in place and other nodes
        are inserted above it or below it in order to hold new leaves. A given
        set of leaves no matter the order of insertion always produces the same
        root said (hash, digest), thus preserving the most important property of
        a sparse Merkle tree.

        Except for the root node, all real nodes have two non-empty children.
        Thus the number of nodes is always 1 less than the number of leaves
        (except when the root has one or more empty leaves). This minimizes the
        number of real nodes to its theoretical limit.

        The keys or indices for each leaf is called its limb. All limbs
        are of length MaxSpan (256). Each node also has a limb whose span is less
        than MaxSpan. Thus any node limb is a prefix to some set of potential
        leaf limbs. The node's limb and span is stored along with its children's
        limbs.

        A new leaf is inserted by climbing down a branch by following the child
        node whose limb is a prefix of the leaf.

        When the leaf hits child node with a non-matching prefix then a new
        forking node is inserted above the non-matching node and below the parent
        node of the non-matching node. The new forking node's prefix is set to
        the maximally length common span of the new leaf's limb and the old
        non-matching node's limb. The children of the new forking node are the
        leaf and the old node attached at the appropriate child as determined
        by the bit where their limbs differ. The new forking node replaces the
        old node as a child of the prior partent node.

        When the leaf hits a child leaf attached to a node, then a new forking
        node is created whose prefix is the common span of both leaves. The
        new forking node replaces the old child leaf as the parent node's child
        and the two leaves are attached at the appropriate child as determined by
        the bit where their limbs differ.


        Values are Matter instances


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
            # if cannot walk down on side:
            #    fork  between node and its child node on side.
            #     above child node and below node.
            #    fork at shallowest span diff of leaf and child node on side
            #    child node should stay on same side of new fork node as it
            #    was on node and leaf should go on other side of new fork node
            #
            #    return updated node with forked child
            # else: cannot walk down past child node:
            #     recurse with with child node on side
            #     update node and return
            child = Partage(childer, nodage)  # make child
            if not self.fitLeafNode(leafer=leaf.part.limb,
                                    noder=child.part.limb,
                                    spanner=child.part.span):  # cannot walk down
                # leaf cannot recurese down child node path
                return self.forkNode(node, left=leaf, right=child, side=side)

            # can recurse down child so recurse
            child = self._insert(leaf=leaf, node=child)  # recursion updates child
            # remove, replace, and return updated node with new child on side
            return self.updateNode(node, child.said, side=side)

        raise ValueError(f"Should never get here")



    def delete(self, infoer, strict=False):
        """Delete leaf corresponding to infoer from tree

        Returns::
            result (Partage|None): when leaf from leafer was found and deleted
                                   otherwise None means problem deleting

        Parameters::
            infoer (Noncer): instance encoding of external source info said for
                        the derived leaf which external said is digest of actual
                        leaf information.
                        The infoer (said) digest code may differ from .code.
                        Thus a Siter instance is compatible with all external
                        info saids for its leaves while ensuring partitioning
                        of a common digest space for all its internal saids
                        including leaf limbs, leaf saids, and node saids.
            strict (bool): False means check for presence of leaf in .leaves
                               If not present in .leaves return False
                               Else traverse tree to find and delete
                           True means ignore presence and always attempt to find
                               leaf in tree to delete.


        """
        # setup for ._delete
        try:
            leaf = self.leafFromInfoer(infoer)  # prevents infoer being empty
        except Exception as ex:  # invalid infoer maybe empty
            return None  # not deletable

        if not self.hasLeaf(leaf.said) and not strict:
            return None  # already deleted

        result = leaf

        # start at root (values as matter primitives)
        # return None if ._delete fails due to error
        try:
            root = self._delete(leaf, self.root)  # new root with deleted leaf
            if not root:  # None returned  so leaf not found
                return None  # nothing to delete
            self.root = root  # deleted so update root

        except ValueError as ex:  # problem deletong
            return None

        if not self.remLeaf(leaf.said) and not strict:  # remove leaf from .leaves
            result = None  # delete not clean

        try:
            del self.infos[leaf.part.limb.qb64]  # rem from infos
        except KeyError as ex:
            if not strict:  # strict
                return None  # malformed .infos

        return result



    def _delete(self, leaf, node, parent=None):
        """Recursive delete of leaf starting at node.

        Values are Matter instances


        Returns::
            new (Partage|None): instance (said, part) of new updated node replacing
                           old node where recursive ._delet began where:
                           said is Noncer instance of node said
                           part is Nodage instance with Matter instance values
                           None means leaf not found in tree

        Parameters::
            leaf (Partage): instance (said, part) of leaf to be deleted where:
                            said is leaf said Noncer instance
                            part is Leafage of leaf with Matter instance values

            node (Partage): instance of (said, part) as part of tree to
                            begin/resume recursive delete where:
                            said is node said Noncer instance
                            part is Nodage of node with Matter instance values
            parent (Partage): parent node of node if any.
                              None means no parent as when node is root

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
            return None  # empty side so leaf not in tree

        if (leafage := self.getLeaf(childer)) is not None:  # child is leaf
            if leafage.limb.num != leaf.part.limb.num:   # leaf not in tree
                return None  # nothing to delete

            #else leafage.limb.num == leaf.part.limb.num found leaf
            if not parent:  # node is root
                # no parent so node is root, update node on side with empty
                childer = Noncer(nonce="")  # replace child with empty
                return self.updateNode(node, childer, side=side)

            # has parent so shift other side child of node upto parent and
            # remove node
            if side:  # leaf on right of node so left child shifts up
                childer = node.part.left  # other child on left
            else:  # leaf on left of node so right child shifts up
                childer = node.part.right

            # which side of parent was node
            if node.said == parent.part.left:  # node was on left of parent
                nside = False  # replace on left of parent
            else:  # node was on right of parent
                nside = True   # replace on right of parent

            self.remNode(node.said)  # remove node, leaf gets removed in .delete
            return self.updateNode(parent, childer, side=nside)  # update parent


        if (nodage := self.getNode(childer)) is not None:  # child is node
            #  walkdown means span of limb of node is longer than common span
            #  between node and leaf
            # if cannot  walk down on side:
            #      return None  leaf not in tree
            # else: can  walk down past child node
            #       recurse with with child node on side
            #       update node and return
            child = Partage(childer, nodage)  # make child to examine
            if not self.fitLeafNode(leafer=leaf.part.limb,
                                    noder=child.part.limb,
                                    spanner=child.part.span):  # cannot walk down
                # leaf cannot recurese down child node path so leaf not in tree
                return None  # nothing to delete

            # can recurse down child so recurse
            child = self._delete(leaf=leaf, node=child, parent=node)  # recursion updates child
            if not self.hasNode(node.said):   # was removed as part of removing leaf
                return child  # child is already updated parent so skip node update
            # remove, replace, and return updated node after deleted leaf in subtree
            return self.updateNode(node, child.said, side=side)

        raise ValueError(f"Should never get here")


    def prove(self, infoer=None, leafer=None):
        """Return proof of leaf derived from infoer in tree,
        either inclusion or exclusion where:
            proof is branch down from root of saidages (NodeSaidage|LeafSaidage)
                where:
                    inclusion proof ends with saidage matching leaf from infoer
                    exclusion proof ends with either saidage of
                        node with uncommon prefix to leaf created from infoer or
                        leaf that does not match leaf from infoer

        Returns::
            result (tuple):  of form (proof, kind) with values:
                            kind (bool|None): True means infoer leaf is included
                                                branch contains proof of inclusion
                                             False means infoer leaf is excluded
                                                branch contains proof of exclusion
                                             None means not provable bad infoer
                            proof (list|None): of parts (nodes and leaves) from
                                    root down to bottom of branch.
                                    When inclusion proof then bottom of branch is
                                         leaf or leaf from infoer or leafer
                                    When exclusion proof then bottom of branch is
                                         either some other non matching leaf
                                         or node whose prefix is not common to leaf

        Parameters::
            infoer (Noncer): instance encoding of external source info said for
                        the derived leaf which external said is digest of actual
                        leaf information.
                        The infoer (said) digest code may differ from .code.
                        Thus a Siter instance is compatible with all external
                        info saids for its leaves while ensuring partitioning
                        of a common digest space for all its internal saids
                        including leaf limbs, leaf saids, and node saids.
                    When None then use leafer
            leafer (Noncer|None): instance encoding of leaf limb as derived
                        from leaf info said which said is digest of actual leaf
                        information.
                        Only applies when infoer is None

        """
        # setup for ._prove
        if not infoer and not leafer:
            raise ValueError(f"Missing infoer or leafer to prove against")

        if infoer:
            try:
                leaf = self.leafFromInfoer(infoer)  # prevents infoer being empty
            except Exception as ex:  # invalid infoer maybe empty
                return (None, None)  # not provable include nor exclude
        elif leafer:
            try:
                leaf = self.leafFromLeafer(leafer)  # prevents leafer being empty
            except Exception as ex:  # invalid leafer maybe empty
                return (None, None)  # not provable include nor exclude

        proof = list()  # mutable so gets populated by recursive descent
        try:
            # populate proof and return kind of proof
            kind = self._prove(leaf, self.root, proof)  # proof kind

        except ValueError as ex:  # problem proofing
            return (None, None)

        return (proof, kind) if kind is not None else (None, None)


    def _prove(self, leaf, node, proof):
        """Recursive descent to populate branch from bottom up and to determine
        proof kind (inclusion or exclusion) for leaf starting at node.

        Values are Matter instances

        Returns::
            kind (bool|None): True means infoer leaf is included
                                proof of inclusion
                              False means infoer leaf is excluded
                                proof of exclusion
                              None means not provable bad infoer

        Parameters::
            leaf (Partage): instance (said, part) of leaf to be proven where:
                            said is leaf said Noncer instance
                            part is Leafage of leaf with Matter instance values
            node (Partage): instance of (said, part) as part of tree to
                            begin/resume recursive descent where:
                            said is node said Noncer instance
                            part is Nodage of node with Matter instance values
            proof (list):  of parts in branch in top down order including node.
                            proof is mutable and is populated on the way down.
                            When leaf included then bottom of proof is
                                 leaf of infoer
                            When leaf excluded then bottom of proof is
                                 either a node whose prefix is uncommon with leaf
                                 or some other leaf that is not leaf of infoer
        """
        # Walk leaf down appropriate node child branch.
        # assumes node limb is prefix of leaf limb. leaf fits below node.
        # Root limb is empty so always prefix of any leaf limb. leaf fits below root.
        # figure out which side of node, leaf must go
        proof.append(self.saidagize(node))  # add node as saidage to proof

        if self.rightAtSpanInt(leaf.part.limb.num, node.part.span.num + 1):  # go right
            # get child on right other on left
            childer = node.part.right   # empty or leaf saider or node saider
        else:  # go left
            # get child on left other on right
            childer = node.part.left  # empty or leaf saider or node saider

        if not childer.nonce:  # child is empty (should only happen at root node)
            return False  # empty on leaf side so leaf not in tree exclusion proof

        if (leafage := self.getLeaf(childer)) is not None:  # child is leaf
            if leafage.limb.num != leaf.part.limb.num:   # leaf not in tree
                kind = False  # bottom leaf not match leaf so exclusion proof
            else:
                kind = True  # bottom leaf matches leaf so inclusion proof
            child = Partage(said=childer, part=leafage)  # bottom leaf
            proof.append(self.saidagize(child))
            return kind  # of proof

        if (nodage := self.getNode(childer)) is not None:  # child is node
            #  walkdown means span of limb of node is longer than common span
            #  between node and leaf
            # if cannot  walk down child node on side:
            #      return None  leaf not in tree
            # else: can  walk down past child node
            #       recurse with with child node on side
            child = Partage(childer, nodage)  # make child to examine
            if not self.fitLeafNode(leafer=leaf.part.limb,
                                    noder=child.part.limb,
                                    spanner=child.part.span):  # cannot walk down
                # leaf cannot recurse down child node path so leaf not in tree
                proof.append(self.saidagize(child))  # child is unwalkable node
                return False  # exclusion proof

            # can recurse down child node so recurse
            return self._prove(leaf=leaf, node=child, proof=proof)  # recursion

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

    def shake(self, node=None):
        """Returns list of leaves from recursive descent traveral of tree attached
        to node.

        Useful for consistency testing of leaves in tree vs. leaves in database
        """
        node = node if node is not None else self.root


    def _shake(self, node, leaves):
        """Recursive depth first traversal of tree attached to node.
        Populates leaves list with leaves as encountered in traversal
        """
