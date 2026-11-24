# Design of SIT SAIDed Info Tree

## Introduction

A SAIDed Info Tree (SIT) is a shallow verifiable Map where
the stucture metadata of each part of the tree (namely the part's path plus tree
metadata) is included in each part's hash.

The approach of digesting data and using that digest as a content addressable
identifier that is the index into the verifiable map is an extension of the
SAID approach. A SAID is a self-contained content addressable identifier.
When the tree structure is itself digested to form the digests (hashes) in the
tree then the Tree is itself a tree of SAIDs and the root digest (hash) it a
SAID of the whold tree. This is exactly the SAID approach to managing data.

Thus we generalize the verifiable map as a SAIDed Information Tree or SIT.

We use CESR encodings throughout the tree for the cryptographic digests.
This provides both cryptographic agility and increased collision resistance.

The most important concept needed to understand a SIT relative to other sparse
Merkle tree algorithms is that a SIT grows from the root down by stretching the
node space between nodes to allow leaves to be inserted. A node is inserted
in a way that maximizes the shrink of the tree (thereby maximizing its potential
to stretch). This is done by including the node's prefix in the index (key) space
in the tree. This prefix (limb and span) fixes the node's absolute location in
the tree once inserted. Other nodes and leaves can be inserted above or below it
but the node itself never moves in an absolute sense. This ensures the essential
verifiable map property that the same set of leaves always results in the same
root digest no matter the insertion order of the leaves.

Using CESR enables a tree or parts of a tree to be streamed in a CESR stream
in either compact CESR binary or readable text mode. CESR streams can attached to KERI
messages, or stored in a database. Each set of data elements uses a special
group code when included in a CESR stream. Each element uses a CESR primitive code
appropriate to the element type.

Security is based on the concept of partitioning the input space to the cryptograpic
digest algorithm used to compute the node and leaf digests (hashes). This concept
is developed in the security analysis section of the paper:
[Efficient Sparse Merkle Trees](https://eprint.iacr.org/2016/683.pdf)

Tree metadata associated with each tree
- The type of digest algorithm used to create the SAIDs for each node and leaf.
  The CESR encoding of each digest includes this code
  Partitioning the digest input space per algorithm increases collison resistance
  and ensures that only digest using the same algorithm are ever used to generate
  the root digest (hash).

Tree metadata stored once per tree but digested with each part includes:
- The type of part either a leaf or a node. This partitions the hash input space
  to improve collison resistance between node hashes and leaf hashes.

- A high entropy (cryptographic strenth) universally unique tree identifier TUID.
  The TUID can embed name spacing components in addition a salty-nonce component.
  The TUID partitions the digest input space per tree this improves collision
  resistance of all hashes in the tree vis a vis hashes for other trees with a
  different TUID.

Data stored with each node part includes:
- SAID of node as key to its storage
- span of limb of node
- limb of node as its prefix
- left child SAID
- right child SAID

Data stored with each leaf part includes:
- SAID of leaf as key to its storage
- span of limb of leaf (to enable different sized trees)
- limb of leaf

Note the SAID of the leaf is computed over the SAID of its info so there is
not need to store with the leaf. However a separate conventional database
key value store is used to store the mapping between leaf SAID and its info SAID
and another to store the actual infor indexed by its info SAID.

Further note, Although for a given SIT, the same digest algorithm must be used to
compute the said of each node and leaf which are in turn used to compute the
root said (digest) in order to avoid a collison attack using two different digest
algorithms, any infomation associated with a leaf via its that information's SAID
can use a different digest algorithm. To clarify, the actual leaf said is computed
using the tree wide digest algorithm not the information specific algorithm.
While each leaf's info hash SAID digest type is individually encoded.
This approach balances security with versatility as a data map.

### Limb and Span
Each leaf has a `limb` of fixed span equal to the maximum span
for the tree `MaxSpan`. This is typically 256. This corresponds to the typical
size in bits of a cryptographic strength hash (digest) of 32 bytes. A maximum span
of 256 is convenient when the leaf `limb` value is generated as an key (index)
for the info (data) value of the leaf by digesting that info (data).

The `span`, of a node indicates the length of its `limb` as a prefix to a leaf
`limb` set. Thus nodes have a variable span `[1..MaxSpan-1]`

A `limb` (path in key space) is encoded as a 32 byte, 256 bit number where the
MSbit corresponds to a child at the root of the tree and the LSbit corresponds
to a child at the  bottom of the tree.
A 0 in a bit position is a left child and a 1 in a bit position is a right child.

A leaf limb always has a span of `256 = MaxSpan`, all bits matter.
Each leaf is attached to a node as a child where the node limb is a valid prefix
to the leaf limb.

A node limb has a span `[1..255]`. The root has span = 0. A node limb's maximum
span must be 255 so that a maximim span limb is always a valid prefix to a leaf
attached to one if its where the child's side (left or right) is given by
the 256th bit of the leaf's limb

### Node and Leaf SAID

The SAID of a node is derived from the digest of its per tree and per node metadata.
The per tree metadata is its part type+tuid and the per node metadata is its
span+limb+left+right. Where left and right are the said of its children nodes or
leaves.



```
node SAIDed data  (+ is concatenation operator)

partType + tuid + span + limb + leftChildSaid + rightChildSaid

node SAIDed data including its SAID

partType + tuid + nodeSaid + span + limb  + leftChildSaid + rightChildSaid

```



The SAID of a leaf is derived from the digest of its per tree and per leaf metadata.
The per tree metadata is its part type+tuid and the per leaf metadata is its
span+limb.
The limb of a leaf is derived from the SAID of its info data using the tree-wide
digest code.

```
leaf SAIDed data  (+ is concatenation operator)

partType + tuid + span + limb

leaf SAIDed data including its SAID

partType + tuid + leafSaid + span + limb

```

### Children

Each child of the root node may be another node's SAID, a leaf's SAID, or empty.
The root node is special because it may have zero, one or two empty children.
All other nodes (not the root) always have two non-empty children.

Each child of a non-root node may be either another non-root node or a leaf.
A non-root node could have as children, two nodes, two leaves, or one node and
one leaf.

Once a node has been inserted it prefix (limb and span) does not change.
Essentially this fixes the position of the node within the tree.
But anytime one or both of its children changes then its SAID changes which
means all its parent node hashes change.

#### Root Node Security

An empty child of a root node does not introduce ambiguity
(tree hash space collision) because a given node or leaf can only be attached
to the root child that corresponds to the most significant path bit (left or right)
of the limb of that child. Moreover because the SAID of a node or leaf is computed
over its span and limb, the hash input space is partitioned between left children
and right children thus providing collison resistance between root hashes.

To restate, there is no ambiguity (collision) between two different roots,
one with an empty left child and another with an empty right child.

Suppose we have a root node with an empty left child and a non empty right child
and we were to only hash a concatenation of the raw data for each element.

The hashed data for that root node is as follows:
`partType + tuid + span + limb + rightChildSAID`

Suppose we have a different root node with an empty right child and a non empty
left child. The hashed data for that root node is as follows:

`partType + tuid + span + limb + leftChildSAID`

Given a crytographic strength collision resistant digest, a left child SAID can
never  equal a right child SAID because the child SAIDs hash their paths and
a left child path always has a 0 in its MSb position and a right child path always
has a 1 in the MSb position of its path. Therefore there is no need to have
hash value constants to replace empty children.

However in the case where the data elements for each node and leaf are serialized
using CESR as is the case with SIT, then an empty child's serialization is
not truly an empty string but includes the CESR code for an empty string.
In this case the empty code in CESR is included in the digest.
This further increases collision resistance between roots with empty children,
becasue now the order matters (left or right) in the concatenation.

`partType + tuid + span + limb + CESREmpty + rightChildSAID`

`partType + tuid + span + limb + leftChildSAID + CESREmmpty`


### Depth

A sparse Merkle tree has a fixed height, typically 256. The height nomenclature is
confusing for a SIT because in a SIT, the node space is compressed (shrunken) by
including prefixes (limb and span) for each node that.
SIT instead defines depth for both nodes and leaves.
In SIT, depth is not a bit position in a limb (key span path) but is the actual
number of nodes above it in its branch back to the root (root node included).
For a conventional binary tree, a nodes's or leaf's depth expressed either as a
bit path offset and the number of nodes above it in its branch are the same.
A given node  or leaf at a given depth corresponds one-to-one to a bit path
through the key space to that node or leaf. To clarify, this is not true for a SIT.
As mentioned above, this is because a SIT is a shrunken shallow sparse Merkle tree.

The depth of a leaf is always one greater than the depth of
the node to which that leaf is attached. A node does not count itself in its
own depth. The root node has a depth of 0.


## Inclusion and Exclusion Proofs

In SIT a proof is fully self-contained. It consists of a list of nodes and leaves
with each containing the  full node or leaf data needed to compute its SAID.
The list starts at the root and traverses the branch down to the bottom.

When its an inclusion proof then the bottom of the branch is the target leaf of
the proof. This is the last element in the list.

When its an exclusion proof then the bottom of the branch is either a non-matching
leaf with respect to the target leaf or a node whose prefix is not common to
the limb of the target leaf. For non-exclusion proofs the target leaf is appended
to the end of the list after the bottom of the branch.

In either case the last item in the proof is the target leaf of the proof i.e.
the leaf being proven as either included or excluded from the tree. This makes
the proof self-contained. A verifier can confirm what the proof is proving given
the root at the front of the list and the target leaf at the end.


## Design Logic

A leaf can only attach to child of node on side given by bit in leaf
limb which bit is located below (greater than) the node limb span.
This leaves room for one more nodes to interposed either above or
below the node to which a leaf is attached. The key is that the
limb of a given node is set by the deepest common span of its
child leaves (node and/or leaf). This leaves gaps in the tree where
virtual missing nodes with empty children would have been. We can
distinguish between real nodes and ghost nodes.
A real node is inserted in the tree with a limb a span a parent and two real
children.
A ghost node represents a potential node that exists only virtually in the key
space of the sparse Merkle tree. As long as the gaps between real nodes
are stable, the ghost nodes that would otherwise fill those gaps themselves
do not need to be hashed/digested.

Because each node and leaf said is computed over its limb, there
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
leaves a stable gap for any virtual ghost nodes above it in the tree.

When a new leaf causes a new fork to be interposed below  existing
node then the existing nodes above it must change their saids but
the nodes below the new node do not. In order for a fork to be
inserted below a node, the leaf must itself fit below that node.
The new node always has a limb value that is set to the deepest
common span of its children. This creates a stable gap for the
virtual ghost nodes.

Creating stable gaps for virtual ghost nodes supports the required
property of a sparse Merkle tree, that is, that the order of insertion
of its leaves does not change the final node structure.
A given set of leaves always has the same set of real nodes.

To elaborate, T]the act of fixing node limbs (prefixes), fixes their
relative place in the tree. Filling in above protects the structure below.
Filling out below does not change the structure above. A stable set of
insertion fill in/out rules ensures that the same set of leaves results
in the same set of nodes. There is no need to expand ancestor ghost nodes into
real nodes each an empty child in order to fill in a leaf. The node limb prefix
accounts for the missing ghost nodes.

This means that when inserting or removing a leaf, the number of
hashes to update the root is only the depth of real nodes from leaf
to root not 256 like other sparse merkle trees.  The number of nodes
in a SIT is L-1 where L is the number of leaves inserted. The average depth
of leaves in a SIT always approaches log2(L). Therefor the average number of hashes
to insert or remove or prove inclusion/exclusion is also log2(L).
This differs from other sparse Merkle trees where the number of
hashes is log2(M) where M is the maximum number of leaves the tree
can hold.

Many optimized SMTs when used as a verifiable map (such as
[Trillian](https://github.com/google/trillian/blob/master/docs/papers/RevocationTransparency.pdf)
expand and hash all the ancester nodes of any non-empty node. Typically these
the ancestor nodes are precomputed placeholder empty nodes for each
height of the tree up to the height 256. In compact SMT, empty subtrees below
a non-empty node are compresses. Compression only happens up to the first
first non-empty parent node of a leaf. For example, the
[Jellyfish](https://developers.diem.com/papers/jellyfish-merkle-tree/2021-01-14.pdf)
SMT compresses a single leaf on an empty subtree up to the non empty node holding
the empty subtree so only one hash is needed for the subtree (thus skipping
hashes equal to the height of the subtree). Jellyfish however expands all ancester
nodes on the branch above any node with two non-empty children.
This makes the average depth a worst case for dense leaf key spaces
such as sequential leaf keys that inhabit the bottom elevations of the leaf key
space. Other compact SMTs like
[Aergo](https://medium.com/aergo/releasing-statetrie-a-hash-tree-built-for-high-performance-interoperability-6ce0406b12ae)
have similar charactericts, namely, compression of empty subtrees with expanded
ancestor branches.

Another compact SMT,
[Nervos](https://github.com/nervosnetwork/sparse-merkle-tree/blob/master/SMT.md),
is similar to Jellyfish (and others like Jellyfish) in that is compresses hashes
of empty subtrees by merging non-empty nodes up to the highest node with two
non-empty children. Unlike jellyfish, however, Nervos stores the key prefix with
each real node so that it does not have to expand the ancestors of nodes with
non-empty children. Any leaf can compare the node prefix to its key
to skip empty sub-trees between real nodes (those with two non-empty
children).  This minimizes the average effective depth of nodes in the tree.

SIT was inspired by this feature of Nervos, namely, storing the node prefix with
the node in order to minimize the average effective depth of the tree).
SIT is therefore most similar to Nervos. The main
differences between SIT and Nervos are full cryptographic agility, simpler logic,
stronger security, and KERI/ACDC friendly. SIT gets both crypto agility and
KERI/ACDC friendliness because it CESR encodes all cryptographic primitives.

SIT's logic is conceptually much simpler than Nervos' (and hence code) because
logically SIT builds the tree by stetching a shrunk tree from the top down
instead of shrinking a full size tree from the bottom up. They both arrive at the
same place its just simpler to do it the SIT way. SIT borrows from Nervos the concept
of including a key space prefix in each node but Nervos logic for applying that
concept is way more convoluted. Nervos my iterate up to 256 times to merge up the
virtual ghost (empty) nodes. Whereas SIT only iterates the number of real nodes
it actually encounters on the way down. The number of real nodes encounted on
average is always `O(log2(L))` where `L` is the number of real leaves.

As mentioned above,  the security of SIT is stronger than Nervos because in SIT
the key prefix (limb in SIT) of each real node (i.e. two non-empty children) is
also hashed for the node, not just for the leaves. Nervos only hashes a leaf's
key with the leaf. It does not hash the node prefix with the node. Hashing the
node prefix with the node better partitions the hash input space as per the
approach to security outlined in
[Efficient Sparse Merkle Trees](https://eprint.iacr.org/2016/683.pdf).
Partitioning the hash input space increases the collision resistance that must
be overcome to perfom a successful malleability attack on an SMT used as a
verifiable map.

To elaborate: both SIT (and Nervos) stretch the nodes space by filling in or
filling out nodes as needed. The fill in/out is both above and below existing nodes
Thus the node space is stretched to fit the leaves.

Conceptually, SIT starts with a fully shrunken real node space and stretches it to
insert a leaf while the Nervos starts with an expanded virtual node space and
re-shrinks it to insert a leaf.

Because SIT (and Nervos) never expand ancestor nodes of nodes with
two non-empty childen the number of nodes is minimized to the theoretical minimum
for a binary tree of `L` leaves. The number of nodes `N` is always 1 less than
the number of leaves `L`, `N = L-1` for trees with at least two real leaves.
In the SIT case there is one exception and that is when the the root has one
or two empty leaves).
This minimized node count enables the average depth of leaves in SIT
to approach the minimum  of `O(log2(L))` where `L` is the number
of real leaves.

Whereas because Jellyfish and other similar algorithms
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
minimizes the number of reads and hashes needed for all of
insertion/deletion and inclusion/exclusion proofing
because the average number of reads and hashes for insertion/deletion and
inclusion/exclusion proofing is a function of the average depth of leaves which
approaches log2(L) where L is the number of real leaves.


One can still do radix storage optimization grouping of real subtrees with
SIT and Nervos to minimize database reads. But that optimization is transparent
to the insertion/deletion/inclusion/exclusion logic of SIT. Whereas in Jellyfish
and other similar Radix based Tries that optimizaiton logic complicates the logic
of insertion/deletion/inclusion/exclusion.

### Node Space Stretching

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

### Insertion Logic

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


### Shallow Tree

The average path length determines the average number of read and hash operations
to insert/delete/includ/exclude a leaf.

The optimization of using a shallow tree means that nodes are only
added as needed to accomodate the number of non-empty leafs.
All nodes but the root node have two children.
Thus the tree grows down from the root and is maximally shallow for its given
set of leaves where the leaf keys or indices determine the actual branching
structure. A highly beneficial sparse merkle tree property is the same set of leaves
results in the same root hash. This fixes the tree structure for a given set
of leaves. And the tree structure is always a function of the density or sparsity
of the actual keys that correpond to that set of leaves. A key set that is
dense and inhabits the bottom elevations of an SMT can explode the average depth
because of ancestor nodes interposed between the dense subtree to get to the root.
A shallow tree avoids interposing ancestor nodes so even poorly formed leaf set
key spaces (such as keys that include sequence numbers) do not explode the
average depth more than the subtree's depth measured relative to its top node
and not absolutely measured relative to the total tree's root node.

To elaborate the SIT only adds nodes as needed to fork to non-empy leafs.
A SIT therefore never has more nodes than the minimum needed
to store its leaves. If the leaf paths are uniformly distributed then the
tree will not only be shallow but well balanced.

Sparse Merkle Tree algorithms that store nodes with an empty children end up
with average tree depths much greater than` Log2(L)` where `L` is the number of
non-empty leaves. Thus they are not shallow in the sense that a SIT is shallow.


### Security

Because node paths are derived from cryptographic strength hashes of the leaves,
and the hash space of cryptographic strength hashes is approximately a
statistically uniform distribution in  order to satisfy the random oracle property,
then the distribution of leaf paths is therefore  statistically uniform across
the path space. This does not guarantee a well balanced tree, but does guarantee
the the average path length is  `O(log2(L))` where `L` is the number of leaves

To elaborate, the average path length of a node is a function of the
statistically approximate uniform distribution that results from a cryptographic
strength digest. Although the worst case for depth of any given leaf is always
the maximum path length, the use of a cryptographic strength digest to generate
the path combined with only storing forking nodes with non-empty
children means that on average the leaf depth approaches the minimum of
`Log2(L)` where `L` is the number of leaves.

To restate, the principal advantage of a SIT comes from the fact that it is
constructed such that the averge depth of the leaves is close to `log2(L)`
where `L` is the number of non-empty leaves.

A SIT generalizes and simplifies the various security, storage, access and
proofing mechanisms implemented in the different varieties of optimized compact
sparse merkle trees.

Fundamentally from a security perspective, including each node's structure in
its hash (digest), especially its height and path, ensures that the nodes of
a given tree cannot be rearranged to result in different tree but with the
same root hash (digest).

This forces an attacker at the very least to perform a successful
collision attack on at least one or more hashes.

Using full cryptographic strength hashes makes any such successful collision attack
computationally infeasible.


Open question does order of insertion of a set of leaves matter to the root digest
Or does the rebalancing insure that any order of insertion of a set of leafs
always results in the same root digest?

Open question, on average how many leaf moves are needed to rebalance on each
new leaf insertion (hopefully 1 on average)


### Design Trade Space

#### Average Node Depth

A SIT makes some trade-offs vis-a-vis other SMT algorithms.
The primary trade-off is that each node in the tree must store its structure
as meta-data in addition to the hashes (SAIDs) of its two children.

The node structure metadata that is unique for each node is the prefix
(limb and span).

The tree metadata is common to the whole tree and does not need to be stored
with each node.

Given the maximum limb span (256) is the size of a cryptographic digest for
content addressable leaves then the per node storage is increased by roughly 50%
over a tree that only stores its two children hashes.  (3 hash equivalents
versus 2 hash equivalents per node).

The number of nodes in a binary tree is given by,
`N = 2^(D) - 1``
where `N` is the number of nodes and `D` is the average depth of the binary tree.

Therefore increasing the average tree depth by 1  doubles the number of
nodes `N`. Likewise decreasing the average depth of a binary tree by 1 halves the
number of nodes  `N`.

Consequently a tree design the reduces the average depth by 1 at the cost of a
100% increase in per node storage requirements would net out a zero increase in
total storage required.
in average depth of 1 results in a net zero difference in total storage required.

Let the variable `N` represent the number of nodes.
Let the variable `S` readssent the per-node storage required.
Let the variable `T` represent the total storage required

We have
`T = N * S`
So if we design a new tree algorithm where the new per node storage
`S1 = 1.5 * S` (50% increase)
but the new number of nodes is
`N1 = N/2 = 0.5 * N`
then the new total storage
`T1 = N1 * S1 = 1.5* S * 0.5 * N = (1.5)*(0.5)* N * S = 0.75* M * S = 3/4(N*S)`
or a 25% improvement.

To elaborate, if we decrease the average depth by one we can we can double the
per node storage and not incur a storage penalty. This gives us a per-node storage
budget target for optimizing the tree using structural (limb, span) meta-data.


### Comparison to Other SMTs

The most popular SMT Trillian is typically used as a verifiable log not a
verifiable map. It can however be modified to be used as a verifiable map. But
it is much less compact than other SMT algorithms that are intended to be used
as verifiable maps. The KERI and SEDI use cases (registry bulk update,
issuance bulk anchoring,  age range proofs, watcher bulk updates)
all require a verifiable map. When used as a verifiable map
[Trillian](https://github.com/google/trillian/blob/master/docs/papers/RevocationTransparency.pdf)
is not considered a compact optimized SMT. It uses pre-computed hashes that when used
as a verifiable map requires computing 256 internal node hashes to insert a
non-empty leaf and recomputing those 256 internal hashes for delete,inclusion and
exclusion proofs . The  successor to  Trillian now called
[Tessera](https://tesseralabs.ai/download/Tessera-EnterpriseAI-Whitepaper.pdf)
uses a tile based disk interface that  pushes the computation load onto its clients for
distributed computing. It has  some of the read optimization of radix tree
chunking but does not optimize the internal tree structure to reduce
the number of hashes for verifiable maps. It pushes the hashing onto the clients
who buld their own trees.

Other popular optimized compact SMT algorithms for verifiable maps, namely,
[Jellyfish](https://developers.diem.com/papers/jellyfish-merkle-tree/2021-01-14.pdf),
[Aergo](https://medium.com/aergo/releasing-statetrie-a-hash-tree-built-for-high-performance-interoperability-6ce0406b12ae),
and [Ethereum](https://eprint.iacr.org/2018/955.pdf) use a radix tree, called a
trie to minimize disk reads by chunking the tree into subtrees.

In a radix tree (trie) each read returns a sub tree of 16 nodes (radix 16 or
4 bits = 4 level subtree). Internally all 16 nodes in each radix subtree must be
examined when doing insertion/deletion/inclusing/exclusion operations. The
primary advantage of radix chunking is the worst case for traversing a tree of
depth 256 requires only 64 reads (256 / 4). Thus the optimization is to
minimize disk access. In the case of  Jellyfish and Aergo the ancestor nodes
of any nodes with non-empty children must be expanded in order to correctly
position a given radix subtree  to generate stable root hashes that do not change
with a change in leaf insertion order. This expansion increases the number of
hashes and average depth of the tree which on average increases the number of reads.
Thus in Jellyfish and Aergo increasing the average tree depth can increase the
depth of the radix sub-trees which in turn increases the average number of reads.
Thus somewhat becoming self-defeating. In Ethereum the storage is not increased
but all the ancestor node hashes must be computed thereby significantly increasing
computation. Overall using a radix tree (trie) significantly increases the
the code complexity and computation load and in some cases the average tree depth.
which may net be overall disadvantageous. To restate ancestor expansion
may conteract savings in disk read operations despite the radix chunking.
When combined with the increase in hashing required for all operations, radix
chunking may be largely self defeating for many applications.

Most importantly reducing shallow SMT algorithms like SIT and Nervos
minimize the average tree depth which in turn minimizes the baseline computation
requirements hashes and the baseline number of disk reads for all operations which
baselines are always on the order of the actual number of nodes on the branch
to a given leaf i.e. its depth.

So a tree whose average depth approaches the minimum of `Log2(L)` where `L`
is the number of inserted leaves optimizes computational performance for the
number of reads and hashes for insertion/deletion operations as well as
and inclusion/exclusion proofing operations.  So overall performance is
maximized by minimizing average leaf depth.

The simplicity of the SIT approach means that radix chunking to minimize reads
is still possible via the external storage interface, but without incurring the
self-defeating trade-off of ancestor node expansion.

Thus the main trade-off for the SIT approach is increased per part (node/leaf) storage
resulting from storing stuctural metadata with each part in order to  stretch
the node space. But as explained above, this increased per part storage
is more than compensated for a reduction of one in average tree depth. In real
world applications it is anticipated that SIT could reduce average tree depth
compared to radix based SMTs by much more than 1.

Finally, the most frequent operations on a tree are inclusion/exclusion proofs
not insertion/deletion. The former can be cached in memory with a read/write through
cache that minimizes the number of total disk reads and writes compared to the
total disk reads and writes for insertion/deletion on a given tree.

For a given tree, the insertion or deletion operations on any leaf are
usually infrequent compared to number of times a leaf must be proven as included
or excluded from the tree.

Indeed, for many applications for a given tree, the ratio of average
inclusin/exclusion operations to insertion/deletion operations is on the order
of thousands to millions.

Therefore the highest value optimization comes first from minimizing average
tree depth and then from in memory caching of inclusion/exclusion proofs not
from radix chunking to minimize reads and writes. But the latter can still be
done on a SIT as an external part of the data storage interface that does not
therefore complicate the SIT logic. Which complicated radix logic would slow down
the much more frequent inclusion/exclusion proofing operations and in some
algorithms expand the ancestor nodes thereby increasing the average depth and
defeating the read optimization gained by radix read chunking.



