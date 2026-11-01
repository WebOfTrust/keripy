# Design of SIT SAIDed Info Tree

Maximally shallow SAIDed Info Tree (SIT) where as verifiable Map where the
stucture metadata of each part of the tree (namely the part's path plus tree
metadata) is included in each part's hash.

The path is derived from a SAID of each part and leaf parts include the SAID
of the data bound to that leaf. Tree metadata includes a unique tree identifier
as a salty nonce, a version, and the type of digest algorithm used to create the
hashes for each node and leaf. Node hashes include the hashes (digests) of their
children. Leaf hashes in the the SAIDs of the data bound to the leaf.

This structure of digesting data and using that digest as a content addressable
identifier that is included with the digested data is exactly the SAID approch.

Thus we generalize the data storage as a SAIDed Information Tree or SIT.

The maximum path length determines the maximum number of leafs and hence nodes
in the tree. But the tree grows down from the root. and only adds nodes
as needed to fork to non-empy leafs. A node with an empty child is always
merged to it first uncommon parent (this is similar to how the
Nervos SMT works). A SIT therefore  never has more nodes than the minimum needed
to store its leaves with non-common path segments.

Sparse Merkle Tree algorithms that do not merge nodes with an empty child
end up with average tree depths greater than Log2(N) where N is the number of
non-empty leaves.

Because paths are derived from cryptographic strength hashes of the leaves, the
distribution of path segments is statistically uniform. The average path length
is a function the statistically approximate uniform distribution that
results from a cryptographic strength digest. Although the worst case for depth
is always the maximum path length, using the digest to generate the path and
only storing forking nodes with non-empty children means that on average the path
length is close to Log2(N) where N is the number of leaves.

To restate, the principal advantage of a SIT comes from the fact that it is
constructed such that the averge depth of the tree is close to log2(N)
where N is the number of non-empty leaves.


A SIT generalizes and simplifies the various security, storage, access and
proofing mechanisms implemented in the different varieties of optimized compact
sparse merkle trees.

Fundamentally from a security perspective, including each part's structure in
its hash (digest), especially its path, ensures that the parts of a given tree
cannot be rearranged to result in different tree but with the same root hash (digest).

This forces an attacker at the very least to perform a successful
collision attack on at least one or more hashes. Using full cryptographic strength
hashes makes any successful collision attack computationally infeasible.

A SIT makes some trade-offs vis-a-vis other sparsed merkle tree like algorithms.
The primary trade-off is that each node in the tree must store its structure
as meta-data in addition to the hashes (SAIDs) of its two children.

The node structure metadata that is unique for each node is the path.
The tree metadata is common to the whole tree and does not need to be stored
with each node.

Given a maximum path length that is the size of a cryptographic digest then
the per node storage is increased by roughly 50% over a tree that only stores
its two children hashes.  (3 hash equivalents versus 2 hash equivalents per node.
In a binary tree increasing the average tree depth by 1  doubles the number of
nodes. Likewise decreasing the average depth of a binary tree by 1 halves the number
of nodes.

N = 2^(D) - 1

Therefore a 100% increase in per node storage that results in a reduction
in average depth of 1 results in a net zero difference in total storage required.

Let the variable S represent the per node storage. Let the variable N represent
the number of nodes.

The total storage for nodes T = N * S
So if we design a new tree algorithm where the new per node storage
S1 = 1.5 * S  (50% increase)
but the new number of nodes is
N1 = N/2 = 0.5 * N
then the new total storage
T1 = N1 * S1 = 1.5* S * 0.5 * N = (1.5)*(0.5)*N * S = 0.75* N * S = 3/4(N*S)
or a $25% improvement.

But as a budget we can double the per node storage if we decrease the average
depth by one and not incur a storage penalty.

Reducing the average tree depth also minimizes the performance requirements of
inclusion and exclusion proofs which are always on the order of the path length
to a given leaf (to proof or disproof its membership in the tree)

So a tree that approaches the minimum of Log2(N) for path length has optimized
performance for the number of reads to generate a proof and the number of operations
to verify a proof.


The stucture metadata and the logic to compute the merged nodes adds to the
overhead to add or remove a node from the tree. But addition and subtraction
happen rarely compared to reading and verifying. Indeed, for many applications
their might be thousands to millions read-verify operations for each add operation
on a given tree. So overall performance is maximized by minimizing tree depth.

