Background notes on SIT

OC-SMT  core functional support

Notes:

The entry index for a key is calculated by taking the Hash of the key and
treating that as a 256 bit big endian integer. The value for that key is stored
in the leaf node indexed by this entry index number. This index is also the
path down the tree from the root. Where each fork starting at msb 0 is left
1 is right. so a tree with 4 leaves has a 2 bit index or path with the path values.

00, 01, 10, 11
there are three forks, upper fork at msb and two lower forks each at lsb

        top  (upper fork)
    0            1   (lower forks)
0        1    0      1

So the tree stores a leaf hash at location = index = path.
then each of the  lower fork stores the hash of the hash of its concatenated children
where concat order  is left | right
thenb upper fork stores hash of its children which are the two lower forks
also in concat left|righ order

The leaf hash enables a Merkle proof of inclusion where one only needs to
disclose the leaf hash to prove the hashed value is included if one has the
hashed value. Technically for a proof of inclusion the path itself is not needed
for the proof just the sibling hashes along the path.

Addressing of the value uses the index=path so in order to do content addressing
using the merkle tree where the index is bound to the merkle proof then we
consider calculating the index (calculated) as the hash of the indexed value.

We can store the leaf values in a key value store and then use the hash of
the key (index) as the leaf hash. This proves the key in included but not
the value. Its only when the leaf hash includes the stored value that we have
a crypto binding of inclusion of the value itself in the tree.

The leaf hash can be different from index as content address hash. The leaf hash
has to include the value or a committment to the value for crypto proof of inclusion
but a content address computed from the value for the index (path) can be different
from the hash for the leaf. Both have to include the value in the hash but both
can include other stuff so they don't have to be equal.

One trick, is when the leaf hash and index are different computations that
the leaf hash include the index. This forces each leaf hash to be unique and bound
to the location of the leaf hash. This prevents a collision where the same
value could stored in different places in the tree and therefore allow a different
tree to give a valid inclusion proof for the same value.

If the index is the leaf hash then I believe that you also have a collision proof
since there is no way to construct a different tree that hashes the same since
the leave hash is the index so it can only appear in one place in the tree.
So merging up with null leaves is unique.

When the leaf hash and index are not the same hash that one has to worry about
constructing fake tree because the same value could be stored at different keys.

For a tree with a path of 256 bits the total number of leaves is 2^256. The total
humber of nodes is almost double that. The nodes in a full tree of height 256
is 2^(257) -1    In other words the number internal nodes is equal to the number
of leaf nodes - 1.

So using the exact same hash format for leaf values as internal node hashes
means that a full tree must have collisions, but this would never happen in
a practical application so is not a viable risk.

A real risk on a sparse tree are attacks where internal nodes with same hash format
as leaf hashes are used to create an alternate tree with same root hash.
So the protection is called domain separation.

-------------------

A leaf value is hashed to provide the leaf hash at the location in the tree
given by its index.

(Zero is a special unique value that should not correspond to a real leaf's value.
(Can we use None in python) In Ethereum world they use the string `0x00000...`

The docs for merkle trees get this mixed up. Sometimes when they say 0 they
mean literally a 0 bit but other times they mean a special hash value.

key in sparse merkle tree is the concatenation of the path. A key of 256 bits
is a left-right forking path down tree.
If a bit position is 0 go left else 1 go right
There are 2^256 keys  value (0...0) to (1...1)

In a binary Merkle tree, a 0 typically represents the left child branch and
a 1 represents the right child branch when navigating from the root down toward a leaf.
• 0 = Left Branch: Moving down to the left child node in the pair.
• 1 = Right Branch: Moving down to the right child node in the pair.

How Branch Direction Works

• Path Navigation: When walking from the root to a leaf, each step in the path
or Merkle proof is designated by a bit (such as 0 or 1) so the verifier knows
whether the sibling hash should be concatenated on the left or on the right
during hash reconstruction.
• Concatenation Order: Parent hashes are computed as H(left || right),
meaning the position (left vs. right) dictates the sequence in which hashes are joined together.
• Bitwise Indexing: In sparse or binary-indexed structures, binary path digits
correspond directly to choosing the left (0) or right (1) branch at each depth level of the tree.


Nervos
Optimization 1: Zero-value optimized hash function
We define the node merging function as following:
if L == 0, return R
if R == 0, return L
otherwise return sha256(L, R)

With optimization 1, we do not need the pre-calculated hash-set.
For a default SMT, all the intermediate nodes are zero values.
Thus, we only need to calculate the hash for non-zero nodes and return zero
for the default nodes.



There’s only one issue that remains. The optimized hash function produces
the same value from different key-value pairs, for example:
merge(N, 0) == merge(0, N).
This behavior opens a weak point for the SMT. An attacker may construct a
collision of merkle root from a faked key-value map.

To fix this, we use the result of hash(key | value) as a leaf’s hash.
For example:
merge(N, leaf_hash(N, 0)) != merge(0, leaf_hash(0, N))
because the leaf_hash(N, 0) is never equals to leaf_hash(0, N) if N != 0,
the attacker can’t construct a collision attacking.

Additionally, we store leaf_hash -> value in a map to keep the reference
to the original value.

We can prove the security of this construction.

Since the key is included in the leaf’s hash, and key is unique in SMT,
no matter what the value is, the leaf_hash(key, value) is unique.
Each node is either merged by two different hashes or merged by a hash with
a zero-value. We already knew that all leaves have a unique hash, so their
parent nodes also have a unique hash, and so on.
The parent of these parent nodes also has a unique hash until the root of the tree.
We got zero value merkle root if the tree is empty.
Otherwise, the root is merged from its two children nodes. Any changes in the
leaves will also change the root hash.
So we believe this construction is security because we can’t construct
a collision of merkle root.


Optimization 2: abstract storage mechanics

In the classic construction of SMT: We store a branch node with its two children
as
Node {left, right}.

We have implemented branch node as the following data structure:

pub struct BranchNode
{
    pub left: MergeValue,
    pub right: MergeValue,
}
When left and right are both zero, it's not needed to store this zero node.

We still face problem: too many branch nodes in real world.
Assuming we have only one leaf node in SMT, there are still 255 branch nodes.
They are all ancestors of the only leaf node.
The amount of branch nodes can be easily reached to millions.
When the leaf nodes grows to above 10k, it can consume a lot of memory.
We realize that the databases or kv-store will be used in SMT proof.
Therefore, we introduce a abstracted layer of storage mechanics, trait Store as following:

/// Trait for customize backend storage
pub trait Store<V>
{
    fn get_branch(&self, branch_key: &BranchKey) -> Result<Option<BranchNode>, Error>;
    fn get_leaf(&self, leaf_key: &H256) -> Result<Option<V>, Error>;
    fn insert_branch(&mut self, node_key: BranchKey, branch: BranchNode) -> Result<(), Error>;
    fn insert_leaf(&mut self, leaf_key: H256, leaf: V) -> Result<(), Error>;
    fn remove_branch(&mut self, node_key: &BranchKey) -> Result<(), Error>;
    fn remove_leaf(&mut self, leaf_key: &H256) -> Result<(), Error>;
}

If branch nodes are not many, we can put them all in memory.
By default, we have such DefaultStore:

pub struct DefaultStore<V>
{
    branches_map: Map<BranchKey, BranchNode>,
    leaves_map: Map<H256, V>,
}

If branch nodes are too many, it's better to implement a database backend.
We suggest RocksDB: an embedded persistent key-value store for fast storage.
Here is an example of RocksDB backend implementation.
https://github.com/quake/smt-rocksdb-store

This store mechanics is only used in making SMT proof.
It doesn't affect on-chain SMT verification which is still very fast and memory-efficient.

Optimization 3: Shortcut nodes

We can optimize the storage space and performance by using shortcut nodes.
A shortcut is a node that has only one leaf node, it can be merged with its parent node.
The shortcut node is only used in the storage, it doesn't affect the verification process.
We implement it as following algorithm: Aergo Trie.
https://github.com/aergoio/aergo/tree/master/pkg/trie
This algorithm is enabled by trie feature, which is disabled by default.



Rust code

fn common_height(key1, key2)
{
    for i in 255..0
    {
        if key1.get_bit(i) != key2.get_bit(i)
        {
            // common height
            return i;
        }
    }
    return 0;
}

// get children at height
// return value is (left, right)
fn children(branch_node, height)
{
    let is_rhs = branch_node.key.get_bit(height);
    if is_rhs
    {
        return (branch_node.sibling, branch_node.node)

    }
    else
    {
        return (branch_node.node, branch_node.sibling)
    }
}

fn get(key)
{

    let node = root;

    // path order by height

    let path = BTreeMap::new();

    loop
    {
        let branch_node = match map.get(node)
        {
            Some(b) => b,
            None => break,
        }
        // common height may be lower than node.fork_height
        let height = max(common_height(key, node.key), node.fork_height);
        if height > node.fork_height
        {
            // node is sibling, end search
            path.push(heignt, node);
            break;
        }

        // node is parent
        // extract children position from branch
        let (left, right) = children(branch_node, height);

        // extract key positon
        let is_right = key.get_bit(height);
        if is_right
        {
            path.push(height, left);
            node = right;
        }
        else
        {
            path.push(height, right);
            node = left;
        }
    }
    return self.leaves[node];
}

use sparse_merkle_tree::
{
    blake2b::Blake2bHasher, default_store::DefaultStore,
    error::Error, MerkleProof,
    SparseMerkleTree, traits::Value, H256
};
use blake2b_rs::{Blake2b, Blake2bBuilder};

// define SMT
type SMT = SparseMerkleTree<Blake2bHasher, Word, DefaultStore<Word>>;

// define SMT value
#[derive(Default, Clone)]
pub struct Word(String);
impl Value for Word {
   fn to_h256(&self) -> H256
   {
       if self.0.is_empty()
       {
           return H256::zero();
       }
       let mut buf = [0u8; 32];
       let mut hasher = new_blake2b();
       hasher.update(self.0.as_bytes());
       hasher.finalize(&mut buf);
       buf.into()
   }
   fn zero() -> Self
   {
       Default::default()
   }
}

// helper function
fn new_blake2b() -> Blake2b
{
    Blake2bBuilder::new(32).personal(b"SMT").build()
}

fn construct_smt()
{
    let mut tree = SMT::default();
    for (i, word) in "The quick brown fox jumps over the lazy dog"
        .split_whitespace()
        .enumerate()
    {
        let key: H256 =
        {
            let mut buf = [0u8; 32];
            let mut hasher = new_blake2b();
            hasher.update(&(i as u32).to_le_bytes());
            hasher.finalize(&mut buf);
            buf.into()
        };
        let value = Word(word.to_string());
        // insert key value into tree
        tree.update(key, value).expect("update");
    }


    println!("SMT root is {:?} ", tree.root());
}

