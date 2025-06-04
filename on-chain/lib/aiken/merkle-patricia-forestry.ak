//// A Merkle Patricia Forestry (MPF) is a key:value structure which stores
//// elements in a radix trie folowing a key, and where nodes also contains a
//// cryptographic hash digest of the sub-trie or value they hold.
////
//// This library enforces (through hashing) that we use trie of radix 16
//// (hexadecimal alphabet). This means that each level in the trie has up to
//// 16 branches.
////
//// An MPF allows for checking membership, insertion and deletion in the trie
//// using only root hashes and a succinct proofs. They are quite efficient in
//// both cpu and mem units. And they also provide proofs that are a / lot smaller
//// than traditional Merkle Patricia Trie; proofs remain however the / main
//// limiting factor.
////
//// Here's a little table that summarizes the average proof's sizes in bytes
//// given a number of elements.
////
//// We also consider the average memory and CPU execution units for verifying
//// a proof for various sizes. Note that [`insert`](#insert) and
//// [`delete`](#delete) require **two** proofs verifications.
////
//// size | avg proof size | avg proof mem | avg proof cpu |
//// ---: | -------------: | ------------: | ------------: |
////  10² |          250   | 70K           | 28M           |
////  10³ |          350   | 100K          | 42M           |
////  10⁴ |          460   | 130K          | 56M           |
////  10⁵ |          560   | 160K          | 70M           |
////  10⁶ |          670   | 190K          | 84M           |
////  10⁷ |          780   | 220K          | 98M           |
////  10⁸ |          880   | 250K          | 112M          |
////  10⁹ |          990   | 280K          | 126M          |

use aiken/builtin.{blake2b_256, slice_bytearray}
use aiken/collection/list
use aiken/merkle_patricia_forestry/helpers.{combine, nibble, nibbles, suffix}
use aiken/merkle_patricia_forestry/merkling.{
  merkle_16, null_hash, sparse_merkle_16,
}
use aiken/primitive/bytearray

// -----------------------------------------------------------------------------
// ------------------------------------------------------------------- Constants
// -----------------------------------------------------------------------------

/// # of bytes
const blake2b_256_digest_size = 32

// -----------------------------------------------------------------------------
// ------------------------------------------------------ Merkle Patricia Forest
// -----------------------------------------------------------------------------

/// since          | <code>1.0.0</code>
/// ---            | ---
///
/// A Merkle Patricia Forestry, typically constructed from a root hash digest
/// using [`from_root`](#from_root).
///
/// ```aiken
/// let trie =
///   mpf.from_root(
///     #"225a4599b804ba53745538c83bfa699ecf8077201b61484c91171f5910a4a8f9",
///   )
/// ```
pub opaque type MerklePatriciaForestry {
  root: ByteArray,
}

// ## Constructing

/// since | <code>1.0.0</code>
/// ---   | ---
///
/// Construct a new [MerklePatriciaForestry](#MerklePatriciaForestry) from its
/// root. On-chain, we actually only need the / root
///
/// The root MUST be 32-bytes long. For an empty trie, see [empty](#empty).
pub fn from_root(root: ByteArray) -> MerklePatriciaForestry {
  expect bytearray.length(root) == blake2b_256_digest_size
  MerklePatriciaForestry { root }
}

/// since | <code>2.0.0</code>
/// ---   | ---
///
/// Construct a new empty [MerklePatriciaForestry](#MerklePatriciaForestry).
pub const empty: MerklePatriciaForestry =
  MerklePatriciaForestry { root: null_hash }

// ## Querying

/// since | <code>1.0.0</code>
/// ---   | ---
///
/// Check whether a [MerklePatriciaForestry](#MerklePatriciaForestry) is empty.
///
/// ```aiken
/// mpf.is_empty(mpf.empty()) == True
/// ```
pub fn is_empty(self: MerklePatriciaForestry) -> Bool {
  self.root == null_hash
}

/// since | <code>1.0.0</code>
/// ---   | ---
///
/// Test whether an element is present in the trie with a specific value. This
/// requires a [Proof](#Proof) of inclusion for the element. The latter can be
/// obtained off-chain from the whole trie containing the element.
///
/// Returns `False` when the element isn't in the tree.
pub fn has(
  self: MerklePatriciaForestry,
  key: ByteArray,
  value: ByteArray,
  proof: Proof,
) -> Bool {
  including(key, value, proof) == self.root
}

// # Modifying

/// since | <code>1.0.0</code>
/// ---   | ---
///
/// Insert an element in the trie. This requires a [Proof](#Proof) of inclusion
/// for the element. The latter can be obtained off-chain from the whole trie
/// containing the element.
///
/// #### Fails when
///
/// - The [Proof](#Proof) is invalid.
/// - There's already an element in the trie at the given key.
pub fn insert(
  self: MerklePatriciaForestry,
  key: ByteArray,
  value: ByteArray,
  proof: Proof,
) -> MerklePatriciaForestry {
  expect excluding(key, proof) == self.root
  MerklePatriciaForestry { root: including(key, value, proof) }
}

/// since | <code>1.0.0</code>
/// ---   | ---
///
/// Remove an element from the trie. This requires a [Proof](#Proof) of
/// inclusion for the element. The latter can be obtained off-chain from the
/// whole trie containing the element.
///
/// #### Fails when
///
/// - the [Proof](#Proof) is invalid
/// - there is no element in the trie at the given key
pub fn delete(
  self: MerklePatriciaForestry,
  key: ByteArray,
  value: ByteArray,
  proof: Proof,
) -> MerklePatriciaForestry {
  expect including(key, value, proof) == self.root
  MerklePatriciaForestry { root: excluding(key, proof) }
}

/// since          | <code>1.1.0</code>
/// ---            | ---
///
/// Update an element in the trie with a a new value. This requires a [Proof](#Proof)
/// of the old element, to ensure its in the list, and a [Proof](#Proof) of the new
/// element, to re-add it.
///
/// Can be thought of as a delete, followed by an insert, but is able to do it with one fewer
/// membership checks
///
/// #### fails when
///
/// - The [Proof](#Proof) is invalid.
/// - There's no element in the trie at the given key.
pub fn update(
  self: MerklePatriciaForestry,
  key: ByteArray,
  proof: Proof,
  old_value: ByteArray,
  new_value: ByteArray,
) {
  expect including(key, old_value, proof) == self.root
  // If we were doing a delete followed by an insert, we'd end up checking the `excluding` again here
  MerklePatriciaForestry { root: including(key, new_value, proof) }
}

// ## Transforming

/// since | <code>1.1.0</code>
/// ---   | ---
///
/// Get the root hash digest of a [MerklePatriciaForestry](#MerklePatriciaForestry).
pub fn root(self: MerklePatriciaForestry) -> ByteArray {
  self.root
}

// -----------------------------------------------------------------------------
// ----------------------------------------------------------------------- Proof
// -----------------------------------------------------------------------------

/// since          | <code>1.0.0</code>
/// ---            | ---
///
/// A Proof is a list of [Step](#Step) which is processed from left to right,
/// which corresponds to the neighbor nodes along the _path_ to the element being
/// proved.
///
/// See [merkle-patricia-forestry/off-chain :: Proving](https://github.com/aiken-lang/merkle-patricia-forestry/tree/main/off-chain#proving)
/// for details about generating a proof.
pub type Proof =
  List<ProofStep>

/// since          | <code>1.0.0</code>
/// ---            | ---
///
/// We distinguish three kind of proof steps: Branch, Fork and Leaf. Each step
/// contains a `skip` value which corresponds to the length of the common prefix
/// at that particular level.
///
/// The details of each level is documented [in the wiki :: Proof Format](https://github.com/aiken-lang/merkle-patricia-forestry/wiki/Proof-format).
pub type ProofStep {
  Branch { skip: Int, neighbors: ByteArray }
  Fork { skip: Int, neighbor: Neighbor }
  Leaf { skip: Int, key: ByteArray, value: ByteArray }
}

/// since          | <code>1.0.0</code>
/// ---            | ---
///
/// A neighbor node used in a proof. See [Proof](#Proof) for details.
pub type Neighbor {
  nibble: Int,
  prefix: ByteArray,
  root: ByteArray,
}

// -----------------------------------------------------------------------------
// ------------------------------------------------------------------- including
// -----------------------------------------------------------------------------

/// Compute the resulting hash digest from a 'Proof' associated with an
/// arbitrary value. If the proof is valid, the result is the root hash of
/// the target trie.
///
/// This can be used to check for membership of an element in a trie.
fn including(key: ByteArray, value: ByteArray, proof: Proof) -> ByteArray {
  do_including(blake2b_256(key), blake2b_256(value), 0, proof)
}

fn do_including(
  path: ByteArray,
  value: ByteArray,
  cursor: Int,
  proof: Proof,
) -> ByteArray {
  when proof is {
    [] -> combine(suffix(path, cursor), value)

    [Branch { skip, neighbors }, ..steps] -> {
      let nextCursor = cursor + 1 + skip
      let root = do_including(path, value, nextCursor, steps)
      do_branch(path, cursor, nextCursor, root, neighbors)
    }

    [Fork { skip, neighbor }, ..steps] -> {
      let nextCursor = cursor + 1 + skip
      let root = do_including(path, value, nextCursor, steps)
      do_fork(path, cursor, nextCursor, root, neighbor)
    }

    [Leaf { skip, key, value: neighborValue }, ..steps] -> {
      let nextCursor = cursor + 1 + skip
      let root = do_including(path, value, nextCursor, steps)

      let neighbor =
        Neighbor {
          prefix: suffix(key, nextCursor),
          nibble: nibble(key, nextCursor - 1),
          root: neighborValue,
        }

      do_fork(path, cursor, nextCursor, root, neighbor)
    }
  }
}

// -----------------------------------------------------------------------------
// ------------------------------------------------------------------- excluding
// -----------------------------------------------------------------------------

/// Similar to [including](#including), but computes the root obtained from
/// walking the proof without including the element.
///
/// So this mainly changes the last step.
fn excluding(key: ByteArray, proof: Proof) -> ByteArray {
  do_excluding(blake2b_256(key), 0, proof)
}

fn do_excluding(path: ByteArray, cursor: Int, proof: Proof) -> ByteArray {
  when proof is {
    [] -> null_hash

    [Branch { skip, neighbors }, ..steps] -> {
      let nextCursor = cursor + 1 + skip
      let root = do_excluding(path, nextCursor, steps)
      do_branch(path, cursor, nextCursor, root, neighbors)
    }

    [Fork { neighbor, .. }] -> {
      let prefix = bytearray.push(neighbor.prefix, neighbor.nibble)
      combine(prefix, neighbor.root)
    }

    [Fork { skip, neighbor }, ..steps] -> {
      let nextCursor = cursor + 1 + skip
      let root = do_excluding(path, nextCursor, steps)
      do_fork(path, cursor, nextCursor, root, neighbor)
    }

    [Leaf { key, value, .. }] -> combine(suffix(key, cursor), value)

    [Leaf { skip, key, value }, ..steps] -> {
      let nextCursor = cursor + 1 + skip
      let root = do_excluding(path, nextCursor, steps)

      let neighbor =
        Neighbor {
          prefix: suffix(key, nextCursor),
          nibble: nibble(key, cursor),
          root: value,
        }

      do_fork(path, cursor, nextCursor, root, neighbor)
    }
  }
}

// -----------------------------------------------------------------------------
// --------------------------------------------------------- do_branch / do_fork
// -----------------------------------------------------------------------------

fn do_branch(
  path: ByteArray,
  cursor: Int,
  nextCursor: Int,
  root: ByteArray,
  neighbors: ByteArray,
) -> ByteArray {
  let branch = nibble(path, nextCursor - 1)

  let prefix = nibbles(path, cursor, nextCursor - 1)

  combine(
    prefix,
    merkle_16(
      branch,
      root,
      slice_bytearray(0, blake2b_256_digest_size, neighbors),
      slice_bytearray(32, blake2b_256_digest_size, neighbors),
      slice_bytearray(64, blake2b_256_digest_size, neighbors),
      slice_bytearray(96, blake2b_256_digest_size, neighbors),
    ),
  )
}

fn do_fork(
  path: ByteArray,
  cursor: Int,
  nextCursor: Int,
  root: ByteArray,
  neighbor: Neighbor,
) -> ByteArray {
  let branch = nibble(path, nextCursor - 1)

  let prefix = nibbles(path, cursor, nextCursor - 1)

  expect branch != neighbor.nibble

  combine(
    prefix,
    sparse_merkle_16(
      branch,
      root,
      neighbor.nibble,
      combine(neighbor.prefix, neighbor.root),
    ),
  )
}

// -----------------------------------------------------------------------------
// ---------------------------------------------------- Custom Tree Computations
// -----------------------------------------------------------------------------

// Experimental function to compute the hash of an entire tree. The structure
// is expected to be a valid tree, and branch nodes are given in a sorted order

pub type Tree {
  TreeBranch { nibble: ByteArray, nodes: List<Pair<Int, Tree>> }
  TreeLeaf { key: ByteArray, value: ByteArray }
}

pub fn compute_tree_hash(tree: Tree, prefix_nibbles: ByteArray) -> ByteArray {
  when tree is {
    TreeBranch { nibble, nodes } -> {
      // Maybe we can do something without reversing the list?
      let child_hashes =
        list.reverse(
          build_child_hashes(
            [],
            nodes,
            0,
            bytearray.concat(prefix_nibbles, nibble),
          ),
        )
      let merkle_root = build_merkle_hash(child_hashes)
      compute_branch_hash(nibble, merkle_root)
    }
    TreeLeaf { key, value } -> {
      let cursor = bytearray.length(prefix_nibbles)
      let key_nibbles = nibbles(key, 0, cursor)
      if key_nibbles == prefix_nibbles {
        compute_leaf_hash(key, value, cursor)
      } else {
        trace @"key_nibbles": key_nibbles
        trace @"prefix_nibbles": prefix_nibbles
        fail @"invalid tree, prefix does not match key"
      }
    }
  }
}

// This operation is going to be inefficient since we're pushing to the end of the list repeatedly. 
// TODO: optimize
fn build_merkle_hash(child_hashes: List<ByteArray>) -> ByteArray {
  when child_hashes is {
    [x] -> x
    [x, y, ..xs] -> build_merkle_hash(list.concat(xs, [combine(x, y)]))
    _ -> fail @"invalid child hashes, must be a non-empty list"
  }
}

fn build_child_hashes(
  child_hashes: List<ByteArray>,
  nodes: List<Pair<Int, Tree>>,
  cursor: Int,
  prefix_nibbles: ByteArray,
) -> List<ByteArray> {
  if cursor == 16 {
    child_hashes
  } else {
    let maybe_node_head = list.head(nodes)
    when maybe_node_head is {
      None ->
        // If we reach the end of the nodes list, we fill the remaining child hashes with null_hash
        build_child_hashes(
          list.push(child_hashes, null_hash),
          nodes,
          cursor + 1,
          prefix_nibbles,
        )
      Some(node_head) -> {
        // If we have a node, we check its index and compute the hash accordingly
        let node_index = node_head.1st
        if cursor > node_index {
          fail @"invalid tree, children must be sorted by index"
        } else {
          expect Some(tail_nodes) = list.tail(nodes)
          if cursor == node_index {
            let new_prefix =
              bytearray.concat(
                prefix_nibbles,
                bytearray.from_int_big_endian(cursor, 1),
              )
            build_child_hashes(
              list.push(
                child_hashes,
                compute_tree_hash(node_head.2nd, new_prefix),
              ),
              tail_nodes,
              cursor + 1,
              prefix_nibbles,
            )
          } else {
            build_child_hashes(
              list.push(child_hashes, null_hash),
              nodes,
              cursor + 1,
              prefix_nibbles,
            )
          }
        }
      }
    }
  }
}

fn compute_leaf_hash(key: ByteArray, value: ByteArray, cursor: Int) -> ByteArray {
  combine(suffix(key, cursor), blake2b_256(value))
}

fn compute_branch_hash(nibble: ByteArray, root: ByteArray) -> ByteArray {
  combine(nibble, root)
}
