use aiken/fuzz.{int}
use aiken/merkle_patricia_forestry.{
  Branch, Fork, Leaf, MerklePatriciaForestry, Neighbor, Proof, ProofStep,
} as mpf

const guava = "guava[uid: 344]"

const kiwi = "kiwi[uid: 0]"

pub type Tree {
  Branch { prefix: ByteArray, leaves: List<Pair<Int, Tree>> }
  Leaf { suffix: ByteArray, value: ByteArray }
}

test learn() {
  let trie: MerklePatriciaForestry = mpf.empty
  let new: MerklePatriciaForestry = mpf.insert(trie, guava, "🤷", [])
  // 3c6d4fbc80b1264e679cb737ab737f9c9afba51e4718891b3c67c07eec14dfe1
  //   mpf.has(new, guava, "🤷", [])
  let fork: MerklePatriciaForestry =
    mpf.insert(
      new,
      kiwi,
      "🥝",
      [
        Fork {
          skip: 0,
          neighbor: Neighbor { nibble: 4, prefix: #"07", root: mpf.root(new) },
        },
      ],
    )

  //   Leaf {
  //     skip: 0,
  //     key: #"4076d8ab234597ab6a35c03c805381bbc016025b36ff1f7df9c5009e1a8b73ef",
  //     value: #"7c3715aba2db74d565a6ce6cc72f20d9cb4652ddb29efe6268be15b105e40911",
  //   },
  //   Fork {
  //     skip: 0,
  //     neighbor: Neighbor { nibble: 0, prefix: #"07", root: mpf.root(new) },
  //   },
  //   Branch {
  //     skip: 0,
  //     neighbors: #"3c6d4fbc80b1264e679cb737ab737f9c9afba51e4718891b3c67c07eec14dfe1",
  //   },
  mpf.root(fork) == "aaa"
}
