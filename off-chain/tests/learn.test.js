import { inspect } from "node:util";
import assert from "node:assert";
import { DIGEST_LENGTH, digest } from "../lib/crypto.js";
import * as buffer from "node:buffer";
import test from "ava";
import {
  NULL_HASH,
  assertInstanceOf,
  commonPrefix,
  eachLine,
  intoPath,
  merkleProof,
  merkleRoot,
  nibble,
  nibbles,
  sparseVector,
  withEllipsis,
} from "../lib/helpers.js";
import { Leaf, Branch, Proof, Trie } from "../lib/trie.js";

const FULL_FRUITS_LIST = [
  { key: "apple[uid: 58]", value: "🍎" },
  { key: "apricot[uid: 0]", value: "🤷" },
  { key: "banana[uid: 218]", value: "🍌" },
  { key: "blueberry[uid: 0]", value: "🫐" },
  { key: "cherry[uid: 0]", value: "🍒" },
  { key: "coconut[uid: 0]", value: "🥥" },
  { key: "cranberry[uid: 0]", value: "🤷" },
  { key: "fig[uid: 68267]", value: "🤷" },
  { key: "grapefruit[uid: 0]", value: "🤷" },
  { key: "grapes[uid: 0]", value: "🍇" },
  { key: "guava[uid: 344]", value: "🤷" },
  { key: "kiwi[uid: 0]", value: "🥝" },
  { key: "kumquat[uid: 0]", value: "🤷" },
  { key: "lemon[uid: 0]", value: "🍋" },
  { key: "lime[uid: 0]", value: "🤷" },
  { key: "mango[uid: 0]", value: "🥭" },
  { key: "orange[uid: 0]", value: "🍊" },
  { key: "papaya[uid: 0]", value: "🤷" },
  { key: "passionfruit[uid: 0]", value: "🤷" },
  { key: "peach[uid: 0]", value: "🍑" },
  { key: "pear[uid: 0]", value: "🍐" },
  { key: "pineapple[uid: 12577]", value: "🍍" },
  { key: "plum[uid: 15492]", value: "🤷" },
  { key: "pomegranate[uid: 0]", value: "🤷" },
  { key: "raspberry[uid: 0]", value: "🤷" },
  { key: "strawberry[uid: 2532]", value: "🍓" },
  { key: "tangerine[uid: 11]", value: "🍊" },
  { key: "tomato[uid: 83468]", value: "🍅" },
  { key: "watermelon[uid: 0]", value: "🍉" },
  { key: "yuzu[uid: 0]", value: "🤷" },
];

const FRUITS_LIST = [
  { key: "guava[uid: 344]", value: "🤷" }, //6d8ab234597ab6a35c03c805381bbc016025b36ff1f7df9c5009e1a8b73ef
  { key: "kiwi[uid: 0]", value: "🥝" },
  { key: "kumquat[uid: 0]", value: "🤷" },
];

test("Trie.load", async (t) => {
  const trie = await Trie.fromList(FRUITS_LIST);

  // const trie = await Trie.fromList([]);
  // await trie.insert('guava[uid: 344]', '🤷');
  // await trie.insert('kiwi[uid: 0]', '🥝');

  // 4076d8ab234597ab6a35c03c805381bbc016025b36ff1f7df9c5009e1a8b73ef
  // console.log("hash: ", trie.hash);
  console.log("verifyRootHash test: ", verifyRootHash(FRUITS_TRIE));

  t.is(
    inspect(trie),
    unindent`
    ╔═══════════════════════════════════════════════════════════════════╗
    ║ #4acd78f345a686361df77541b2e0b533f53362e36620a1fdd3a13e0b61a3b078 ║
    ╚═══════════════════════════════════════════════════════════════════╝
    ┌─ 0 #520a7f805c5f
    ├─ 1 #58c5e4a29601
    ├─ 2 #c9431d708d20
    ├─ 3 #070a12b8b349
    ├─ 4 #79519b8cdfbd
    ├─ 5 #08434fd717ae
    ├─ 7 #aeb3a9f2e198
    ├─ 8 #b27d20a5187a
    ├─ a #c2f2115774c1
    ├─ b #da0bdb30bf45
    ├─ c #a22a7b4d767a
    ├─ d #0a747d583e2e
    ├─ e #da1771d107c8
    └─ f #117abf0e19fb
`
  );
});

const FRUITS_TRIE = {
  rootHash: "83a5c96888616bc2be9e65b6fab3673d57a862467f89ac14294aec2f2bc73ae3",
  prefix: "4",
  node: {
    0: {
      rootHash:
        "fdd60cf1b7551043644d8018b4840848a520a66d329e67ba602f859fc53394ff",
      prefix: "7",
      node: {
        0: null,
        1: null,
        2: null,
        3: null,
        4: null,
        5: null,
        6: {
          suffix:
            "d8ab234597ab6a35c03c805381bbc016025b36ff1f7df9c5009e1a8b73ef",
          hash: "c538c893306ae9d0c4a7cb8e5fba158973e638421b4ab402eab983bcfcbda3e5",
          key: "guava[uid: 344]",
          value: "🤷",
        },
        7: null,
        8: null,
        9: null,
        a: null,
        b: null,
        c: {
          suffix:
            "58473af4b3e5b24e65481294b0772ed6a7dd793937c6c90179960d154a22",
          hash: "785e20425cf9f1e53062415986b0f4acc0649ae38b28c5780dd664208a1480c9",
          key: "kiwi[uid: 0]",
          value: "🥝",
        },
        d: null,
        e: null,
        f: null,
      },
    },
    1: null,
    2: null,
    3: null,
    4: null,
    5: null,
    6: null,
    7: null,
    8: null,
    9: null,
    a: {
      suffix: "522f84bcda4bebb725d5f2b92af615b57cc1777bb0d8b2c6c18c3e3e6520cd",
      hash: "e0b9d1f525e31d059de29ab22f02291d16566d45bd3a813776f845001bd3aa4b",
      key: "kumquat[uid: 0]",
      value: "🤷",
    },
    b: null,
    c: null,
    d: null,
    e: null,
    f: null,
  },
};

function verifyRootHash(trie) {
  const { rootHash, prefix, node } = trie;

  function computeNodeHash(nodeData) {
    if (nodeData === null) {
      return null;
    }

    if (!nodeData.node) {
      // Leaf node
      const value =
        typeof nodeData.value === "string"
          ? Buffer.from(nodeData.value)
          : nodeData.value;
      assertInstanceOf(Buffer, { value });
      const leafHash = computeLeafHash(nodeData.suffix, digest(value));
      console.log("leafHash: ", leafHash);
      return leafHash;
    } else {
      // branch node
      const childHashes = Object.values(nodeData.node).map((child) => {
        if (child != null) {
          return computeNodeHash(child);
        } else {
          return null;
        }
      });
      const root = merkleRoot(childHashes);
      const branchHash = computeBranchHash(nodeData.prefix, root);
      console.log("branchHash: ", branchHash);
      return branchHash;
    }
  }

  const computedRootHash = computeNodeHash({ node, prefix });
  console.log("computedRootHash: ", computedRootHash);
  console.log("rootHash: ", rootHash);

  return computedRootHash === rootHash;
}

function computeLeafHash(suffix, value) {
  // NOTE:
  // We append the remaining prefix to the value. However, to make this
  // step more efficient on-chain, we append it as a raw bytestring instead of
  // an array of nibbles.
  //
  // If the prefix's length is odd however, we must still prepend one nibble, and
  // then the rest.
  const isOdd = suffix.length % 2 > 0;

  const head = isOdd
    ? Buffer.concat([Buffer.from([0x00]), nibbles(suffix.slice(0, 1))])
    : Buffer.from([0xff]);

  const tail = Buffer.from(isOdd ? suffix.slice(1) : suffix, "hex");

  assert(
    value.length === DIGEST_LENGTH,
    `value must be a ${DIGEST_LENGTH}-byte digest but it is ${value?.toString(
      "hex"
    )}`
  );

  return digest(Buffer.concat([head, tail, value]));
}

function computeBranchHash(prefix, root) {
  // console.log("computeBranchHash prefix: ", prefix);
  // console.log("computeBranchHash root: ", root);
  assert(
    root.length === DIGEST_LENGTH,
    `root must be a ${DIGEST_LENGTH}-byte digest but it is ${root?.toString(
      "hex"
    )}`
  );

  return digest(Buffer.concat([nibbles(prefix), root]));
}

function unindent(str) {
  const lines = str[0].split("\n").filter((n) => n.length > 0);
  const n = (lines[0] || "").length - (lines[0] || "").trimStart().length;
  return lines
    .map((s) => s.slice(n))
    .join("\n")
    .trimEnd();
}