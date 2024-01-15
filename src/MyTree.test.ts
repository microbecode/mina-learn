import {
  AccountUpdate,
  Field,
  MerkleTree,
  MerkleWitness,
  Mina,
  Poseidon,
  PrivateKey,
  PublicKey,
} from 'o1js';
import { MyTree } from './MyTree';

let proofsEnabled = false;

xdescribe('MyTree', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    senderAccount: PublicKey,
    senderKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: MyTree;

  let tree: MerkleTree;

  const height = 7;

  class MerkleWitness7 extends MerkleWitness(height) {}

  beforeAll(async () => {
    const Local = Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);
    ({ privateKey: deployerKey, publicKey: deployerAccount } =
      Local.testAccounts[0]);
    ({ privateKey: senderKey, publicKey: senderAccount } =
      Local.testAccounts[1]);

    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new MyTree(zkAppAddress);

    if (proofsEnabled) await MyTree.compile();

    tree = new MerkleTree(height);

    // deploy the smart contract
    const deployTxn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      zkApp.deploy();
      // get the root of the new tree to use as the initial tree root
      zkApp.initState(tree.getRoot());
    });
    await deployTxn.prove();
    deployTxn.sign([deployerKey, zkAppPrivateKey]);

    await deployTxn.send();
  });

  it('can store a hundred values locally', async () => {
    // create a new tree

    const incrementIndex = 2n;
    const incrementAmount = Field(9);

    // get the witness for the current tree
    let witness = new MerkleWitness7(tree.getWitness(incrementIndex));

    // update the leaf locally
    tree.setLeaf(incrementIndex, incrementAmount);

    /*  // update the smart contract
    const txn1 = await Mina.transaction(senderAccount, () => {
      zkApp.update(
        witness,
        Field(0), // leafs in new trees start at a state of 0
        incrementAmount
      );
    });
    await txn1.prove();
    const pendingTx = await txn1.sign([senderKey, zkAppPrivateKey]).send();
    await pendingTx.wait(); */
    const aaa = tree.getNode(6, 2n);

    console.log(
      'node value, hashed',
      aaa.value,
      Poseidon.hash([incrementAmount])
    );

    witness = new MerkleWitness7(tree.getWitness(incrementIndex));
    const computedRoot = witness.calculateRoot(
      Poseidon.hash([incrementAmount])
    );

    console.log('ARE EQUAL?', computedRoot, tree.getRoot());
    // compare the root of the smart contract tree to our local tree
    console.log(
      `BasicMerkleTree: local tree root hash after send1: ${tree.getRoot()}`
    );
    console.log(
      `BasicMerkleTree: smart contract root hash after send1: ${zkApp.treeRoot.get()}`
    );
  });
});

describe('MyTree', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    senderAccount: PublicKey,
    senderKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: MyTree;

  let tree: MerkleTree;

  const height = 8;

  class MerkleWitness8 extends MerkleWitness(height) {}

  beforeAll(async () => {
    const Local = Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);
    ({ privateKey: deployerKey, publicKey: deployerAccount } =
      Local.testAccounts[0]);
    ({ privateKey: senderKey, publicKey: senderAccount } =
      Local.testAccounts[1]);

    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new MyTree(zkAppAddress);

    if (proofsEnabled) await MyTree.compile();

    tree = new MerkleTree(height);

    // deploy the smart contract
    const deployTxn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      zkApp.deploy();
      // get the root of the new tree to use as the initial tree root
      zkApp.initState(tree.getRoot());
    });
    await deployTxn.prove();
    deployTxn.sign([deployerKey, zkAppPrivateKey]);

    await deployTxn.send();
  });

  xit('can store a hundred values locally', async () => {
    class MerkleWitness8 extends MerkleWitness(8) {}
    let tree = new MerkleTree(height);
    for (let i = 0; i < 100; i++) {
      const newValue = Field(i + 1);
      tree.setLeaf(BigInt(i), newValue);
    }
    {
      let witness = new MerkleWitness8(tree.getWitness(7n));
      const computedRoot = witness.calculateRoot(Field(8));
      computedRoot.assertEquals(tree.getRoot(), 'invalid root 1');
    }
    {
      let witness = new MerkleWitness8(tree.getWitness(57n));
      const computedRoot = witness.calculateRoot(Field(58));
      computedRoot.assertEquals(tree.getRoot(), 'invalid root 2');
    }
  });

  it('can store a hundred values in the contract', async () => {
    for (let i = 0; i < 100; i++) {
      const txn = await Mina.transaction(senderAccount, () => {
        const newValue = Field(i + 1);
        tree.setLeaf(BigInt(i), newValue);

        let witness = new MerkleWitness8(tree.getWitness(BigInt(i)));

        zkApp.update(
          witness,
          Field(0), // leafs in new trees start at a state of 0
          newValue
        );
      });
      await txn.prove();
      await txn.sign([senderKey, zkAppPrivateKey]).send();
    }
  });
});
