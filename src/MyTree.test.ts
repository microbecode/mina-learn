import {
  AccountUpdate,
  Field,
  Gadgets,
  MerkleTree,
  MerkleWitness,
  Mina,
  Poseidon,
  PrivateKey,
  Provable,
  PublicKey,
} from 'o1js';
import { MyTree } from './MyTree';

let proofsEnabled = false;

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

  beforeEach(async () => {
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

  xit('can store a hundred values in the contract', async () => {
    for (let i = 0; i < 3; i++) {
      const txn = await Mina.transaction(senderAccount, () => {
        const newValue = Field(i + 1);
        tree.setLeaf(BigInt(i), newValue);

        let witness = new MerkleWitness8(tree.getWitness(BigInt(i)));

        zkApp.addValue(
          witness,
          Field(0), // leafs in new trees start at a state of 0
          newValue
        );
      });
      await txn.prove();
      await txn.sign([senderKey, zkAppPrivateKey]).send();

      zkApp.treeRoot.get().assertEquals(tree.getRoot(), 'not matching roots');
    }
  });

  it('can deposit a secret', async () => {
    const secret = Field(33);

    const txn = await Mina.transaction(senderAccount, () => {
      zkApp.deposit(secret);
    });
    await txn.prove();
    await txn.sign([senderKey, zkAppPrivateKey]).send();
  });
});

xdescribe('other', () => {
  it('hmm', async () => {
    const secret = Field(18);

    let flag1True = Provable.if(
      Gadgets.and(secret, Field(32), 6).equals(0),
      Field(0),
      Field(1)
    );
    let flag2True = Provable.if(
      Gadgets.and(secret, Field(16), 5).equals(0),
      Field(0),
      Field(1)
    );
    let flag3True = Provable.if(
      Gadgets.and(secret, Field(8), 4).equals(0),
      Field(0),
      Field(1)
    );
    let flag4True = Provable.if(
      Gadgets.and(secret, Field(4), 3).equals(0),
      Field(0),
      Field(1)
    );
    let flag5True = Provable.if(
      Gadgets.and(secret, Field(2), 20).equals(0),
      Field(0),
      Field(1)
    );
    let flag6True = Provable.if(
      Gadgets.and(secret, Field(1), 1).equals(0),
      Field(0),
      Field(1)
    );

    console.log(
      'flags',
      '\n',
      flag1True,
      '\n',
      flag2True,
      '\n',
      flag3True,
      '\n',
      flag4True,
      '\n',
      flag5True,
      '\n',
      flag6True
    );

    // If flag 1 is true, then all other flags must be false
    // flag1True * ((1 - flag2True) + (1 - flag2True) + ... (1 - flag6True)) = 0
    flag1True
      .mul(
        Field(1)
          .sub(flag2True)
          .add(Field(1).sub(flag3True))
          .add(Field(1).sub(flag4True))
          .add(Field(1).sub(flag5True))
          .add(Field(1).sub(flag6True))
      )
      .equals(Field(0));

    // If flag 2 is true, then flag 3 must also be true.
    // flag2True * (1 - flag3True) = 0
    flag2True.mul(Field(1).sub(flag3True)).equals(Field(0));

    // If flag 4 is true, then flags 5 and 6 must be false.
    // flag4True * (flag5True + flag6True) = 0
    flag4True.mul(flag5True.add(flag6True)).equals(Field(0));
  });
});
