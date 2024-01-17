import {
  AccountUpdate,
  Bool,
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

  xit('can deposit a secret', async () => {
    const secret = Field(33);

    const txn = await Mina.transaction(senderAccount, () => {
      zkApp.deposit(secret);
    });
    await txn.prove();
    await txn.sign([senderKey, zkAppPrivateKey]).send();
  });

  describe('Flag checks', () => {
    xit('Valid values, without triggering checks', async () => {
      const expected = true;
      zkApp.checkFlags(Field(0)).assertEquals(expected); // 000000
      zkApp.checkFlags(Field(1)).assertEquals(expected); // 000001
      zkApp.checkFlags(Field(2)).assertEquals(expected); // 000010
      zkApp.checkFlags(Field(3)).assertEquals(expected); // 000011
      zkApp.checkFlags(Field(8)).assertEquals(expected); // 001000
      zkApp.checkFlags(Field(9)).assertEquals(expected); // 001001
      zkApp.checkFlags(Field(10)).assertEquals(expected); // 001010
      zkApp.checkFlags(Field(11)).assertEquals(expected); // 001011
    });

    xit('Valid values, while triggering checks', async () => {
      const expected = true;
      zkApp.checkFlags(Field(4)).assertEquals(expected); // 000100
      zkApp.checkFlags(Field(12)).assertEquals(expected); // 001100
      zkApp.checkFlags(Field(24)).assertEquals(expected); // 011000
      zkApp.checkFlags(Field(25)).assertEquals(expected); // 011001
      zkApp.checkFlags(Field(26)).assertEquals(expected); // 011010
      zkApp.checkFlags(Field(27)).assertEquals(expected); // 011011
      zkApp.checkFlags(Field(28)).assertEquals(expected); // 011100
      zkApp.checkFlags(Field(32)).assertEquals(expected); // 100000
    });

    it('Invalid values', async () => {
      const expected = false;

      zkApp.checkFlags(Field(5)).assertEquals(expected); // 000101 rule3
      zkApp.checkFlags(Field(6)).assertEquals(expected); // 000110 rule3
      zkApp.checkFlags(Field(7)).assertEquals(expected); // 001101 rule3
      zkApp.checkFlags(Field(13)).assertEquals(expected); // 001101 rule3
      zkApp.checkFlags(Field(14)).assertEquals(expected); // 001110 rule3
      zkApp.checkFlags(Field(15)).assertEquals(expected); // 001111 rule3
      zkApp.checkFlags(Field(16)).assertEquals(expected); // 010000 rule2
      zkApp.checkFlags(Field(17)).assertEquals(expected); // 010001 rule2
      zkApp.checkFlags(Field(18)).assertEquals(expected); // 010010 rule2
      zkApp.checkFlags(Field(19)).assertEquals(expected); // 010011 rule2
      zkApp.checkFlags(Field(20)).assertEquals(expected); // 010100 rule2
      zkApp.checkFlags(Field(21)).assertEquals(expected); // 010101 rule2 rule3
      zkApp.checkFlags(Field(22)).assertEquals(expected); // 010110 rule2 rule3
      zkApp.checkFlags(Field(23)).assertEquals(expected); // 010111 rule2 rule3
      zkApp.checkFlags(Field(29)).assertEquals(expected); // 011101 rule3
      zkApp.checkFlags(Field(30)).assertEquals(expected); // 011110 rule3
      zkApp.checkFlags(Field(31)).assertEquals(expected); // 011111 rule3

      for (let i = 33; i < 64; i++) {
        zkApp.checkFlags(Field(i)).assertEquals(expected); // fail at least due to rule 1
      }
    });
  });
});

xdescribe('other', () => {
  it('hmm', async () => {
    const secret = Field(16);
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

    const checked = Field(1)
      .mul(Field(1).sub(Field(0)))
      .equals(Field(0));
    console.log('IS IT', checked, flag2True, flag3True);
    console.log('other', Bool(true) && Bool(false));
  });
});
