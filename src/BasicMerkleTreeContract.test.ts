import {
  AccountUpdate,
  Field,
  MerkleTree,
  MerkleWitness,
  Mina,
  PrivateKey,
  PublicKey,
} from 'o1js';
import { BasicMerkleTreeContract } from './BasicMerkleTreeContract';

let proofsEnabled = false;

describe('BasicMerkleTreeContract.js', () => {
  /* let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    senderAccount: PublicKey,
    senderKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: BasicMerkleTreeContract;

  beforeAll(() => {
    const Local = Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);
    ({ privateKey: deployerKey, publicKey: deployerAccount } =
      Local.testAccounts[0]);
    ({ privateKey: senderKey, publicKey: senderAccount } =
      Local.testAccounts[1]);
    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new BasicMerkleTreeContract(zkAppAddress);
  }); */

  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    senderAccount: PublicKey,
    senderKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: BasicMerkleTreeContract;

  beforeAll(() => {
    const Local = Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);
    ({ privateKey: deployerKey, publicKey: deployerAccount } =
      Local.testAccounts[0]);
    ({ privateKey: senderKey, publicKey: senderAccount } =
      Local.testAccounts[1]);

    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new BasicMerkleTreeContract(zkAppAddress);
  });

  describe('BasicMerkleTreeContract()', () => {
    it('original', async () => {
      if (proofsEnabled) await BasicMerkleTreeContract.compile();

      // create a new tree
      const height = 20;
      const tree = new MerkleTree(height);
      class MerkleWitness20 extends MerkleWitness(height) {}

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

      const incrementIndex = 522n;
      const incrementAmount = Field(9);

      // get the witness for the current tree
      const witness = new MerkleWitness20(tree.getWitness(incrementIndex));

      // update the leaf locally
      tree.setLeaf(incrementIndex, incrementAmount);

      // update the smart contract
      const txn1 = await Mina.transaction(senderAccount, () => {
        zkApp.update(
          witness,
          Field(0), // leafs in new trees start at a state of 0
          incrementAmount
        );
      });
      await txn1.prove();
      const pendingTx = await txn1.sign([senderKey, zkAppPrivateKey]).send();
      await pendingTx.wait();

      // compare the root of the smart contract tree to our local tree
      console.log(
        `BasicMerkleTree: local tree root hash after send1: ${tree.getRoot()}`
      );
      console.log(
        `BasicMerkleTree: smart contract root hash after send1: ${zkApp.treeRoot.get()}`
      );
    });
  });
});
