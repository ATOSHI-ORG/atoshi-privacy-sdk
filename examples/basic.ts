/**
 * Basic usage example
 */

import { PrivacyWallet, TransactionBuilder, PrivacyRpcClient } from '../src';

async function main() {
  console.log('🚀 Atoshi Privacy SDK Example\n');

  // 1. Initialize wallet
  console.log('1. Initializing wallet...');
  const wallet = new PrivacyWallet();
  await wallet.init();

  // 2. Generate keypair
  console.log('2. Generating keypair...');
  const keypair = await wallet.generateKeypair();
  console.log(`   Public Key: ${keypair.publicKey.toString().slice(0, 20)}...`);

  // 3. Create a note (simulating deposit)
  console.log('3. Creating note...');
  const note = await wallet.createNote(
    BigInt('1000000000000000000'), // 1 token
    0n, // Native token
    keypair.publicKey
  );
  console.log(`   Commitment: ${note.getCommitment()?.toString().slice(0, 20)}...`);

  // 4. Add note to wallet
  wallet.addNote(note);
  console.log('   Note added to wallet');

  // 5. Check balance
  const balance = wallet.getBalance(0n);
  console.log(`   Balance: ${balance.toString()}`);

  // 6. Export wallet
  console.log('4. Exporting wallet...');
  const backup = wallet.export();
  console.log(`   Backup size: ${backup.length} bytes`);

  // 7. Import wallet
  console.log('5. Importing wallet...');
  const newWallet = new PrivacyWallet();
  await newWallet.init();
  await newWallet.import(backup);
  console.log(`   Imported ${newWallet.getAllNotes().length} notes`);

  // 8. Test RPC client (if node is running)
  console.log('6. Testing RPC client...');
  const rpc = new PrivacyRpcClient('http://localhost:8080');
  
  try {
    const healthy = await rpc.health();
    if (healthy) {
      const state = await rpc.getState();
      console.log(`   Node state: root=${state.merkleRoot.slice(0, 20)}...`);
    } else {
      console.log('   Node not available (this is expected if not running)');
    }
  } catch (e) {
    console.log('   Node not available (this is expected if not running)');
  }

  console.log('\n✅ Example completed!');
}

main().catch(console.error);

