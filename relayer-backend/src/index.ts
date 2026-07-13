import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import nacl from 'tweetnacl';
import { ethers } from 'ethers';
import { 
    Keypair, TransactionInstruction, PublicKey,
    TransactionMessage, VersionedTransaction,
    SystemProgram 
} from '@solana/web3.js';
import bs58 from 'bs58';
import dns from 'dns';
import axios from 'axios';
import crypto from 'crypto';

const LENS_MINT_ABI = [
    "function mintFromHardware(address to, string calldata uuid, bytes32 sha256Hash, string calldata pHash) external returns (uint256)"
];

dns.setDefaultResultOrder('ipv4first');
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

interface MetadataPayload {
    uuid: string;
    sha256: string;
    phash: string;
    pubkey: string;
    timestamp: number;
    chain: string;
}

interface SignedEnvelope {
    payload_json: string;
    signature: string;
}

const evmRpc = process.env.EVM_RPC_URL ? process.env.EVM_RPC_URL.trim() : '';
const evmKey = process.env.EVM_PRIVATE_KEY ? process.env.EVM_PRIVATE_KEY.trim() : '';
const solRpc = process.env.SOLANA_RPC_URL ? process.env.SOLANA_RPC_URL.trim() : 'https://api.devnet.solana.com';
const solKey = process.env.SOLANA_PRIVATE_KEY ? process.env.SOLANA_PRIVATE_KEY.trim() : '';

const evmProvider = evmRpc ? new ethers.JsonRpcProvider(evmRpc) : null;
const evmWallet = (evmKey && evmProvider) ? new ethers.Wallet(evmKey, evmProvider) : null;
const solanaKeypair = solKey ? Keypair.fromSecretKey(bs58.decode(solKey)) : null;

const HTTP_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'User-Agent': 'Mozilla/5.0'
};

app.post('/api/v1/mint', async (req: Request, res: Response) => {
    try {
        const { payload_json, signature } = req.body as SignedEnvelope;

        if (!payload_json || !signature) {
            return res.status(400).json({ error: 'Missing payload_json or signature' });
        }

        let payload: MetadataPayload;
        try {
            payload = JSON.parse(payload_json);
        } catch (e: any) {
            return res.status(400).json({ error: 'Invalid payload_json format' });
        }

        const { pubkey, chain, sha256, phash, uuid } = payload;

        try {
            const pubKeyBytes = Buffer.from(pubkey, 'hex');
            const sigBytes = Buffer.from(signature, 'hex');
            const msgBytes = Buffer.from(payload_json, 'utf8');

            const isValid = nacl.sign.detached.verify(msgBytes, sigBytes, pubKeyBytes);
            if (!isValid) {
                return res.status(401).json({ error: 'Signature verification failed' });
            }
        } catch (e: any) {
            return res.status(401).json({ error: 'Invalid crypto format' });
        }

        console.log(`\n[Relayer] Auth OK | UUID: ${uuid} | Target: ${chain.toUpperCase()}`);

        let txHash = '';

        if (chain.toLowerCase() === 'evm') {
            const evmContractAddress = process.env.EVM_CONTRACT_ADDRESS ? process.env.EVM_CONTRACT_ADDRESS.trim() : '';
            if (!evmWallet || !evmContractAddress) {
                return res.status(500).json({ error: 'EVM config missing' });
            }
            
            const lensContract = new ethers.Contract(evmContractAddress, LENS_MINT_ABI, evmWallet);
            const sha256Bytes32 = "0x" + sha256; 
            
            try {
                console.log(`[Relayer] Executing EVM Contract Mint...`);
                const tx = await lensContract.mintFromHardware(
                    evmWallet.address,
                    uuid,
                    sha256Bytes32,
                    phash
                );
                txHash = tx.hash;
            } catch (e: any) {
                console.error(`[Relayer] EVM Error:`, e.message);
                return res.status(502).json({ error: `EVM mint failed: ${e.message}` });
            }

        } else if (chain.toLowerCase() === 'solana') {
            const solanaProgramIdStr = process.env.SOLANA_PROGRAM_ID ? process.env.SOLANA_PROGRAM_ID.trim() : '';
            if (!solanaKeypair || !solanaProgramIdStr) {
                return res.status(500).json({ error: 'Solana config missing' });
            }

            const programId = new PublicKey(solanaProgramIdStr);
            const sha256Buffer = Buffer.from(sha256, 'hex');

            if (sha256Buffer.length !== 32) {
                return res.status(400).json({ error: 'Invalid sha256 length' });
            }

            // PDA Derivation
            const [cameraRecordPDA] = PublicKey.findProgramAddressSync(
                [Buffer.from("camera"), sha256Buffer],
                programId
            );

            // Anchor Discriminator
            const sighash = crypto.createHash('sha256').update('global:mint_from_hardware').digest().subarray(0, 8);

            // Borsh Serialization
            const uuidBuffer = Buffer.from(uuid, 'utf8');
            const uuidLen = Buffer.alloc(4);
            uuidLen.writeUInt32LE(uuidBuffer.length);

            const phashBuffer = Buffer.from(phash, 'utf8');
            const phashLen = Buffer.alloc(4);
            phashLen.writeUInt32LE(phashBuffer.length);

            const dataBuffer = Buffer.concat([
                sighash,
                uuidLen, uuidBuffer,
                sha256Buffer, // Fixed 32 bytes array, no length prefix
                phashLen, phashBuffer
            ]);

            const ix = new TransactionInstruction({
                programId: programId,
                keys: [
                    { pubkey: cameraRecordPDA, isSigner: false, isWritable: true },
                    { pubkey: solanaKeypair.publicKey, isSigner: true, isWritable: true },
                    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
                ],
                data: dataBuffer,
            });

            console.log(`[Relayer] Anchor PDA: ${cameraRecordPDA.toBase58()}`);
            console.log(`[Relayer] Fetching Blockhash...`);
            
            const rpcNodes = [
                solRpc,
                'https://api.devnet.solana.com',
                'https://rpc.ankr.com/solana_devnet',
                'https://api.testnet.solana.com'
            ];

            let recentBlockhash = '';
            let successfulRpc = '';

            for (const rpc of rpcNodes) {
                try {
                    const cleanRpc = rpc.replace(/^SOLANA_RPC_URL=/, '').trim();
                    const { data } = await axios.post(cleanRpc, {
                        jsonrpc: '2.0', id: 1, 
                        method: 'getLatestBlockhash', 
                        params: [{ commitment: 'finalized' }]
                    }, { headers: HTTP_HEADERS, timeout: 5000 });

                    const parsedData = Array.isArray(data) ? data[0] : data;
                    
                    if (parsedData?.result?.value?.blockhash) {
                        recentBlockhash = parsedData.result.value.blockhash;
                        successfulRpc = cleanRpc;
                        break;
                    }
                } catch (e: any) {
                    continue;
                }
            }

            if (!recentBlockhash) {
                return res.status(502).json({ error: 'RPC nodes failed' });
            }

            const messageV0 = new TransactionMessage({
                payerKey: solanaKeypair.publicKey,
                recentBlockhash: recentBlockhash,
                instructions: [ix],
            }).compileToV0Message();

            const transaction = new VersionedTransaction(messageV0);
            transaction.sign([solanaKeypair]);
            
            console.log(`[Relayer] Broadcasting via [${successfulRpc}]...`);

            const serializedTx = Buffer.from(transaction.serialize()).toString('base64');
            try {
                const { data: sendData } = await axios.post(successfulRpc, {
                    jsonrpc: '2.0', id: 2, 
                    method: 'sendTransaction', 
                    params: [serializedTx, { 
                        encoding: 'base64', 
                        skipPreflight: true, 
                        maxRetries: 3 
                    }]
                }, { headers: HTTP_HEADERS, timeout: 15000 });

                const parsedSend = Array.isArray(sendData) ? sendData[0] : sendData;
                
                if (parsedSend.error) throw new Error(parsedSend.error.message);
                txHash = parsedSend.result;
            } catch (e: any) {
                console.error(`[Relayer] Solana Tx Error:`, e.message);
                return res.status(502).json({ error: `Solana send tx error: ${e.message}` });
            }
            
        } else {
            return res.status(400).json({ error: `Unsupported chain: ${chain}` });
        }

        console.log(`[Relayer] Tx Broadcasted | Hash: ${txHash}`);
        return res.json({ tx_hash: txHash });

    } catch (error: any) {
        console.error('[Relayer] Server error:', error.message);
        return res.status(500).json({ error: 'Server error', details: error.message });
    }
});

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Relayer] Daemon listening on 0.0.0.0:${PORT}`);
    console.log(`[Relayer] EVM Enabled: ${!!evmWallet}`);
    console.log(`[Relayer] Solana Enabled: ${!!solanaKeypair}`);
});