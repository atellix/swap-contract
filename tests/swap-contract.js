const { Buffer } = require('buffer')
const { DateTime } = require("luxon")
const { v4: uuidv4, parse: uuidparse } = require('uuid')
const { PublicKey, Keypair, SystemProgram, SYSVAR_RENT_PUBKEY } = require('@solana/web3.js')
const { TOKEN_PROGRAM_ID } = require('@solana/spl-token')
const { promisify } = require('util')
const exec = promisify(require('child_process').exec)
const fs = require('fs').promises
const base32 = require("base32.js")
const anchor = require('@project-serum/anchor')

const provider = anchor.Provider.env()
//const provider = anchor.Provider.local()
anchor.setProvider(provider)

const swapContract = anchor.workspace.SwapContract
const swapContractPK = swapContract.programId
const oraclePK = new PublicKey('DpoK8Zz69APV9ntjuY9C4LZCxANYMV56M2cbXEdkjxME')

const SPL_ASSOCIATED_TOKEN = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL')
async function associatedTokenAddress(walletAddress, tokenMintAddress) {
    const addr = await PublicKey.findProgramAddress(
        [walletAddress.toBuffer(), TOKEN_PROGRAM_ID.toBuffer(), tokenMintAddress.toBuffer()],
        SPL_ASSOCIATED_TOKEN
    )
    const res = { 'pubkey': await addr[0].toString(), 'nonce': addr[1] }
    return res
}

async function programAddress(inputs, program) {
    const addr = await PublicKey.findProgramAddress(inputs, program)
    const res = { 'pubkey': await addr[0].toString(), 'nonce': addr[1] }
    return res
}

describe('swap-contract', () => {
    it('Swap wSOL for USDV', async () => {
        const rootData = await programAddress([swapContractPK.toBuffer()], swapContractPK)
        var tokenMint1
        var tokenMint2
        var swapData
        var swapDataPK
        var authData
        var authDataPK
        var spjs
        try {
            spjs = await fs.readFile('../data/swap.json')
        } catch (error) {
            console.error('File Error: ', error)
        }
        const swapCache = JSON.parse(spjs.toString())
        var djs
        try {
            djs = await fs.readFile('../data/swap-usdv-wsol.json')
        } catch (error) {
            console.error('File Error: ', error)
        }
        const swapSpec = JSON.parse(djs.toString())
        tokenMint1 = new PublicKey(swapSpec.tokenMint1)
        tokenMint2 = new PublicKey(swapSpec.tokenMint2)
        authDataPK = new PublicKey(swapCache.swapContractRBAC)
        swapDataPK = new PublicKey(swapSpec.swapData)
        feesTK = new PublicKey(swapSpec.feesToken)
        const tkiData1 = await programAddress([tokenMint1.toBuffer()], swapContractPK)
        const tkiData2 = await programAddress([tokenMint2.toBuffer()], swapContractPK)
        const tokData1 = await associatedTokenAddress(new PublicKey(rootData.pubkey), tokenMint1)
        const tokData2 = await associatedTokenAddress(new PublicKey(rootData.pubkey), tokenMint2)
        const userToken1 = await associatedTokenAddress(provider.wallet.publicKey, tokenMint1)
        const userToken2 = await associatedTokenAddress(provider.wallet.publicKey, tokenMint2)
        return swapContract.rpc.swap(
            rootData.nonce,
            tokData1.nonce,
            tokData2.nonce,
            true, // True - Buy, False - Sell
            //new anchor.BN(10 ** 9),
            new anchor.BN(100 * (10**4)),
            {
                accounts: {
                    rootData: new PublicKey(rootData.pubkey),
                    authData: authDataPK,
                    swapUser: provider.wallet.publicKey,
                    swapData: swapDataPK,
                    inbInfo: new PublicKey(tkiData1.pubkey),
                    inbTokenSrc: new PublicKey(userToken1.pubkey),
                    inbTokenDst: new PublicKey(tokData1.pubkey),
                    outInfo: new PublicKey(tkiData2.pubkey),
                    outTokenSrc: new PublicKey(tokData2.pubkey),
                    outTokenDst: new PublicKey(userToken2.pubkey),
                    tokenProgram: TOKEN_PROGRAM_ID,
                    feesToken: feesTK,
                },
                remainingAccounts: [
                    { pubkey: oraclePK, isWritable: false, isSigner: false },
                ],
            }
        )
    })
})
