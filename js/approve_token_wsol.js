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

const SPL_ASSOCIATED_TOKEN = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL')
async function associatedTokenAddress(walletAddress, tokenMintAddress) {
    const addr = await PublicKey.findProgramAddress(
        [walletAddress.toBuffer(), TOKEN_PROGRAM_ID.toBuffer(), tokenMintAddress.toBuffer()],
        SPL_ASSOCIATED_TOKEN
    )
    const res = { 'pubkey': await addr[0].toString(), 'nonce': addr[1] }
    return res
}

async function programAddress(inputs, program = swapContractPK) {
    const addr = await PublicKey.findProgramAddress(inputs, program)
    const res = { 'pubkey': await addr[0].toString(), 'nonce': addr[1] }
    return res
}

function exportSecretKey(keyPair) {
    var enc = new base32.Encoder({ type: "crockford", lc: true })
    return enc.write(keyPair.secretKey).finalize()
}

function importSecretKey(keyStr) {
    var dec = new base32.Decoder({ type: "crockford" })
    var spec = dec.write(keyStr).finalize()
    return Keypair.fromSecretKey(new Uint8Array(spec))
}

async function createTokenMint() {
    var res = await exec('./create_mint.sh')
    return res.stdout
}

async function main() {
    var ndjs
    try {
        ndjs = await fs.readFile('/Users/mfrager/Build/solana/net-authority/js/net.json')
    } catch (error) {
        console.error('File Error: ', error)
    }
    const netData = JSON.parse(ndjs.toString())

    const rootData = await programAddress([swapContractPK.toBuffer()])

    const tkiBytes = swapContract.account.tokenInfo.size
    const tkiRent = await provider.connection.getMinimumBalanceForRentExemption(tkiBytes)

    var tokenMint = new PublicKey('So11111111111111111111111111111111111111112')
    var tokenDecimals = 9
    var authData
    var authDataPK
    var swapAdmin1
    var swapDeposit1
    var swapWithdraw1

    var ndjs
    try {
        spjs = await fs.readFile('/Users/mfrager/Build/solana/swap-contract/js/swap.json')
    } catch (error) {
        console.error('File Error: ', error)
    }
    const swapCache = JSON.parse(spjs.toString())
    authDataPK = new PublicKey(swapCache.swapContractRBAC)
    swapAdmin1 = importSecretKey(swapCache.swapAdmin1_secret)
    swapDeposit1 = importSecretKey(swapCache.swapDeposit1_secret)
    swapWithdraw1 = importSecretKey(swapCache.swapWithdraw1_secret)

    const tkiData = await programAddress([tokenMint.toBuffer()])
    const tokData = await associatedTokenAddress(new PublicKey(rootData.pubkey), tokenMint)

    if (true) {
        console.log('Fund Swap Admin')
        var tx = new anchor.web3.Transaction()
        tx.add(
            anchor.web3.SystemProgram.transfer({
                fromPubkey: provider.wallet.publicKey,
                toPubkey: swapAdmin1.publicKey,
                lamports: tkiRent + await provider.connection.getMinimumBalanceForRentExemption(165),
            })
        )
        await provider.send(tx)
    }

    console.log('Approve Token: ' + tokenMint.toString())
    await swapContract.rpc.approveToken(
        rootData.nonce,
        tkiData.nonce,
        tokData.nonce,
        new anchor.BN(tkiRent),
        new anchor.BN(tkiBytes),
        tokenDecimals,
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authDataPK,
                swapAdmin: swapAdmin1.publicKey,
                swapToken: new PublicKey(tokData.pubkey),
                tokenMint: tokenMint,
                tokenInfo: new PublicKey(tkiData.pubkey),
                tokenProgram: TOKEN_PROGRAM_ID,
                ascProgram: SPL_ASSOCIATED_TOKEN,
                systemProgram: SystemProgram.programId,
                systemRent: SYSVAR_RENT_PUBKEY,
            },
            signers: [swapAdmin1],
        }
    )
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})