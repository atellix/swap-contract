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
    var res = await exec('/Users/mfrager/Build/solana/swap-contract/create_mint.sh')
    return res.stdout
}

function sleep(millis) {
  return new Promise(resolve => setTimeout(resolve, millis));
}

async function main() {
    var ndjs
    try {
        ndjs = await fs.readFile('/Users/mfrager/Build/solana/net-authority/js/net.json')
    } catch (error) {
        console.error('File Error: ', error)
    }
    const netData = JSON.parse(ndjs.toString())

    var jsres = await exec('solana program show --output json ' + swapContractPK.toString())
    var res = JSON.parse(jsres.stdout)
    const programData = res.programdataAddress

    const rootData = await programAddress([swapContractPK.toBuffer()])
    const rootBytes = swapContract.account.rootData.size
    const rootRent = await provider.connection.getMinimumBalanceForRentExemption(rootBytes)
    console.log("Root Data: " + rootData.pubkey)

    const tkiBytes = swapContract.account.tokenInfo.size
    const tkiRent = await provider.connection.getMinimumBalanceForRentExemption(tkiBytes)

    const authBytes = 130 + (16384 * 6)
    const authRent = await provider.connection.getMinimumBalanceForRentExemption(authBytes)

    const swapBytes = swapContract.account.swapData.size
    const swapRent = await provider.connection.getMinimumBalanceForRentExemption(swapBytes)

    var tokenMint1
    var tokenMint2
    var swapData
    var swapDataPK
    var authData
    var authDataPK
    var swapAdmin1
    var swapDeposit1
    var swapWithdraw1

    var spjs
    try {
        spjs = await fs.readFile('/Users/mfrager/Build/solana/swap-contract/js/swap.json')
    } catch (error) {
        console.error('File Error: ', error)
    }
    const swapCache = JSON.parse(spjs.toString())

    var djs
    try {
        djs = await fs.readFile('/Users/mfrager/Build/solana/swap-contract/js/json/data-usdc-usdv.json')
    } catch (error) {
        console.error('File Error: ', error)
    }
    const swapSpec = JSON.parse(djs.toString())

    tokenMint1 = new PublicKey(swapSpec.tokenMint1)
    tokenMint2 = new PublicKey(swapSpec.tokenMint2)
    authDataPK = new PublicKey(swapCache.swapContractRBAC)
    swapDataPK = new PublicKey(swapSpec.swapData)
    feesTK = new PublicKey(swapSpec.feesToken)
    swapAdmin1 = importSecretKey(swapCache.swapAdmin1_secret)
    swapDeposit1 = importSecretKey(swapCache.swapDeposit1_secret)
    swapWithdraw1 = importSecretKey(swapCache.swapWithdraw1_secret)

    const tkiData1 = await programAddress([tokenMint1.toBuffer()])
    const tkiData2 = await programAddress([tokenMint2.toBuffer()])
    const tokData1 = await associatedTokenAddress(new PublicKey(rootData.pubkey), tokenMint1)
    const tokData2 = await associatedTokenAddress(new PublicKey(rootData.pubkey), tokenMint2)

    console.log('Swap: ' + swapSpec.swapData)
    const userToken1 = await associatedTokenAddress(provider.wallet.publicKey, tokenMint1)
    const userToken2 = await associatedTokenAddress(provider.wallet.publicKey, tokenMint2)

    var l1 = swapContract.addEventListener('SwapEvent', (evt, slot) => {
        console.log('Event - Slot: ' + slot)
        console.log(evt.eventHash.toString())
        console.log(evt)
    })

    console.log("Root Nonce: " + rootData.nonce)

    console.log({
        rootData: new PublicKey(rootData.pubkey).toString(),
        authData: authDataPK.toString(),
        swapUser: provider.wallet.publicKey.toString(),
        swapData: swapDataPK.toString(),
        inbInfo: new PublicKey(tkiData1.pubkey).toString(),
        inbTokenSrc: new PublicKey(userToken1.pubkey).toString(),
        inbTokenDst: new PublicKey(tokData1.pubkey).toString(),
        inbMint: tokenMint1.toString(),
        outInfo: new PublicKey(tkiData2.pubkey).toString(),
        outTokenSrc: new PublicKey(tokData2.pubkey).toString(),
        outTokenDst: new PublicKey(userToken2.pubkey).toString(),
        outMint: tokenMint2.toString(),
        feesToken: feesTK.toString(),
    })
    await swapContract.rpc.swap(
        rootData.nonce,
        tokData1.nonce,
        tokData2.nonce,
        false, // True - Buy, False - Sell
        new anchor.BN(25 * 10000),
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
            /*remainingAccounts: [
                { pubkey: oraclePK, isWritable: false, isSigner: false },
            ],*/
        }
    )

    await sleep(2000)
    await swapContract.removeEventListener(l1)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
