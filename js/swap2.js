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
const oraclePK = new PublicKey('GvDMxPzN1sCj7L26YDK2HnMRXEQmQ2aemov8YBtPS7vR')

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

function sleep(millis) {
  return new Promise(resolve => setTimeout(resolve, millis));
}

async function main() {
    var ndjs
    try {
        ndjs = await fs.readFile('../../data/net.json')
    } catch (error) {
        console.error('File Error: ', error)
    }
    const netData = JSON.parse(ndjs.toString())

    var jsres = await exec('solana program show --output json ' + swapContractPK.toString())
    var res = JSON.parse(jsres.stdout)
    const programData = res.programdataAddress

    const rootData = await programAddress([swapContractPK.toBuffer()])

    var tokenMint1
    var tokenMint2
    var swapData
    var swapDataPK
    var authData
    var authDataPK

    var spjs
    try {
        spjs = await fs.readFile('../../data/swap.json')
    } catch (error) {
        console.error('File Error: ', error)
    }
    const swapCache = JSON.parse(spjs.toString())

    var djs
    try {
        djs = await fs.readFile('../../data/swap-wsol-usdv.json')
    } catch (error) {
        console.error('File Error: ', error)
    }
    const swapSpec = JSON.parse(djs.toString())

    tokenMint1 = new PublicKey(swapSpec.inbMint) // WSOL
    tokenMint2 = new PublicKey(swapSpec.outMint) // USDV
    authDataPK = new PublicKey(swapCache.swapContractRBAC)
    var swapId = 0
    var buf = Buffer.alloc(2)
    buf.writeInt16LE(swapId)
    swapData = await programAddress([tokenMint1.toBuffer(), tokenMint2.toBuffer(), buf], swapContractPK)
    swapDataPK = new PublicKey(swapData.pubkey)
    feesTK = new PublicKey(swapSpec.feesToken)

    const tokData1 = await associatedTokenAddress(swapDataPK, tokenMint1)
    const tokData2 = await associatedTokenAddress(swapDataPK, tokenMint2)
    console.log('Token Vaults')
    console.log(tokData1)
    console.log(tokData2)

    console.log('Swap: ' + swapSpec.swapData)
    const userToken1 = await associatedTokenAddress(provider.wallet.publicKey, tokenMint1)
    const userToken2 = await associatedTokenAddress(provider.wallet.publicKey, tokenMint2)

    var l1 = swapContract.addEventListener('SwapEvent', (evt, slot) => {
        console.log('Event - Slot: ' + slot)
        console.log(evt.eventHash.toString())
        console.log(evt)
    })

    console.log({
        swapUser: provider.wallet.publicKey.toString(),
        swapData: swapDataPK.toString(),
        inbTokenSrc: new PublicKey(userToken1.pubkey).toString(),
        inbTokenDst: new PublicKey(tokData1.pubkey).toString(),
        outTokenSrc: new PublicKey(tokData2.pubkey).toString(),
        outTokenDst: new PublicKey(userToken2.pubkey).toString(),
        feesToken: feesTK.toString(),
    })
    let apires = await swapContract.rpc.swap(
        swapData.nonce,         // swap data nonce
        tokData1.nonce,         // inbound vault nonce
        tokData2.nonce,         // outbound vault nonce
        0,                      // root nonce
        true,                   // swap direction
        false,                  // merchant swap
        true,                   // is buy order
        //new anchor.BN(10 ** 9),
        new anchor.BN(100 * 10000),
        {
            accounts: {
                swapUser: provider.wallet.publicKey,
                swapData: swapDataPK,
                inbTokenSrc: new PublicKey(userToken1.pubkey),
                inbTokenDst: new PublicKey(tokData1.pubkey),
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
    console.log(apires)
    await sleep(2000)
    await swapContract.removeEventListener(l1)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
