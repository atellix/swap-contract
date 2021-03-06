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
const { associatedTokenAddress, programAddress, importSecretKey, exportSecretKey, jsonFileRead, jsonFileWrite } = require('../../js/atellix-common')

const provider = anchor.Provider.env()
//const provider = anchor.Provider.local()
anchor.setProvider(provider)
const swapContract = anchor.workspace.SwapContract
const swapContractPK = swapContract.programId

async function main() {
    const netData = await jsonFileRead('../../data/net.json')
    const netKeys = await jsonFileRead('../../data/export/network_keys.json')
    const rootData = await programAddress([swapContractPK.toBuffer()], swapContractPK)

    var authData
    var authDataPK
    var usdvMint1
    var swapDepost1
    var swapId = 0

    const swapCache = await jsonFileRead('../../data/swap.json')
    authDataPK = new PublicKey(swapCache.swapContractRBAC)
    console.log(netKeys['usdv-mint-1-secret'])
    usdvMint1 = importSecretKey(netKeys['usdv-mint-1-secret'])
    swapDeposit1 = importSecretKey(netKeys['swap-deposit-1-secret'])

    var inbMint = new PublicKey(netData.tokenMintUSDC)
    var outMint = new PublicKey(netData.tokenMintUSDV)

    var buf = Buffer.alloc(2)
    buf.writeInt16LE(swapId)
    const tkiData = await programAddress([inbMint.toBuffer(), outMint.toBuffer(), buf], swapContractPK)
    const tokData = await associatedTokenAddress(new PublicKey(tkiData.pubkey), outMint)
    console.log({
        rootData: new PublicKey(rootData.pubkey).toString(),
        authData: authDataPK.toString(),
        swapAdmin: swapDeposit1.publicKey.toString(),
        swapData: new PublicKey(tkiData.pubkey).toString(),
        swapToken: new PublicKey(tokData.pubkey).toString(),
        tokenAdmin: usdvMint1.publicKey.toString(),
        inbMint: inbMint.toString(),
        outMint: outMint.toString(),
        tokenProgram: TOKEN_PROGRAM_ID.toString(),
    })

    console.log('Deposit: ' + tokData.pubkey)
    let res = await swapContract.rpc.mintDeposit(
        swapId,
        rootData.nonce,
        tkiData.nonce,
        tokData.nonce,
        new anchor.BN('1000000000000000'),  // One billion
        false,                              // true = inbound token, false = outbound token
        new anchor.BN('123'),               // Event uuid
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authDataPK,
                swapAdmin: swapDeposit1.publicKey,
                swapData: new PublicKey(tkiData.pubkey),
                swapToken: new PublicKey(tokData.pubkey),
                tokenAdmin: usdvMint1.publicKey,
                inbMint: inbMint,
                outMint: outMint,
                tokenProgram: TOKEN_PROGRAM_ID,
            },
            signers: [swapDeposit1, usdvMint1],
        }
    )
    console.log(res)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
