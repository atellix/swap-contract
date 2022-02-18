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
    const netKeys = await jsonFileRead('../../data/export/network_keys.json')
    const netData = await jsonFileRead('../../data/net.json')
    const rootData = await programAddress([swapContractPK.toBuffer()], swapContractPK)
    //const tkiBytes = swapContract.account.tokenInfo.size
    //const tkiRent = await provider.connection.getMinimumBalanceForRentExemption(tkiBytes)

    var authData
    var authDataPK
    var swapDepost1
    var inbMint = new PublicKey(netData.tokenMintUSDC)
    var outMint = new PublicKey(netData.tokenMintUSDV)

    const swapCache = await jsonFileRead('../../data/swap.json')
    authDataPK = new PublicKey(swapCache.swapContractRBAC)
    swapDeposit1 = importSecretKey(netKeys['swap-deposit-1-secret'])
    treasury1 = importSecretKey(netKeys['treasury-1-secret'])

    const tkiData = await programAddress([inbMint.toBuffer(), outMint.toBuffer()], swapContractPK)
    const tokData = await associatedTokenAddress(new PublicKey(tkiData.pubkey), outMint)
    const srcToken = await associatedTokenAddress(treasury1.publicKey, outMint)

    console.log('Token Info: ' + tkiData.pubkey)
    console.log('Deposit: ' + tokData.pubkey)
    let res = await swapContract.rpc.deposit(
        rootData.nonce,
        tkiData.nonce,
        tokData.nonce,
        new anchor.BN('100000000000'),  // Ten million (* 10000)
        false,                          // true = inbound, false = outbound
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authDataPK,
                swapAdmin: swapDeposit1.publicKey,
                swapData: new PublicKey(tkiData.pubkey),
                swapToken: new PublicKey(tokData.pubkey),
                inbMint: inbMint,
                outMint: outMint,
                tokenSrc: new PublicKey(srcToken.pubkey),
                tokenAdmin: treasury1.publicKey,
                tokenProgram: TOKEN_PROGRAM_ID,
            },
            signers: [swapDeposit1, treasury1],
        }
    )
    console.log(res)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
