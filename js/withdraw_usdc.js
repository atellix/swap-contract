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
    var swapId = 0
    var inbMint = new PublicKey(netData.tokenMintUSDC)
    var outMint = new PublicKey(netData.tokenMintUSDV)

    const swapCache = await jsonFileRead('../../data/swap.json')
    authDataPK = new PublicKey(swapCache.swapContractRBAC)
    swapWithdraw1 = importSecretKey(netKeys['swap-withdraw-1-secret'])
    destOwner = new PublicKey(provider.wallet.publicKey)
    destAta = await associatedTokenAddress(destOwner, inbMint)

    var buf = Buffer.alloc(2)
    buf.writeInt16LE(swapId)
    const tkiData = await programAddress([inbMint.toBuffer(), outMint.toBuffer(), buf], swapContractPK)
    const tokData = await associatedTokenAddress(new PublicKey(rootData.pubkey), inbMint)

    var jsres = await exec('solana program show --output json ' + swapContractPK.toString())
    var pgres = JSON.parse(jsres.stdout)
    const programData = pgres.programdataAddress

    if (false) {
        console.log('Grant: SwapPermit')
        await swapContract.rpc.grant(
            rootData.nonce,
            7, // SwapPermit
            {
                accounts: {
                    program: swapContractPK,
                    programAdmin: provider.wallet.publicKey,
                    programData: new PublicKey(programData),
                    rootData: new PublicKey(rootData.pubkey),
                    authData: authDataPK,
                    rbacUser: new PublicKey(destAta.pubkey),
                },
            }
        )
    }

    console.log('Token Info: ' + tkiData.pubkey)
    console.log('Withdraw: ' + tokData.pubkey)
    let res = await swapContract.rpc.withdraw(
        swapId,
        rootData.nonce,
        tkiData.nonce,
        tokData.nonce,
        new anchor.BN('25000000'),  // 25 (* 1000000)
        true,                       // true = inbound, false = outbound
        new anchor.BN('123'),       // Event UUID
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authDataPK,
                swapAdmin: swapWithdraw1.publicKey,
                swapData: new PublicKey(tkiData.pubkey),
                swapToken: new PublicKey(tokData.pubkey),
                inbMint: inbMint,
                outMint: outMint,
                tokenDst: new PublicKey(destAta.pubkey),
                tokenProgram: TOKEN_PROGRAM_ID,
            },
            signers: [swapWithdraw1],
        }
    )
    console.log(res)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
