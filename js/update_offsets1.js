const { Buffer } = require('buffer')
const { DateTime } = require('luxon')
const { v4: uuidv4, parse: uuidparse } = require('uuid')
const { PublicKey, Keypair, SystemProgram, SYSVAR_RENT_PUBKEY } = require('@solana/web3.js')
const { TOKEN_PROGRAM_ID } = require('@solana/spl-token')
const { promisify } = require('util')
const exec = promisify(require('child_process').exec)
const fs = require('fs').promises
const base32 = require('base32.js')
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

    var swapData
    var swapDataPK
    var authData
    var authDataPK
    var swapAdmin1

    const swapCache = await jsonFileRead('../../data/swap.json')
    authDataPK = new PublicKey(swapCache.swapContractRBAC)
    swapAdmin1 = importSecretKey('yhaxxhhvbtn0xbg3b53a3yknh5zyk9t720gsj6ypzzmsqd4bfc880dcvxmfybesczgny7qa2tjzbzdvjc2fmaad2fm7h14evyzeyecr')

    let swapName = 'wsol-usdv'
    let swapSpec = await jsonFileRead('../../data/swap-' + swapName + '.json')

    var collateralMint = new PublicKey(swapSpec.inbMint)
    var issuingMint = new PublicKey(swapSpec.outMint)
    var swapId = 0
    var buf = Buffer.alloc(2)
    buf.writeInt16LE(swapId)
    var swapData = await programAddress([collateralMint.toBuffer(), issuingMint.toBuffer(), buf], swapContractPK)
    var uuid1 = uuidparse(uuidv4())
    var swapId = 0

    swapDataPK = new PublicKey(swapData.pubkey)

    console.log('Update Swap Offset')

    let res = await swapContract.rpc.updateSwapOffset(
        swapId,
        rootData.nonce,
        swapData.nonce,
        new anchor.BN("123400"), // tokens outstanding offset delta
        new anchor.BN("364593180"), // cost basis offset delta
        new anchor.BN(uuid1), // uuid
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authDataPK,
                swapAdmin: swapAdmin1.publicKey,
                swapData: swapDataPK,
                feesToken: new PublicKey(swapSpec.feesToken),
                inbMint: collateralMint,
                outMint: issuingMint,
            },
            signers: [swapAdmin1],
        }
    )
    console.log(res)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
