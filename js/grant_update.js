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
const { SPL_ASSOCIATED_TOKEN, associatedTokenAddress, programAddress, importSecretKey, jsonFileRead } = require('../../js/atellix-common')

const provider = anchor.Provider.env()
//const provider = anchor.Provider.local()
anchor.setProvider(provider)
const swapContract = anchor.workspace.SwapContract
const swapContractPK = swapContract.programId

async function main() {
    const netData = await jsonFileRead('../../data/net.json')
    const swapCache = await jsonFileRead('../../data/swap.json')
    const swapContractPK = new PublicKey(swapCache.swapContractProgram)
    const swapContractDataPK = new PublicKey(swapCache.swapContractProgramData)
    const rootData = await programAddress([swapContractPK.toBuffer()], swapContractPK)

    const authDataPK = new PublicKey(swapCache.swapContractRBAC)
    const swapAdmin1 = importSecretKey(swapCache.swapAdmin1_secret)

    console.log('Grant: Swap Update 1 (to swapAdmin1)')
    await swapContract.rpc.grant(
        rootData.nonce,
        5,
        {
            accounts: {
                program: swapContractPK,
                programAdmin: provider.wallet.publicKey,
                programData: swapContractDataPK,
                rootData: new PublicKey(rootData.pubkey),
                authData: authDataPK,
                rbacUser: swapAdmin1.publicKey,
            },
        }
    )
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
