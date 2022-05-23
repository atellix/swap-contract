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

    const swapCache = await jsonFileRead('../../data/swap.json')
    const authDataPK = new PublicKey(swapCache.swapContractRBAC)

    var jsres = await exec('solana program show --output json ' + swapContractPK.toString())
    var pgres = JSON.parse(jsres.stdout)
    const programData = pgres.programdataAddress

    console.log('Grant: NetworkAuth')
    var res = await swapContract.rpc.grant(
        rootData.nonce,
        1, // NetworkAuth
        {
            accounts: {
                program: swapContractPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                rootData: new PublicKey(rootData.pubkey),
                authData: authDataPK,
                rbacUser: new PublicKey('AUTHXb39qs2VyztqH9zqh3LLLVGMzMvvYN3UXQHeJeEH'),
            },
        }
    )
    console.log(res)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
