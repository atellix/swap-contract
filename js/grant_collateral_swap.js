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

console.log("Admin: " + provider.wallet.publicKey.toString())

async function main() {
    const manager = '9dUberxKNzpYKwUvFsE6cWT4s4Z3XaXsejLpPhf69ETk'
    const permit = [
        'ACKQycxy3M8KotkG2cyGvgV8FddFsjcxjCPQqbZw4r9N', // WSOL
        'A7eBKhb2igMG9odcveWHDCD7KADxe75ZS2SHmiFFLfe4', // USDC
    ]
    var jsres = await exec('solana program show --output json ' + swapContractPK.toString())
    var res = JSON.parse(jsres.stdout)
    const programData = res.programdataAddress
    const rootData = await programAddress([swapContractPK.toBuffer()], swapContractPK)
    const swapCache = await jsonFileRead('../../data/swap.json')
    const authDataPK = new PublicKey(swapCache.swapContractRBAC)
    
    if (true) {
        console.log('Grant: Swap Deposit To: ' + manager)
        console.log(await swapContract.rpc.grant(
            rootData.nonce,
            3, // SwapDeposit
            {
                accounts: {
                    program: swapContractPK,
                    programAdmin: provider.wallet.publicKey,
                    programData: new PublicKey(programData),
                    rootData: new PublicKey(rootData.pubkey),
                    authData: authDataPK,
                    rbacUser: new PublicKey(manager),
                },
            }
        ))
    }
    if (false) {
        console.log('Grant: Swap Withdraw To: ' + manager)
        console.log(await swapContract.rpc.grant(
            rootData.nonce,
            4, // SwapWithdraw
            {
                accounts: {
                    program: swapContractPK,
                    programAdmin: provider.wallet.publicKey,
                    programData: new PublicKey(programData),
                    rootData: new PublicKey(rootData.pubkey),
                    authData: authDataPK,
                    rbacUser: new PublicKey(manager),
                },
            }
        ))
    }
    if (false) {
        console.log('Grant: Swap Offset To: ' + manager)
        console.log(await swapContract.rpc.grant(
            rootData.nonce,
            8, // SwapOffset
            {
                accounts: {
                    program: swapContractPK,
                    programAdmin: provider.wallet.publicKey,
                    programData: new PublicKey(programData),
                    rootData: new PublicKey(rootData.pubkey),
                    authData: authDataPK,
                    rbacUser: new PublicKey(manager),
                },
            }
        ))
    }
    if (false) {
        for (var x = 0; x < permit.length; x++) {
            let dst = permit[x]
            console.log('Grant: Swap Permit To: ' + dst)
            console.log(await swapContract.rpc.grant(
                rootData.nonce,
                7, // SwapPermit
                {
                    accounts: {
                        program: swapContractPK,
                        programAdmin: provider.wallet.publicKey,
                        programData: new PublicKey(programData),
                        rootData: new PublicKey(rootData.pubkey),
                        authData: authDataPK,
                        rbacUser: new PublicKey(dst),
                    },
                }
            ))
        }
    }
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
