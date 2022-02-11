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

console.log("User: " + provider.wallet.publicKey.toString())

async function main() {
    const netKeys = await jsonFileRead('../../data/export/network_keys.json')
    const netData = await jsonFileRead('../../data/net.json')
    var writeData = {}
    writeData['swapContractProgram'] = swapContractPK.toString()

    var jsres = await exec('solana program show --output json ' + swapContractPK.toString())
    var res = JSON.parse(jsres.stdout)
    const programData = res.programdataAddress
    writeData['swapContractProgramData'] = programData

    const rootData = await programAddress([swapContractPK.toBuffer()], swapContractPK)
    //const rootBytes = swapContract.account.rootData.size
    //const rootRent = await provider.connection.getMinimumBalanceForRentExemption(rootBytes)
    writeData['swapContractRootData'] = rootData.pubkey
    console.log("Root Data: " + rootData.pubkey)

    const authBytes = 130 + (16384 * 2)
    const authRent = await provider.connection.getMinimumBalanceForRentExemption(authBytes)

    var authData
    var authDataPK

    authData = anchor.web3.Keypair.generate()
    authDataPK = authData.publicKey
    writeData['swapContractRBAC'] = authData.publicKey.toString()

    writeData['swapRoot1'] = netKeys['swap-network-admin-1-public']
    writeData['swapAdmin1'] = netKeys['swap-data-admin-1-public']
    writeData['swapDeposit1'] = netKeys['swap-deposit-1-public']
    writeData['swapWithdraw1'] = netKeys['swap-withdraw-1-public']
    writeData['swapUpdate1'] = netKeys['swap-update-1-public']
    writeData['swapAbort1'] = netKeys['swap-abort-1-public']
    writeData['swapFees1'] = netKeys['swap-fees-1-public']

    swapAbort2 = importSecretKey(netKeys['swap-abort-2-secret'])
    writeData['swapAbort2'] = swapAbort2.publicKey.toString()
    writeData['swapAbort2_secret'] = netKeys['swap-abort-2-secret']

    console.log('Create RBAC Account')
    const tx = new anchor.web3.Transaction()
    tx.add(
        anchor.web3.SystemProgram.createAccount({
            fromPubkey: provider.wallet.publicKey,
            newAccountPubkey: authData.publicKey,
            space: authBytes,
            lamports: authRent,
            programId: swapContractPK,
        })
    )
    console.log(await provider.send(tx, [authData]))

    console.log('Initialize')
    await swapContract.rpc.initialize(
        {
            accounts: {
                program: swapContractPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                systemProgram: SystemProgram.programId,
            }
        }
     )

    console.log('Grant: Swap Network Admin 1')
    await swapContract.rpc.grant(
        rootData.nonce,
        0, // NetworkAdmin
        {
            accounts: {
                program: swapContractPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                rbacUser: new PublicKey(writeData['swapRoot1']),
            },
        }
    )

    console.log('Grant: Swap Data Admin 1')
    await swapContract.rpc.grant(
        rootData.nonce,
        2, // SwapAdmin
        {
            accounts: {
                program: swapContractPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                rbacUser: new PublicKey(writeData['swapAdmin1']),
            },
        }
    )

    console.log('Grant: Swap Deposit 1')
    await swapContract.rpc.grant(
        rootData.nonce,
        3, // SwapDeposit
        {
            accounts: {
                program: swapContractPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                rbacUser: new PublicKey(writeData['swapDeposit1']),
            },
        }
    )

    console.log('Grant: Swap Withdraw 1')
    await swapContract.rpc.grant(
        rootData.nonce,
        4, // SwapWithdraw
        {
            accounts: {
                program: swapContractPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                rbacUser: new PublicKey(writeData['swapWithdraw1']),
            },
        }
    )

    console.log('Grant: Swap Update 1')
    await swapContract.rpc.grant(
        rootData.nonce,
        5, // SwapUpdate
        {
            accounts: {
                program: swapContractPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                rbacUser: new PublicKey(writeData['swapUpdate1']),
            },
        }
    )

    console.log('Grant: Swap Abort 1')
    await swapContract.rpc.grant(
        rootData.nonce,
        6, // SwapAbort
        {
            accounts: {
                program: swapContractPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                rbacUser: new PublicKey(writeData['swapAbort1']),
            },
        }
    )

    console.log('Grant: Swap Abort 2')
    await swapContract.rpc.grant(
        rootData.nonce,
        6, // SwapAbort
        {
            accounts: {
                program: swapContractPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                rbacUser: new PublicKey(writeData['swapAbort2']),
            },
        }
    )

    await jsonFileWrite('../../data/swap.json', writeData)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
