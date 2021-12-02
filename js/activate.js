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
const { associatedTokenAddress, programAddress, exportSecretKey, jsonFileRead, jsonFileWrite } = require('../../js/atellix-common')

const provider = anchor.Provider.env()
//const provider = anchor.Provider.local()
anchor.setProvider(provider)
const swapContract = anchor.workspace.SwapContract
const swapContractPK = swapContract.programId

console.log("User: " + provider.wallet.publicKey.toString())

async function main() {
    const netData = await jsonFileRead('../../data/net.json')
    var writeData = {}
    writeData['swapContractProgram'] = swapContractPK.toString()

    var jsres = await exec('solana program show --output json ' + swapContractPK.toString())
    var res = JSON.parse(jsres.stdout)
    const programData = res.programdataAddress
    writeData['swapContractProgramData'] = programData

    const rootData = await programAddress([swapContractPK.toBuffer()], swapContractPK)
    const rootBytes = swapContract.account.rootData.size
    const rootRent = await provider.connection.getMinimumBalanceForRentExemption(rootBytes)
    writeData['swapContractRootData'] = rootData.pubkey
    console.log("Root Data: " + rootData.pubkey)

    const tkiBytes = swapContract.account.tokenInfo.size
    const tkiRent = await provider.connection.getMinimumBalanceForRentExemption(tkiBytes)

    const authBytes = 130 + (16384 * 6)
    const authRent = await provider.connection.getMinimumBalanceForRentExemption(authBytes)

    const swapBytes = swapContract.account.swapData.size
    const swapRent = await provider.connection.getMinimumBalanceForRentExemption(swapBytes)

    var swapData
    var swapDataPK
    var authData
    var authDataPK
    var swapAdmin1
    var swapDeposit1
    var swapWithdraw1

    if (true) {
        authData = anchor.web3.Keypair.generate()
        authDataPK = authData.publicKey
        writeData['swapContractRBAC'] = authData.publicKey.toString()

        swapAdmin1 = anchor.web3.Keypair.generate()
        writeData['swapAdmin1'] = swapAdmin1.publicKey.toString()
        writeData['swapAdmin1_secret'] = exportSecretKey(swapAdmin1)

        swapDeposit1 = anchor.web3.Keypair.generate()
        writeData['swapDeposit1'] = swapDeposit1.publicKey.toString()
        writeData['swapDeposit1_secret'] = exportSecretKey(swapDeposit1)

        swapWithdraw1 = anchor.web3.Keypair.generate()
        writeData['swapWithdraw1'] = swapWithdraw1.publicKey.toString()
        writeData['swapWithdraw1_secret'] = exportSecretKey(swapWithdraw1)

        if (true) {
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
            await provider.send(tx, [authData])
        }

        console.log('Initialize')
        await swapContract.rpc.initialize(
            new anchor.BN(rootBytes),
            new anchor.BN(rootRent),
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

        console.log('Grant: Swap Admin 1')
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
                    rbacUser: swapAdmin1.publicKey,
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
                    rbacUser: swapDeposit1.publicKey,
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
                    rbacUser: swapWithdraw1.publicKey,
                },
            }
        )

        console.log('Grant: Swap Update 1 (to swapAdmin1)')
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
                    rbacUser: swapAdmin1.publicKey,
                },
            }
        )

        await jsonFileWrite('../../data/swap.json', writeData)
    } else {
        const swapCache = await jsonFileRead('../../data/swap.json')
        authDataPK = new PublicKey(swapCache.swapContractRBAC)
        swapAdmin1 = importSecretKey(swapCache.swapAdmin1_secret)
        swapDeposit1 = importSecretKey(swapCache.swapDeposit1_secret)
        swapWithdraw1 = importSecretKey(swapCache.swapWithdraw1_secret)
    }

    if (true) {
        console.log('Fund Swap Admin')
        var tx = new anchor.web3.Transaction()
        tx.add(
            anchor.web3.SystemProgram.transfer({
                fromPubkey: provider.wallet.publicKey,
                toPubkey: swapAdmin1.publicKey,
                lamports: (tkiRent + await provider.connection.getMinimumBalanceForRentExemption(165)) * 2,
            })
        )
        await provider.send(tx)
    }
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
