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

function exportSecretKey(keyPair) {
    var enc = new base32.Encoder({ type: "crockford", lc: true })
    return enc.write(keyPair.secretKey).finalize()
}

function importSecretKey(keyStr) {
    var dec = new base32.Decoder({ type: "crockford" })
    var spec = dec.write(keyStr).finalize()
    return Keypair.fromSecretKey(new Uint8Array(spec))
}

async function main() {
    var ndjs
    try {
        ndjs = await fs.readFile('/Users/mfrager/Build/solana/net-authority/js/net.json')
    } catch (error) {
        console.error('File Error: ', error)
    }
    const netData = JSON.parse(ndjs.toString())
    const tokenMint = new PublicKey(netData.tokenMintUSDV)

    var swapData = {}
    swapData['tokenMintUSDV'] = tokenMint.toString()
    swapData['swapContractProgram'] = swapContractPK.toString()

    var jsres = await exec('solana program show --output json ' + swapContractPK.toString())
    var res = JSON.parse(jsres.stdout)
    const programData = res.programdataAddress
    swapData['swapContractProgramData'] = programData

    const rootData = await programAddress([swapContractPK.toBuffer()])
    const rootBytes = swapContract.account.rootData.size
    const rootRent = await provider.connection.getMinimumBalanceForRentExemption(rootBytes)
    console.log('Root Data')
    console.log((new PublicKey(rootData.pubkey)).toString(), rootBytes, rootRent)

    const authData = anchor.web3.Keypair.generate()
    const authBytes = 130 + (16384 * 6)
    const authRent = await provider.connection.getMinimumBalanceForRentExemption(authBytes)
    console.log('Auth Data')
    console.log(authData.publicKey.toString(), authBytes, authRent)
    swapData['swapContractRBAC'] = authData.publicKey.toString()

    var swapAdmin1
    var swapDeposit1
    var swapWithdraw1

    if (true) {
        swapAdmin1 = anchor.web3.Keypair.generate()
        swapData['swapAdmin1'] = swapAdmin1.publicKey.toString()
        swapData['swapAdmin1_secret'] = exportSecretKey(swapAdmin1)

        swapDeposit1 = anchor.web3.Keypair.generate()
        swapData['swapDeposit1'] = swapDeposit1.publicKey.toString()
        swapData['swapDeposit1_secret'] = exportSecretKey(swapDeposit1)

        swapWithdraw1 = anchor.web3.Keypair.generate()
        swapData['swapWithdraw1'] = swapWithdraw1.publicKey.toString()
        swapData['swapWithdraw1_secret'] = exportSecretKey(swapWithdraw1)

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
                },
                remainingAccounts: [
                    { pubkey: provider.wallet.publicKey, isWritable: true, isSigner: true },
                    { pubkey: new PublicKey(rootData.pubkey), isWritable: true, isSigner: false },
                    { pubkey: SystemProgram.programId, isWritable: false, isSigner: false }
                ]
            }
        )

        console.log('Grant: Swap Admin 1')
        await swapContract.rpc.grant(
            rootData.nonce,
            1,
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
            2,
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
            3,
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

        try {
            await fs.writeFile('swap.json', JSON.stringify(netData, null, 4))
        } catch (error) {
            console.log("File Error: " + error)
        }
    } else {
        var ndjs
        try {
            spjs = await fs.readFile('/Users/mfrager/Build/solana/swap-contract/js/swap.json')
        } catch (error) {
            console.error('File Error: ', error)
        }
        const swapCache = JSON.parse(spjs.toString())
        swapAdmin1 = importSecretKey(swapCache.swapAdmin1)
        swapDeposit1 = importSecretKey(swapCache.swapDeposit1)
        swapWithdraw1 = importSecretKey(swapCache.swapWithdraw1)
    }

    console.log('Deposit')
    await swapContract.rpc.deposit(
        rootData.nonce,
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                swapAdmin: swapDeposit1.publicKey,
            },
            signers: [swapDeposit1],
        }
    )
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
