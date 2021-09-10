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

async function createTokenMint() {
    var res = await exec('/Users/mfrager/Build/solana/swap-contract/create_mint.sh')
    return res.stdout
}

async function main() {
    var ndjs
    try {
        ndjs = await fs.readFile('/Users/mfrager/Build/solana/net-authority/js/net.json')
    } catch (error) {
        console.error('File Error: ', error)
    }
    const netData = JSON.parse(ndjs.toString())
    var writeData = {}
    writeData['swapContractProgram'] = swapContractPK.toString()

    var jsres = await exec('solana program show --output json ' + swapContractPK.toString())
    var res = JSON.parse(jsres.stdout)
    const programData = res.programdataAddress
    writeData['swapContractProgramData'] = programData

    const rootData = await programAddress([swapContractPK.toBuffer()])
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

    var tokenMint1
    var tokenMint2
    var swapData
    var swapDataPK
    var authData
    var authDataPK
    var swapAdmin1
    var swapDeposit1
    var swapWithdraw1

    if (true) {
        var mint1 = await createTokenMint()
        var mint2 = await createTokenMint()
        console.log("Mints: " + mint1 + " " + mint2)
        tokenMint1 = new PublicKey(mint1)
        tokenMint2 = new PublicKey(mint2)
        writeData['tokenMint1'] = tokenMint1.toString()
        writeData['tokenMint2'] = tokenMint2.toString()

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

        swapData = anchor.web3.Keypair.generate()
        swapDataPK = swapData.publicKey
        writeData['swapData'] = swapData.publicKey.toString()

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
            await fs.writeFile('swap.json', JSON.stringify(writeData, null, 4))
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
        tokenMint1 = new PublicKey(swapCache.tokenMint1)
        tokenMint2 = new PublicKey(swapCache.tokenMint2)
        authDataPK = new PublicKey(swapCache.swapContractRBAC)
        swapAdmin1 = importSecretKey(swapCache.swapAdmin1_secret)
        swapDeposit1 = importSecretKey(swapCache.swapDeposit1_secret)
        swapWithdraw1 = importSecretKey(swapCache.swapWithdraw1_secret)
    }

    if (true) {
        console.log('Fund Swap Deposit Admin')
        var tx = new anchor.web3.Transaction()
        tx.add(
            anchor.web3.SystemProgram.transfer({
                fromPubkey: provider.wallet.publicKey,
                toPubkey: swapDeposit1.publicKey,
                lamports: (tkiRent + await provider.connection.getMinimumBalanceForRentExemption(165)) * 2,
            })
        )
        await provider.send(tx)
    }

    const tkiData1 = await programAddress([tokenMint1.toBuffer()])
    const tkiData2 = await programAddress([tokenMint2.toBuffer()])
    const tokData1 = await associatedTokenAddress(new PublicKey(rootData.pubkey), tokenMint1)
    const tokData2 = await associatedTokenAddress(new PublicKey(rootData.pubkey), tokenMint2)

    console.log('Approve Token 1: ' + tokenMint1.toString())
    await swapContract.rpc.approveToken(
        rootData.nonce,
        tkiData1.nonce,
        tokData1.nonce,
        new anchor.BN(tkiRent),
        new anchor.BN(tkiBytes),
        4,
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authDataPK,
                swapAdmin: swapDeposit1.publicKey,
                swapToken: new PublicKey(tokData1.pubkey),
                tokenMint: tokenMint1,
                tokenInfo: new PublicKey(tkiData1.pubkey),
                tokenProgram: TOKEN_PROGRAM_ID,
                ascProgram: SPL_ASSOCIATED_TOKEN,
                systemProgram: SystemProgram.programId,
                systemRent: SYSVAR_RENT_PUBKEY,
            },
            signers: [swapDeposit1],
        }
    )

    console.log('Approve Token 2: ' + tokenMint2.toString())
    await swapContract.rpc.approveToken(
        rootData.nonce,
        tkiData2.nonce,
        tokData2.nonce,
        new anchor.BN(tkiRent),
        new anchor.BN(tkiBytes),
        4,
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authDataPK,
                swapAdmin: swapDeposit1.publicKey,
                swapToken: new PublicKey(tokData2.pubkey),
                tokenMint: tokenMint2,
                tokenInfo: new PublicKey(tkiData2.pubkey),
                tokenProgram: TOKEN_PROGRAM_ID,
                ascProgram: SPL_ASSOCIATED_TOKEN,
                systemProgram: SystemProgram.programId,
                systemRent: SYSVAR_RENT_PUBKEY,
            },
            signers: [swapDeposit1],
        }
    )

    console.log('Deposit 1: ' + tokData1.pubkey)
    await swapContract.rpc.deposit(
        rootData.nonce,
        tkiData1.nonce,
        tokData1.nonce,
        true,
        new anchor.BN(1000000000000000),
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authDataPK,
                swapAdmin: swapDeposit1.publicKey,
                swapToken: new PublicKey(tokData1.pubkey),
                tokenAdmin: provider.wallet.publicKey,
                tokenMint: tokenMint1,
                tokenInfo: new PublicKey(tkiData1.pubkey),
                tokenProgram: TOKEN_PROGRAM_ID,
            },
            signers: [swapDeposit1],
        }
    )

    console.log('Deposit 2: ' + tokData2.pubkey)
    await swapContract.rpc.deposit(
        rootData.nonce,
        tkiData2.nonce,
        tokData2.nonce,
        true,
        new anchor.BN(1000000000000000),
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authDataPK,
                swapAdmin: swapDeposit1.publicKey,
                swapToken: new PublicKey(tokData2.pubkey),
                tokenAdmin: provider.wallet.publicKey,
                tokenMint: tokenMint2,
                tokenInfo: new PublicKey(tkiData2.pubkey),
                tokenProgram: TOKEN_PROGRAM_ID,
            },
            signers: [swapDeposit1],
        }
    )

    console.log('Create Swap')
    feesAcct = anchor.web3.Keypair.generate()
    if (true) {
        const tx = new anchor.web3.Transaction()
        tx.add(
            anchor.web3.SystemProgram.createAccount({
                fromPubkey: provider.wallet.publicKey,
                newAccountPubkey: swapDataPK,
                space: swapBytes,
                lamports: swapRent,
                programId: swapContractPK,
            })
        )
        await provider.send(tx, [swapData])
    }
    /*console.log({
        rootData: new PublicKey(rootData.pubkey).toString(),
        authData: authDataPK.toString(),
        swapAdmin: swapAdmin1.publicKey.toString(),
        swapData: swapDataPK.toString(),
        inbInfo: new PublicKey(tkiData1.pubkey).toString(),
        outInfo: new PublicKey(tkiData2.pubkey).toString(),
        feesAccount: feesAcct.publicKey.toString(),
    })*/
    await swapContract.rpc.createSwap(
        rootData.nonce,
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authDataPK,
                swapAdmin: swapAdmin1.publicKey,
                swapData: swapDataPK,
                inbInfo: new PublicKey(tkiData1.pubkey),
                outInfo: new PublicKey(tkiData2.pubkey),
                feesAccount: feesAcct.publicKey,
            },
            signers: [swapAdmin1],
        }
    )

    console.log('Swap')
    const userToken1 = await associatedTokenAddress(provider.wallet.publicKey, tokenMint1)
    const userToken2 = await associatedTokenAddress(provider.wallet.publicKey, tokenMint2)
    console.log({
        rootData: new PublicKey(rootData.pubkey).toString(),
        authData: authDataPK.toString(),
        swapUser: provider.wallet.publicKey.toString(),
        swapData: swapDataPK.toString(),
        inbInfo: new PublicKey(tkiData1.pubkey).toString(),
        inbTokenSrc: new PublicKey(userToken1.pubkey).toString(),
        inbTokenDst: new PublicKey(tokData1.pubkey).toString(),
        inbMint: tokenMint1.toString(),
        outInfo: new PublicKey(tkiData2.pubkey).toString(),
        outTokenSrc: new PublicKey(tokData2.pubkey).toString(),
        outTokenDst: new PublicKey(userToken2.pubkey).toString(),
        outMint: tokenMint2.toString(),
    })
    await swapContract.rpc.swap(
        rootData.nonce,
        tokData1.nonce,
        tokData2.nonce,
        new anchor.BN(999 * 10000),
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authDataPK,
                swapUser: provider.wallet.publicKey,
                swapData: swapDataPK,
                inbInfo: new PublicKey(tkiData1.pubkey),
                inbTokenSrc: new PublicKey(userToken1.pubkey),
                inbTokenDst: new PublicKey(tokData1.pubkey),
                inbMint: tokenMint1,
                outInfo: new PublicKey(tkiData2.pubkey),
                outTokenSrc: new PublicKey(tokData2.pubkey),
                outTokenDst: new PublicKey(userToken2.pubkey),
                outMint: tokenMint2,
                tokenProgram: TOKEN_PROGRAM_ID,
                //feesAccount: feesAcct.publicKey,
            },
        }
    )
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
