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
const oraclePK = new PublicKey('DpoK8Zz69APV9ntjuY9C4LZCxANYMV56M2cbXEdkjxME')

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
    var res = await exec('./create_mint.sh')
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

    const rootData = await programAddress([swapContractPK.toBuffer()])

    const feesOwner = anchor.web3.Keypair.generate()

    const swapBytes = swapContract.account.swapData.size
    const swapRent = await provider.connection.getMinimumBalanceForRentExemption(swapBytes)

    var swapData
    var swapDataPK

    var tokenMint = new PublicKey('HZE3aet4kKEnBdKsTAWcc9Axv6F7p9Yu4rcNJcuxddZr')
    var authData
    var authDataPK
    var swapAdmin1
    var swapDeposit1
    var swapWithdraw1

    var ndjs
    try {
        spjs = await fs.readFile('/Users/mfrager/Build/solana/swap-contract/js/swap.json')
    } catch (error) {
        console.error('File Error: ', error)
    }
    const swapCache = JSON.parse(spjs.toString())
    authDataPK = new PublicKey(swapCache.swapContractRBAC)
    swapAdmin1 = importSecretKey(swapCache.swapAdmin1_secret)
    swapDeposit1 = importSecretKey(swapCache.swapDeposit1_secret)
    swapWithdraw1 = importSecretKey(swapCache.swapWithdraw1_secret)

    var writeData = {}

    var mint1 = 'So11111111111111111111111111111111111111112' // WSOL
    var mint2 = 'HZE3aet4kKEnBdKsTAWcc9Axv6F7p9Yu4rcNJcuxddZr' // USDV
    console.log("Mints: " + mint1 + " " + mint2)
    tokenMint1 = new PublicKey(mint1)
    tokenMint2 = new PublicKey(mint2)
    writeData['tokenMint1'] = tokenMint1.toString()
    writeData['tokenMint2'] = tokenMint2.toString()
    
    const tkiData1 = await programAddress([tokenMint1.toBuffer()])
    const tkiData2 = await programAddress([tokenMint2.toBuffer()])
    const tokData1 = await associatedTokenAddress(new PublicKey(rootData.pubkey), tokenMint1)
    const tokData2 = await associatedTokenAddress(new PublicKey(rootData.pubkey), tokenMint2)

    var feesInbound = true
    var feesToken
    if (feesInbound) {
        feesToken = await associatedTokenAddress(feesOwner.publicKey, tokenMint1)
    } else {
        feesToken = await associatedTokenAddress(feesOwner.publicKey, tokenMint2)
    }

    swapData = anchor.web3.Keypair.generate()
    swapDataPK = swapData.publicKey
    writeData['swapData'] = swapData.publicKey.toString()
    writeData['feesOwner'] = feesOwner.publicKey.toString()
    writeData['feesOwner_secret'] = exportSecretKey(feesOwner)
    writeData['feesToken'] = feesToken.pubkey

    console.log('Create Swap')

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

    let res = await swapContract.rpc.createSwap(
        rootData.nonce,
        true, // use oracle
        false, // inverse oracle
        false, // oracle range check
        1, // 0 - no oracle, 1 - switchboard.xyz
        new anchor.BN(0), // range min
        new anchor.BN(0), // range max
        new anchor.BN(10 ** 9), // swap rate
        new anchor.BN(10 ** 4), // base rate
        feesInbound, // fees on inbound token
        0, // fees basis points
        false, // merchant-only
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authDataPK,
                swapAdmin: swapAdmin1.publicKey,
                swapData: swapDataPK,
                inbInfo: new PublicKey(tkiData1.pubkey),
                outInfo: new PublicKey(tkiData2.pubkey),
                feesToken: new PublicKey(feesToken.pubkey)
            },
            remainingAccounts: [
                { pubkey: oraclePK, isWritable: false, isSigner: false },
            ],
            signers: [swapAdmin1],
        }
    )
    console.log(res)
    let swapName = swapDataPK.toString().substring(0, 8)
    swapName = 'usdv-wsol'
    try {
        await fs.writeFile('data-' + swapName + '.json', JSON.stringify(writeData, null, 4))
    } catch (error) {
        console.log("File Error: " + error)
    }
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
