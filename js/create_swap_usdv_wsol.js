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
    const feesOwner = new PublicKey(netKeys['swap-fees-1-public'])
    const swapBytes = swapContract.account.swapData.size
    const swapRent = await provider.connection.getMinimumBalanceForRentExemption(swapBytes)

    var swapData
    var swapDataPK
    var authData
    var authDataPK
    var swapAdmin1

    const swapCache = await jsonFileRead('../../data/swap.json')
    authDataPK = new PublicKey(swapCache.swapContractRBAC)
    swapAdmin1 = importSecretKey(netKeys['swap-data-admin-1-secret'])

    var writeData = {}

    var oraclePK = new PublicKey('DpoK8Zz69APV9ntjuY9C4LZCxANYMV56M2cbXEdkjxME')
    var mint1 = 'So11111111111111111111111111111111111111112' // WSOL
    var mint2 = netData.tokenMintUSDV
    console.log("Mints: " + mint1 + " " + mint2)
    tokenMint1 = new PublicKey(mint1)
    tokenMint2 = new PublicKey(mint2)
    writeData['tokenMint1'] = tokenMint1.toString()
    writeData['tokenMint2'] = tokenMint2.toString()
    
    const tkiData1 = await programAddress([tokenMint1.toBuffer(), tokenMint2.toBuffer()], swapContractPK)
    const tkiData2 = await programAddress([tokenMint2.toBuffer(), tokenMint1.toBuffer()], swapContractPK)
    const tokData1 = await associatedTokenAddress(new PublicKey(rootData.pubkey), tokenMint1)
    const tokData2 = await associatedTokenAddress(new PublicKey(rootData.pubkey), tokenMint2)

    var feesInbound = true
    var feesToken
    if (feesInbound) {
        feesToken = await associatedTokenAddress(feesOwner, tokenMint1)
    } else {
        feesToken = await associatedTokenAddress(feesOwner, tokenMint2)
    }

    swapData = anchor.web3.Keypair.generate()
    swapDataPK = swapData.publicKey
    writeData['swapData'] = swapData.publicKey.toString()
    writeData['feesOwner'] = feesOwner.toString()
    writeData['feesToken'] = feesToken.pubkey

    console.log('Create Swap')

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

    let res = await swapContract.rpc.createSwap(
        rootData.nonce,
        false, // basis rates
        false, // basis inbound
        true, // use oracle
        false, // oracle max
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
    await jsonFileWrite('../../data/swap-' + swapName + '.json', writeData)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
