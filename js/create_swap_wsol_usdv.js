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
    const feesOwner = new PublicKey(netKeys['swap-fees-1-public'])
    const swapBytes = swapContract.account.swapData.size
    const swapRent = await provider.connection.getMinimumBalanceForRentExemption(swapBytes)

    var authData
    var authDataPK
    var swapAdmin1
    var swapId = 0

    const swapCache = await jsonFileRead('../../data/swap.json')
    authDataPK = new PublicKey(swapCache.swapContractRBAC)
    swapAdmin1 = importSecretKey(netKeys['swap-data-admin-1-secret'])

    var writeData = {}

    var oraclePK = new PublicKey('DpoK8Zz69APV9ntjuY9C4LZCxANYMV56M2cbXEdkjxME')
    var collateralTokenMint = 'So11111111111111111111111111111111111111112' // WSOL
    var issuingTokenMint = netData.tokenMintUSDV
    console.log('Mints: ' + collateralTokenMint + ' ' + issuingTokenMint)
    collateralMint = new PublicKey(collateralTokenMint)
    issuingMint = new PublicKey(issuingTokenMint)
    writeData['inbMint'] = collateralMint.toString()
    writeData['outMint'] = issuingMint.toString()
    
    var buf = Buffer.alloc(2)
    buf.writeInt16LE(swapId)
    const swapData = await programAddress([collateralMint.toBuffer(), issuingMint.toBuffer(), buf], swapContractPK)

    var feesInbound = true
    var feesToken
    if (feesInbound) {
        feesToken = await associatedTokenAddress(feesOwner, collateralMint)
    } else {
        feesToken = await associatedTokenAddress(feesOwner, issuingMint)
    }

    writeData['swapData'] = swapData.pubkey
    writeData['feesOwner'] = feesOwner.toString()
    writeData['feesToken'] = feesToken.pubkey

    console.log('SwapAdmin:')
    console.log(swapAdmin1.publicKey.toString())

    console.log('Fund Swap Admin')
    const tx = new anchor.web3.Transaction()
    tx.add(
        anchor.web3.SystemProgram.transfer({
            fromPubkey: provider.wallet.publicKey,
            toPubkey: swapAdmin1.publicKey,
            lamports: await provider.connection.getMinimumBalanceForRentExemption(swapContract.account.swapData.size),
        })
    )
    await provider.send(tx)

    console.log('Create Swap')
    let res = await swapContract.rpc.createSwap(
        swapId,                     // swap id
        rootData.nonce,             // root bump seed
        swapData.nonce,             // swap bump seed
        false,                      // oracle verify
        1,                          // oracle type: 0 - no oracle, 1 - switchboard.xyz
        new anchor.BN(0),           // oracle verify min
        new anchor.BN(0),           // oracle verify max
        feesInbound,                // fees on inbound token
        // Inbound "Collateral" tokens (minting... swap_direction = 1: Collateral -> Issuing
        9,                          // decimals
        false,                      // basis swap rates
        true,                       // oracle swap rates
        false,                      // oracle max
        false,                      // oracle inverse
        0,                          // fees bps
        new anchor.BN(10 ** 4),     // swap rate
        new anchor.BN(10 ** 9),     // base rate
        false,                      // merchant-enabled swap
        // Outbound "Issuing" tokens (burning... swap_direction = 0: Issuing -> Collateral)
        4,                          // decimals
        true,                       // basis swap rates
        true,                       // oracle swap rates
        true,                       // oracle max
        true,                       // oracle inverse
        100,                        // fees bps
        new anchor.BN(10 ** 4),     // swap rate
        new anchor.BN(10 ** 9),     // base rate
        true,                       // merchant-enabled swap
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authDataPK,
                swapAdmin: swapAdmin1.publicKey,
                swapData: new PublicKey(swapData.pubkey),
                inbMint: collateralMint,
                outMint: issuingMint,
                feesToken: new PublicKey(feesToken.pubkey),
                systemProgram: SystemProgram.programId,
            },
            remainingAccounts: [
                { pubkey: oraclePK, isWritable: false, isSigner: false },
            ],
            signers: [swapAdmin1],
        }
    )
    console.log(res)
    let swapName = swapData.pubkey.substring(0, 8)
    swapName = 'wsol-usdv'
    await jsonFileWrite('../../data/swap-' + swapName + '.json', writeData)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
