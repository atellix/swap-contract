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
    const netKeys = await jsonFileRead('../../data/export/network_keys.json')
    const netData = await jsonFileRead('../../data/net.json')

    const rootData = await programAddress([swapContractPK.toBuffer()], swapContractPK)
    const tkiBytes = swapContract.account.tokenInfo.size
    const tkiRent = await provider.connection.getMinimumBalanceForRentExemption(tkiBytes)

    var tokenMint = new PublicKey(netData.tokenMintUSDC)
    var tokenDecimals = 6
    var authData
    var authDataPK
    var swapAdmin1

    const swapCache = await jsonFileRead('../../data/swap.json')
    authDataPK = new PublicKey(swapCache.swapContractRBAC)
    swapAdmin1 = importSecretKey(netKeys['swap-data-admin-1-secret'])

    const tkiData = await programAddress([tokenMint.toBuffer()], swapContractPK)
    const tokData = await associatedTokenAddress(new PublicKey(rootData.pubkey), tokenMint)

    console.log('Fund Swap Admin')
    var tx = new anchor.web3.Transaction()
    tx.add(
        anchor.web3.SystemProgram.transfer({
            fromPubkey: provider.wallet.publicKey,
            toPubkey: swapAdmin1.publicKey,
            lamports: (tkiRent + await provider.connection.getMinimumBalanceForRentExemption(165)),
        })
    )
    await provider.send(tx)

    console.log('Approve Token: ' + tokenMint.toString())
    await swapContract.rpc.approveToken(
        rootData.nonce,
        tkiData.nonce,
        tokData.nonce,
        new anchor.BN(tkiRent),
        new anchor.BN(tkiBytes),
        tokenDecimals,
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authDataPK,
                swapAdmin: swapAdmin1.publicKey,
                swapToken: new PublicKey(tokData.pubkey),
                tokenMint: tokenMint,
                tokenInfo: new PublicKey(tkiData.pubkey),
                tokenProgram: TOKEN_PROGRAM_ID,
                ascProgram: SPL_ASSOCIATED_TOKEN,
                systemProgram: SystemProgram.programId,
                systemRent: SYSVAR_RENT_PUBKEY,
            },
            signers: [swapAdmin1],
        }
    )
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
