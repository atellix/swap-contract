const { Buffer } = require('buffer')
const { DateTime } = require("luxon")
const { v4: uuidv4, parse: uuidparse } = require('uuid')
const { Keypair, PublicKey, SystemProgram, SYSVAR_RENT_PUBKEY } = require('@solana/web3.js')
const { TOKEN_PROGRAM_ID } = require('@solana/spl-token')
const fs = require('fs').promises
const base32 = require("base32.js")

const anchor = require('@project-serum/anchor')
const provider = anchor.Provider.env()
//const provider = anchor.Provider.local()
anchor.setProvider(provider)

const { associatedTokenAddress, programAddress, importSecretKey, exportSecretKey, jsonFileRead, jsonFileWrite } = require('../../js/atellix-common')

async function main() {
    let kp = anchor.web3.Keypair.generate()
    console.log('Manager Pubkey: ' + kp.publicKey.toString())
    console.log('Manager Secret: ' + exportSecretKey(kp))
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
