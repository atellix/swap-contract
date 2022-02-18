const { Buffer } = require('buffer')
const { PublicKey, Keypair } = require('@solana/web3.js')
const { promisify } = require('util')
const exec = promisify(require('child_process').exec)
const fs = require('fs').promises
const base32 = require('base32.js')
const anchor = require('@project-serum/anchor')
const { importSecretKey, exportSecretKey, jsonFileRead, jsonFileWriteKey } = require('../../js/atellix-common')

const provider = anchor.Provider.env()
//const provider = anchor.Provider.local()
anchor.setProvider(provider)

async function main() {
    addr = anchor.web3.Keypair.generate()
    console.log(addr.publicKey.toString())
    await jsonFileWriteKey('key-' + addr.publicKey.toString() + '.json', addr)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
