const { Buffer } = require('buffer')
const { DateTime } = require('luxon')
const { v4: uuidv4, parse: uuidparse } = require('uuid')
const { PublicKey, Keypair, SystemProgram, SYSVAR_RENT_PUBKEY } = require('@solana/web3.js')
const { TOKEN_PROGRAM_ID } = require('@solana/spl-token')
const { PROGRAM_ID, createCreateMetadataAccountV3Instruction } = require('@metaplex-foundation/mpl-token-metadata')
const { promisify } = require('util')
const exec = promisify(require('child_process').exec)
const fs = require('fs').promises
const base32 = require('base32.js')
const anchor = require('@project-serum/anchor')
const { programAddress, importSecretKey, jsonFileRead } = require('../../js/atellix-common')

const provider = anchor.Provider.env()
//const provider = anchor.Provider.local()
anchor.setProvider(provider)

async function main() {
    const netKeys = await jsonFileRead('../../data/export/network_keys.json')
    var mint = new PublicKey(netKeys['usdv-token-1-public'])
    var md = await programAddress([Buffer.from('metadata', 'utf8'), PROGRAM_ID.toBuffer(), mint.toBuffer()], PROGRAM_ID)
    var mintAuth = importSecretKey(netKeys['usdv-mint-1-secret'])
    var tx = new anchor.web3.Transaction()
    tx.add(createCreateMetadataAccountV3Instruction(
        {
            metadata: new PublicKey(md.pubkey),
            mint: mint,
            mintAuthority: mintAuth.publicKey,
            payer: provider.wallet.publicKey,
            updateAuthority: mintAuth.publicKey,
        },
        {
            createMetadataAccountArgsV3: {
                collectionDetails: null,
                data: {
                    collection: null,
                    creators: null,
                    name: 'Virtual USD',
                    sellerFeeBasisPoints: 0,
                    symbol: 'USDV',
                    uri: 'https://media.atellix.net/token/usdv.json',
                    uses: null
                },
                isMutable: true
            }
        }
    ))
    console.log(await provider.send(tx, [mintAuth]))
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
