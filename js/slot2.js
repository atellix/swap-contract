const { Buffer } = require('buffer')
const { DateTime } = require("luxon")
const { v4: uuidv4, parse: uuidparse } = require('uuid')
const { PublicKey, SystemProgram, SYSVAR_RENT_PUBKEY } = require('@solana/web3.js')
const { TOKEN_PROGRAM_ID } = require('@solana/spl-token')

const anchor = require('@project-serum/anchor')
const provider = anchor.Provider.env()
//const provider = anchor.Provider.local()
anchor.setProvider(provider)

function sleep(millis) {
    return new Promise(resolve => setTimeout(resolve, millis))
}

async function getBlock(slot) {
    var res = null
    try {
        res = await provider.connection.getBlock(slot, { commitment: 'confirmed' } )
    } catch (error) {}        
    return res
}

async function main() {
    console.log('Get Slot')
    //let sl = await provider.connection.getSlot('confirmed')
    let sl = 92958467
    let bl = await getBlock(sl)
    if (bl) {
        for (var i = 0; i < bl.transactions.length; i++) {
            if (typeof bl.transactions[i].meta.status['Ok'] !== 'undefined') {
                console.log(bl.transactions[i])
            }
        }
    }
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})

