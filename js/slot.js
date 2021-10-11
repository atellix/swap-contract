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
    let sl = await provider.connection.getSlot('confirmed')
    console.log(sl)
    let start = sl - 20
    let progs = {}
    for (var k = start; k < sl; k++) {
        console.log('Get Block: ' + k + ' Last Slot: ' + sl)
        let bl = await getBlock(k)
        if (bl) {
            //console.log(bl.transactions[1].meta)
            for (var i = 0; i < bl.transactions.length; i++) {
                let lm = bl.transactions[i].meta.logMessages
                for (var j = 0; j < lm.length; j++) {
                    if (
                        lm[j].substring(0, 8) === 'Program ' &&
                        lm[j].substring(0, 12) !== 'Program log:' && 
                        lm[j].slice(-8) === ' success'
                    ) {
                        let trimmed = lm[j].substring(8, lm[j].length - 8)
                        //console.log(lm[j])
                        //console.log(trimmed)
                        if (typeof progs[trimmed] === 'undefined') {
                            progs[trimmed] = 1
                        } else {
                            progs[trimmed]++
                        }
                    }
                }
            }
        }
        sl = await provider.connection.getSlot()
    }
    console.log(progs)
    //console.log(bl.transactions[0].transaction.message.instructions[0].accounts)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})

