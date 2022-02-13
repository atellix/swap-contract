const { PublicKey } = require('@solana/web3.js')
const anchor = require('@project-serum/anchor')
const { associatedTokenAddress } = require('../../js/atellix-common')

const provider = anchor.Provider.env()
//const provider = anchor.Provider.local()
anchor.setProvider(provider)
const swapContract = anchor.workspace.SwapContract

function showData(spec) {
    var r = {}
    for (var i in spec) {
        if (typeof spec[i] === 'object' && spec[i].constructor.name === 'Object') {
            r[i] = showData(spec[i])
        } else if (typeof spec[i].toString !== 'undefined') {
            r[i] = spec[i].toString()
        }
    }
    return r
}

async function main() {
    let tki = new PublicKey('5jft9469zMQoaxWA8iiSDiBWLQBq11BKuMus8Yf8X28F')
    let res = await swapContract.account.swapData.fetch(tki)
    //console.log(res)
    console.log(showData(res))
}

main()
