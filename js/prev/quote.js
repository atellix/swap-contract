const { Buffer } = require('buffer')
const { DateTime } = require("luxon")
const { v4: uuidv4, parse: uuidparse } = require('uuid')
const { PublicKey, SystemProgram, SYSVAR_RENT_PUBKEY } = require('@solana/web3.js')
const { TOKEN_PROGRAM_ID } = require('@solana/spl-token')

const anchor = require('@project-serum/anchor')
const provider = anchor.Provider.env()
//const provider = anchor.Provider.local()
anchor.setProvider(provider)
const swapContract = anchor.workspace.SwapContract

//console.log(swapContract.programId.toString())
//process.exit(0)

async function main() {
    console.log('Oracle Result')
    await swapContract.rpc.oracleResult(
        {
            accounts: {
                oracleData: new PublicKey('DpoK8Zz69APV9ntjuY9C4LZCxANYMV56M2cbXEdkjxME'),
            },
        }
    )
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})

