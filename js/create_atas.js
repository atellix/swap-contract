const { promisify } = require('util')
const exec = promisify(require('child_process').exec)
const { jsonFileRead } = require('../../js/atellix-common')

async function main() {
    const swapUSDC = await jsonFileRead('../../data/swap-usdc-usdv.json')
    const swapWSOL = await jsonFileRead('../../data/swap-wsol-usdv.json')

    var res
    console.log('ATA: Swap USDC-USDV')
    res = await exec('spl-token create-account ' + swapUSDC['inbMint'] + ' --owner ' + swapUSDC['swapData'] + ' --output json')
    console.log(res.stdout)
    res = await exec('spl-token create-account ' + swapUSDC['outMint'] + ' --owner ' + swapUSDC['swapData'] + ' --output json')
    console.log(res.stdout)

    console.log('ATA: Swap WSOL-USDV')
    res = await exec('spl-token create-account ' + swapWSOL['inbMint'] + ' --owner ' + swapWSOL['swapData'] + ' --output json')
    console.log(res.stdout)
    res = await exec('spl-token create-account ' + swapWSOL['outMint'] + ' --owner ' + swapWSOL['swapData'] + ' --output json')
    console.log(res.stdout)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
