const { importSecretKey } = require('../../js/atellix-common')

async function main() {
    var k = importSecretKey('xtj8ey8bqgxt09rqkz5wtbkzqcbreaw6y5yywmnvnafrf7f1qh9kbz4e3xyrhtg7mhebfv9sh04an21gv44sn4mjpjyfkafyb66jvnr')
    console.log(k.publicKey.toString())
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
