const { PublicKey, SystemProgram, Transaction } = require('@solana/web3.js')
const { TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, Token } = require('@solana/spl-token')
const anchor = require('@project-serum/anchor')
const { associatedTokenAddress } = require('../../js/atellix-common')

const provider = anchor.Provider.env()
//const provider = anchor.Provider.local()
anchor.setProvider(provider)
//const swapContract = anchor.workspace.SwapContract
//const swapContractPK = swapContract.programId

async function main() {
    let mint = new PublicKey('So11111111111111111111111111111111111111112')
    let owner = provider.wallet.publicKey
    let ata = await associatedTokenAddress(owner, mint)
    console.log('ATA:')
    console.log(ata.pubkey)
    let tx = new Transaction()
    let deposit = false
    let amount = 3
    let token = new Token(provider.connection, mint, TOKEN_PROGRAM_ID, owner)
    if (deposit) {
        try {
            await token.getAccountInfo(new PublicKey(ata.pubkey))
        } catch (error) {
            console.log(error)
            tx.add(Token.createAssociatedTokenAccountInstruction(
                ASSOCIATED_TOKEN_PROGRAM_ID,
                TOKEN_PROGRAM_ID, 
                mint,
                new PublicKey(ata.pubkey),
                owner,
                owner,
            ))            
        }
        tx.add(SystemProgram.transfer({
            fromPubkey: owner,
            lamports: amount * 10**9,
            toPubkey: new PublicKey(ata.pubkey),
        }))
        tx.add(Token.createSyncNativeInstruction(
            TOKEN_PROGRAM_ID, 
            new PublicKey(ata.pubkey),
        ))
    } else {
        let account = await token.getAccountInfo(new PublicKey(ata.pubkey))
        let balance = account.amount
        let diff = balance.sub(new anchor.BN(amount * 10**9))
        console.log(diff.toString())
        tx.add(Token.createCloseAccountInstruction(
            TOKEN_PROGRAM_ID, 
            new PublicKey(ata.pubkey),
            owner,
            owner,
            []
        ))
        console.log(await provider.send(tx))
        tx = new Transaction()
        tx.add(Token.createAssociatedTokenAccountInstruction(
            ASSOCIATED_TOKEN_PROGRAM_ID,
            TOKEN_PROGRAM_ID, 
            mint,
            new PublicKey(ata.pubkey),
            owner,
            owner,
        ))
        tx.add(SystemProgram.transfer({
            fromPubkey: owner,
            lamports: diff.toString(),
            toPubkey: new PublicKey(ata.pubkey),
        }))
        tx.add(Token.createSyncNativeInstruction(
            TOKEN_PROGRAM_ID, 
            new PublicKey(ata.pubkey),
        ))
    }
    //console.log(tx)
    console.log(await provider.send(tx))
}

main()
