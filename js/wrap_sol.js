const { PublicKey, SystemProgram, Transaction } = require('@solana/web3.js')
const { TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, AccountLayout, Token } = require('@solana/spl-token')
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
    let amount = 5
    let token = new Token(provider.connection, mint, TOKEN_PROGRAM_ID, owner)
    if (deposit) {
        try {
            await token.getAccountInfo(new PublicKey(ata.pubkey))
        } catch (error) {
            //console.log(error)
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
        console.log(await provider.send(tx))
    } else {
        let kp = anchor.web3.Keypair.generate()
        let size = AccountLayout.span
        let rent = await provider.connection.getMinimumBalanceForRentExemption(size)
        tx.add(SystemProgram.createAccount({
            fromPubkey: owner,
            newAccountPubkey: kp.publicKey,
            lamports: rent,
            space: size,
            programId: TOKEN_PROGRAM_ID,
        }))
        tx.add(Token.createInitAccountInstruction(
            TOKEN_PROGRAM_ID,
            mint,
            kp.publicKey,
            owner,
        ))
        tx.add(Token.createTransferInstruction(
            TOKEN_PROGRAM_ID, 
            new PublicKey(ata.pubkey),
            kp.publicKey,
            owner,
            [provider.wallet.payer],
            amount * 10**9,
            0,
        ))
        tx.add(Token.createCloseAccountInstruction(
            TOKEN_PROGRAM_ID, 
            kp.publicKey,
            owner,
            owner,
            [],
        ))
        console.log(await provider.send(tx, [kp]))
    }
    //console.log(tx)
}

main()
