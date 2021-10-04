#!/bin/bash

### FOR TESTING ONLY: Use new_swap_token.sh in net_authority/js to create internal tokens

TMP=$(mktemp)
solana-keygen new --silent --no-bip39-passphrase --force --outfile $TMP 2>&1 > /dev/null
MINT=$(solana-keygen pubkey $TMP)
spl-token create-token --decimals 4 --output json -- $TMP 2>&1 > /dev/null
spl-token create-account $MINT --output json 2>&1 > /dev/null
spl-token mint $MINT 100000 --output json 2>&1 > /dev/null
rm $TMP
echo -n $MINT

