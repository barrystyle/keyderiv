# keyderiv


## to use:


go mod init keyderiv

go mod tidy

go build

./keyderiv


## how does it work:

takes standard extended pubkey in wif format (can obtain this from wallet->info under electrum), is then able to derive the pubkeys in the keypath range m/0/x (standard electrum)
