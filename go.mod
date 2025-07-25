module github.com/lightningnetwork/lightning-onion

require (
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da
	github.com/btcsuite/btcd v0.24.3-0.20250318170759-4f4ea81776d6
	github.com/btcsuite/btcd/btcec/v2 v2.3.4
	github.com/btcsuite/btclog v0.0.0-20241003133417-09c4e92e319c
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0
	github.com/stretchr/testify v1.10.0
	github.com/urfave/cli v1.22.9
	golang.org/x/crypto v0.33.0
)

require (
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.4 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/lightningnetwork/lightning-onion => ./

go 1.22.0

toolchain go1.23.9
