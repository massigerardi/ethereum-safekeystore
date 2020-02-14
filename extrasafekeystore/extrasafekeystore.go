package extrasafekeystore

import (
	"crypto/ecdsa"
	"fmt"

	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/massigerardi/go-ethereum/accounts/keystore"

	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/tyler-smith/go-bip39"
)

// CreatePrivateKey returns a private key with a random generated mnemonic set of words
func CreatePrivateKey() (*ecdsa.PrivateKey, error) {
	words, err := generateMnemonic()
	if err != nil {
		return nil, err
	}
	privateKey, err := CreatePrivateKeyFromMnemonic(words)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// CreatePrivateKeyFromMnemonic returns a private key with a given mnemonic set of words
func CreatePrivateKeyFromMnemonic(words string) (*ecdsa.PrivateKey, error) {
	seed, err := hdwallet.NewSeedFromMnemonic(words)
	if err != nil {
		return nil, err
	}

	wallet, err := hdwallet.NewFromSeed(seed)
	if err != nil {
		return nil, err
	}

	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err := wallet.Derive(path, true)
	if err != nil {
		return nil, err
	}

	privateKey, err := wallet.PrivateKey(account)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// StoreWithDefault stores a keystore with go-ethereum default settings and returns the path to the JSON file
func StoreWithDefault(dir string, privateKey *ecdsa.PrivateKey, passphrase string) (string, error) {
	ks := keystore.NewKeyStore(dir, keystore.StandardScryptN, keystore.StandardScryptP)
	path, err := store(privateKey, passphrase, ks)
	if err != nil {
		return "", err
	}
	return path, nil
}

// StoreWithAES256 stores a keystore with AES-256 and longer scrypt iteration and returns the path to the JSON file
func StoreWithAES256(dir string, privateKey *ecdsa.PrivateKey, passphrase string) (string, error) {
	scryptN := 1 << 20
	scryptP := keystore.StandardScryptP
	cipher := keystore.Aes256()
	ks := keystore.NewKeyStoreWithCipher(dir, scryptN, scryptP, cipher)
	path, err := store(privateKey, passphrase, ks)
	if err != nil {
		return "", err
	}
	return path, nil
}

func store(privateKey *ecdsa.PrivateKey, passphrase string, ks *keystore.KeyStore) (string, error) {
	defer timeTrack(time.Now(), "import key")
	account, err := ks.ImportECDSA(privateKey, passphrase)
	if err != nil {
		return "", err
	}
	return account.URL.Path, nil
}

func generateMnemonic() (string, error) {
	// Generate a mnemonic for memorization or user-friendly seeds
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}
	return mnemonic, nil
}

func timeTrack(start time.Time, execution string) {
	elapsed := time.Since(start)
	fmt.Printf("%s took %s\n\n", execution, elapsed)
}

func privateKeyHex(pk *ecdsa.PrivateKey) string {
	privateKeyBytes := crypto.FromECDSA(pk)
	return hexutil.Encode(privateKeyBytes)[2:]
}
