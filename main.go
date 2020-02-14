package main

import (
	"log"

	keystore "github.com/massigerardi/ethereum-safekeystore/extrasafekeystore"
)

func main() {
	//create the private key
	privateKey, err := keystore.CreatePrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	//create a keystore file encrypting with AES 256
	path, err := keystore.StoreWithAES256("./wallets", privateKey, "Arma.virumque.cano")
	if err != nil {
		log.Fatal(err)
	}
	log.Println(path)

}
