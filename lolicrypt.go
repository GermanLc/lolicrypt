package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func main() {
	mode := ""
	file := ""
	key := []byte{}
	keyfile := ""
	var err error
	data := []byte{}

	for i := 0; i < len(os.Args)-1; i++ {
		switch os.Args[i] {
		case "-d":
			mode = "decrypt"
		case "-e":
			mode = "encrypt"
		case "--file":
			file = os.Args[i+1]
		case "--key":
			key = []byte(os.Args[i+1])
		case "--keyfile":
			keyfile = os.Args[i+1]
		}
	}

	if mode == "" {
		fmt.Printf("Mode: ")
		fmt.Scanln(&mode)
	}
	if file == "" {
		fmt.Printf("File: ")
		fmt.Scanln(&file)
	}
	if len(key) == 0 && keyfile == "" {
		keytype := "n"
		fmt.Printf("keyfile? [y/N]: ")
		fmt.Scanln(&keytype)
		if keytype == "y" {
			fmt.Printf("Keyfile: ")
			fmt.Scanln(&keyfile)
		} else {
			fmt.Printf("Key: ")
			fmt.Scanln(&key)
		}
	}

	if len(key) == 0 && keyfile == "" {
		panic("not enough arguments")
	}

	if keyfile != "" {
		key, err = ioutil.ReadFile(keyfile)
		if err != nil {
			panic("keyfile " + err.Error())
		}
	}

	data, err = ioutil.ReadFile(file)
	if err != nil {
		panic("readfile " + err.Error())
	}

	if mode == "encrypt" {
		data, err = encrypt(data, key)
	} else if mode == "decrypt" {
		data, err = decrypt(data, key)
	}
	if err != nil {
		panic("crypt " + err.Error())
	}

	err = ioutil.WriteFile(file, data, 0777)
	if err != nil {
		panic("write " + err.Error())
	}

	fmt.Println("successfully " + mode + "ed " + file)
}

func createHash(key []byte) []byte {
	hasher := md5.New()
	hasher.Write(key)
	return hasher.Sum(nil)
}

func encrypt(data []byte, passphrase []byte) ([]byte, error) {
	block, err := aes.NewCipher(createHash(passphrase))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decrypt(data []byte, passphrase []byte) ([]byte, error) {
	block, err := aes.NewCipher(createHash(passphrase))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
