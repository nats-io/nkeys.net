package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/nats-io/nkeys"
	"io"
	"log"
	"nats.io/nkeys.net/nkTestGen"
)

func main() {
	println("Generating test data...")

	xkeys := generateXKeyTestData()

	testData := nkTestGen.TestData{
		XKeys: xkeys,
	}

	jsonData, err := json.MarshalIndent(testData, "", "  ")
	if err != nil {
		log.Fatal("Error marshaling to JSON:", err)
	}

	fmt.Print(string(jsonData))

	println("bye")
}

func generateXKeyTestData() []nkTestGen.XKeysTestData {
	var keyPairs []nkTestGen.XKeysTestData

	for i := 0; i < 100; i++ {

		kp1, seed1, pk1, err := generateKeys()
		if err != nil {
			log.Fatal("Error generating keys:", err)
		}

		kp2, seed2, pk2, err := generateKeys()
		if err != nil {
			log.Fatal("Error generating keys:", err)
		}

		// Generate random data with length upto ~10KB
		randomLen := 1 + (i * 100)
		randomData := make([]byte, randomLen)
		_, err = io.ReadFull(rand.Reader, randomData[:])
		if err != nil {
			log.Fatal("Error generating random data:", err)
		}
		text := base64.StdEncoding.EncodeToString(randomData)

		sealedData, err := kp1.Seal(randomData, pk2)
		if err != nil {
			log.Fatal("Error sealing:", err)
		}

		sealedDataBase64 := base64.StdEncoding.EncodeToString(sealedData)

		openedData, err := kp2.Open(sealedData, pk1)
		if err != nil {
			log.Fatal("Error opening:", err)
		}

		keyPairData := nkTestGen.XKeysTestData{
			Seed1:      string(seed1),
			PK1:        pk1,
			Text:       text,
			CypherText: sealedDataBase64,
			OpenText:   base64.StdEncoding.EncodeToString(openedData),
			Seed2:      string(seed2),
			PK2:        pk2,
		}

		keyPairs = append(keyPairs, keyPairData)

	}

	return keyPairs
}

func generateKeys() (nkeys.KeyPair, []byte, string, error) {
	kp, err := nkeys.CreateCurveKeys()
	if err != nil {
		return nil, nil, "", err
	}

	seed, err := kp.Seed()
	if err != nil {
		return nil, nil, "", err
	}

	pk, err := kp.PublicKey()
	if err != nil {
		return nil, nil, "", err
	}

	return kp, seed, pk, nil
}
