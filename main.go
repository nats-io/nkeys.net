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

	testData := nkTestGen.TestData{
		XKeys: generateXKeyTestData(),
	}

	jsonData, err := json.MarshalIndent(testData, "", "  ")
	if err != nil {
		log.Fatal("Error marshaling to JSON:", err)
	}

	fmt.Print(string(jsonData))

	println("bye")
}

func generateXKeyTestData() []nkTestGen.XKeysTestData {
	var data []nkTestGen.XKeysTestData

	for i := 0; i < 100; i++ {
		kp1, seed1, pk1 := generateKeys()
		kp2, seed2, pk2 := generateKeys()

		// Generate random data with length upto ~10KB
		randomData := make([]byte, 1+(i*100))
		_, err := io.ReadFull(rand.Reader, randomData[:])
		if err != nil {
			log.Fatal("Error generating random data:", err)
		}

		seal, err := kp1.Seal(randomData, pk2)
		if err != nil {
			log.Fatal("Error sealing:", err)
		}

		open, err := kp2.Open(seal, pk1)
		if err != nil {
			log.Fatal("Error opening:", err)
		}

		data = append(data, nkTestGen.XKeysTestData{
			Seed1:      string(seed1),
			PK1:        pk1,
			Text:       base64.StdEncoding.EncodeToString(randomData),
			CypherText: base64.StdEncoding.EncodeToString(seal),
			OpenText:   base64.StdEncoding.EncodeToString(open),
			Seed2:      string(seed2),
			PK2:        pk2,
		})
	}

	return data
}

func generateKeys() (nkeys.KeyPair, []byte, string) {
	kp, err := nkeys.CreateCurveKeys()
	if err != nil {
		log.Fatal("Error generating keys:", err)
	}

	seed, err := kp.Seed()
	if err != nil {
		log.Fatal("Error generating keys:", err)
	}

	pk, err := kp.PublicKey()
	if err != nil {
		log.Fatal("Error generating keys:", err)
	}

	return kp, seed, pk
}
