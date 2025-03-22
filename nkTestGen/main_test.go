package nkTestGen

import (
	"encoding/base64"
	"encoding/json"
	"github.com/nats-io/nkeys"
	"log"
	"os"
	"testing"
)

func TestXKeys(t *testing.T) {
	// Open the JSON file
	file, err := os.Open("test_data.json")
	if err != nil {
		t.Fatalf("Failed to open JSON file: %v", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			t.Fatalf("Failed to close JSON file: %v", err)
		}
	}(file)

	// Decode the JSON array into a slice of XKeysTestData structs
	var data TestData
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	// Print each struct element
	for _, x := range data.XKeys {

		if x.Text != x.OpenText {
			t.Fatalf("Text mismatch")
		}

		kp1, err := nkeys.FromCurveSeed([]byte(x.Seed1))
		if err != nil {
			t.Fatalf("Can't read seed: %v", err)
		}
		pk1, err := kp1.PublicKey()
		if err != nil {
			t.Fatalf("Can't read public key: %v", err)
		}
		if pk1 != x.PK1 {
			t.Fatalf("Public key mismatch. Expected: %v, Got: %v", x.PK1, pk1)
		}

		kp2, err := nkeys.FromCurveSeed([]byte(x.Seed2))
		if err != nil {
			t.Fatalf("Can't read seed: %v", err)
		}
		pk2, err := kp2.PublicKey()
		if err != nil {
			t.Fatalf("Can't read public key: %v", err)
		}
		if pk2 != x.PK2 {
			t.Fatalf("Public key mismatch. Expected: %v, Got: %v", x.PK2, pk2)
		}

		randomData, err := base64.StdEncoding.DecodeString(x.Text)
		if err != nil {
			t.Fatalf("Can't read random data: %v", err)
		}

		cypherText, err := base64.StdEncoding.DecodeString(x.CypherText)
		if err != nil {
			t.Fatalf("Can't read random data: %v", err)
		}

		openedData, err := kp2.Open(cypherText, pk1)
		if err != nil {
			log.Fatal("Error opening:", err)
		}
		openedDataBase64 := base64.StdEncoding.EncodeToString(openedData)
		if openedDataBase64 != x.Text {
			t.Fatalf("Open data mismatch")
		}

		sealedData, err := kp1.Seal(randomData, pk2)
		if err != nil {
			log.Fatal("Error sealing:", err)
		}
		openedData2, err := kp2.Open(sealedData, pk1)
		if err != nil {
			log.Fatal("Error opening:", err)
		}
		openedData2Base64 := base64.StdEncoding.EncodeToString(openedData2)
		if openedData2Base64 != x.Text {
			t.Fatalf("Open data 2 mismatch")
		}
	}
}
