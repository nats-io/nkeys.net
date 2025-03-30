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
        kp1, err := nkeys.FromCurveSeed([]byte(x.Seed1))
        if err != nil {
            t.Fatalf("Can't read seed: %v", err)
        }
        pk1, err := kp1.PublicKey()
        if err != nil {
            t.Fatalf("Can't read public key: %v", err)
        }
        kp2, err := nkeys.FromCurveSeed([]byte(x.Seed2))
        if err != nil {
            t.Fatalf("Can't read seed: %v", err)
        }
        pk2, err := kp2.PublicKey()
        if err != nil {
            t.Fatalf("Can't read public key: %v", err)
        }

        // Double check data
        if x.Text != x.OpenText {
            t.Fatalf("Text mismatch")
        }
        if pk1 != x.PK1 {
            t.Fatalf("Public key mismatch. Expected: %v, Got: %v", x.PK1, pk1)
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

        // Check if sealed ok
        open, err := kp2.Open(cypherText, pk1)
        if err != nil {
            log.Fatal("Error opening:", err)
        }
        if base64.StdEncoding.EncodeToString(open) != x.Text {
            t.Fatalf("Open data mismatch")
        }

        // Double check seal since we can't compare sealed data since
        // it'd be different every time because of nonce
        seal, err := kp1.Seal(randomData, pk2)
        if err != nil {
            log.Fatal("Error sealing:", err)
        }
        open2, err := kp2.Open(seal, pk1)
        if err != nil {
            log.Fatal("Error opening:", err)
        }
        if base64.StdEncoding.EncodeToString(open2) != x.Text {
            t.Fatalf("Open data 2 mismatch")
        }
    }
}
