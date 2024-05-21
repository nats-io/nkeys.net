# NKeys .NET

[![Build and Test](https://github.com/nats-io/nkeys.net/actions/workflows/test.yml/badge.svg)](https://github.com/nats-io/nkeys.net/actions/workflows/test.yml)
[![NuGet](https://img.shields.io/nuget/v/NATS.NKeys.svg)](https://www.nuget.org/packages/NATS.NKeys/)

NKeys is a public-key signature system based on [Ed25519](
https://ed25519.cr.yp.to/) for the [NATS](https://nats.io/) ecosystem.

## Usage

Create a new key pair:

```csharp
// Create a new key pair for a user
KeyPair keyPair = KeyPair.CreatePair(PrefixByte.User);

// Get the seed
// Output example (your seed will be different):
// Seed: SUAOBFVHF4ZWKTBJ6QP4C362WLBBBFIE7ENFTPYKUGZ3M2ESOXY353LXDI
string seed = keyPair.GetSeed();
Console.WriteLine($"Seed: {seed}");

// Get the public key
// Output example (your public key will be different):
// Public key: UBIWK4X3RXCPJ4CMIAVLAFDFABMLCCMZDDLAO5OZZ2265MDLXUTOGO4B
string publicKey = keyPair.GetPublicKey();
Console.WriteLine($"Public key: {publicKey}");
```

Sign and verify a message:

```csharp
// Using already generated seed and public key
var seed = "SOAELH6NJCEK4HST5644G4HK7TOAFZGRRJHNM4EUKUY7PPNDLIKO5IH4JM";
var publicKey = "ODPWIBQJVIQ42462QAFI2RKJC4RZHCQSIVPRDDHWFCJAP52NRZK6Z2YC";

// Create a key pair from seed
KeyPair pair1 = KeyPair.FromSeed(seed);
Assert.Equal(seed, pair1.GetSeed());
Assert.Equal(publicKey, pair1.GetPublicKey());

// Create a key pair from public key
KeyPair pair2 = KeyPair.FromPublicKey(publicKey);
Assert.Equal(publicKey, pair2.GetPublicKey());

// Sign and verify
var message = new ReadOnlyMemory<byte>([42, 43, 44]);
var signature = new Memory<byte>(new byte[64]);
pair1.Sign(message, signature);
Assert.True(pair2.Verify(message, signature));

// Verify fails with corrupt data
var corrupt = new ReadOnlyMemory<byte>([43, 44]);
Assert.False(pair2.Verify(corrupt, signature));
```

## About

A public-key signature system based on [Ed25519](https://ed25519.cr.yp.to/) for
the [NATS](https://nats.io/) ecosystem.

See also https://github.com/nats-io/nkeys
