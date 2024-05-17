using System;
using System.IO;
using System.Security.Cryptography;
using NATS.NKeys.Internal;
using NATS.NKeys.NaCl;

namespace NATS.NKeys.Benchmarks;

/// <summary>
/// Helper class for NKeys operations implemented using a simple approach
/// as a proof of concept and reference implementation to compare with the optimized version.
/// </summary>
public static class NKeysReference1
{
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    // New 32-byte seed using a random number generator
    public static byte[] NewSeed(RandomNumberGenerator rng)
    {
        var seed = new byte[32];
        rng.GetBytes(seed);
        return seed;
    }

    // Data Format:
    // +--+--------------------------------+--+
    // |XX|          SEED(32)              |CR|
    // +--+--------------------------------+--+
    //   XX: [ 2 bytes] prefix e.g., SU for User seed (secret key)
    // SEED: [32 bytes] seed generated using an RNG (secret key)
    //   CR: [ 2 bytes] CRC16 checksum of prefix and seed
    public static string GetEncodedSeed(char initial, byte[] seed)
    {
        // Encode first two bytes to generate the prefix letters in Base32 e.g., SU for User seed
        var s = Base32Alphabet.IndexOf('S');
        var i = Base32Alphabet.IndexOf(initial);
        var prefix = new byte[2];
        prefix[0] = (byte)(s << 3 | i >> 2);
        prefix[1] = (byte)((i & 3) << 6);

        // Combine the prefix and seed
        var stream = new MemoryStream();
        stream.Write(prefix, 0, prefix.Length);
        stream.Write(seed, 0, seed.Length);

        // Calculate the CRC16 checksum of the prefix and seed
        var checksum = BitConverter.GetBytes(Crc16.Checksum(stream.ToArray()));
        stream.Write(checksum, 0, checksum.Length);
        var data = stream.ToArray();

        // Encode the data to Base32
        var length = Base32.GetEncodedLength(data);
        var chars = new char[length];
        Base32.ToBase32(data, chars);
        return new string(chars);
    }

    // Data Format:
    // +-+--------------------------------+--+
    // |X|          PUB(32)              |CR|
    // +-+--------------------------------+--+
    //    X: [ 1 byte ] prefix e.g., U for User
    //  PUB: [32 bytes] ED25519 Public Key generated using a seed (secret key)
    //   CR: [ 2 bytes] CRC16 checksum of prefix and seed
    public static string GetEncodedPublicKey(char initial, byte[] seed)
    {
        // Encode first byte to generate the prefix letter in Base32 e.g., U for User
        var i = Base32Alphabet.IndexOf(initial);
        var prefix = new byte[1];
        prefix[0] = (byte)(i << 3);

        // Generate the public key from the seed
        var publicKeyFromSeed = Ed25519.PublicKeyFromSeed(seed);

        // Combine the prefix and public key
        var stream = new MemoryStream();
        stream.Write(prefix, 0, prefix.Length);
        stream.Write(publicKeyFromSeed, 0, publicKeyFromSeed.Length);

        // Calculate the CRC16 checksum of the prefix and public key
        var checksum = BitConverter.GetBytes(Crc16.Checksum(stream.ToArray()));
        stream.Write(checksum, 0, checksum.Length);
        var data = stream.ToArray();

        // Encode the data to Base32
        var length = Base32.GetEncodedLength(data);
        var chars = new char[length];
        Base32.ToBase32(data, chars);
        return new string(chars);
    }

    public static byte[] FromEncodedSeed(string encodedSeed)
    {
        var length = Base32.GetDataLength(encodedSeed.ToCharArray());
        var raw = new Span<byte>(new byte[length]);
        Base32.FromBase32(encodedSeed.ToCharArray(), raw);
        return raw.Slice(2, 32).ToArray();
    }

    // Ed25519 wrapper
    public static byte[] Sign(byte[] seed, byte[] input)
    {
        var privateKey = Ed25519.ExpandedPrivateKeyFromSeed(seed);
        return Ed25519.Sign(input, privateKey);
    }

    // Ed25519 wrapper
    public static bool VerifyUsingSeed(byte[] seed, byte[] input, byte[] signature)
    {
        var publicKey = Ed25519.PublicKeyFromSeed(seed);
        return VerifyUsingPublicKey(publicKey, input, signature);
    }

    // Ed25519 wrapper
    public static bool VerifyUsingPublicKey(byte[] publicKey, byte[] input, byte[] signature)
        => Ed25519.Verify(signature, input, publicKey);
}
