using System;
using System.Collections.Generic;
using NATS.NKeys.Benchmarks;
using Xunit;
using Xunit.Abstractions;

namespace NATS.NKeys.Tests;

public class NKeysTest(ITestOutputHelper output)
{
    public static IEnumerable<object[]> PrefixData
    {
        get
        {
            yield return [PrefixByte.User, 'U'];
            yield return [PrefixByte.Account, 'A'];
            yield return [PrefixByte.Operator, 'O'];
            yield return [PrefixByte.Cluster, 'C'];
            yield return [PrefixByte.Server, 'N'];
        }
    }

    [Fact]
    public void XKey_from_seed()
    {
        var kp = KeyPair.FromSeed("SXALBV3GJABONHXVSTRWL2NXYVUF5LY66CGVF4INX2XBMMVYT2KCZXRXWA".ToCharArray());
        Assert.Equal("XBKXUQXILUXDDHTWEDECINN24IUYFQAYG737MB5PMEAVMUMHCIWRA3UD", kp.GetPublicKey());
        var exception = Assert.Throws<NKeysException>(() => kp.Sign(default, default));
        Assert.Equal("Invalid curve key operation", exception.Message);
    }

    [Fact]
    public void XKey_create()
    {
        var kp = KeyPair.CreatePair(PrefixByte.Curve, new FixedRng());
        Assert.Equal("SXAD4F52S2XAJTJ3TGDJ4VXQVW7TU35XJUSVKF25ZRXIWCIUK6NLANRHVY", kp.GetSeed());
        Assert.Equal("XDS6PE7IMMUA7XXUZLWQIPUCRS3J2IGXVMI3ZEOWX7LY4IMBPH2XECZM", kp.GetPublicKey());
        var exception = Assert.Throws<NKeysException>(() => kp.Sign(default, default));
        Assert.Equal("Invalid curve key operation", exception.Message);
    }

    [MemberData(nameof(PrefixData))]
    [Theory]
    public void Create_key_pair(PrefixByte prefix, char initial)
    {
        var pair = KeyPair.CreatePair(prefix);
        Assert.NotNull(pair);
        Assert.NotEmpty(pair.GetSeed());
        Assert.NotEmpty(pair.GetPublicKey());
        Assert.Equal(initial, pair.GetPublicKey()[0]);
        Assert.Equal($"S{initial}", pair.GetSeed().Substring(0, 2));

        var signature = new Memory<byte>(new byte[64]);
        var message = new ReadOnlyMemory<byte>([1, 2]);
        var corrupt = new ReadOnlyMemory<byte>([1, 2, 3]);
        pair.Sign(message, signature);
        Assert.True(pair.Verify(message, signature));
        Assert.False(pair.Verify(corrupt, signature));

        // check against reference implementations
        var pair1Seed = NKeysReference1.FromEncodedSeed(pair.GetSeed());
        var signature1 = NKeysReference1.Sign(pair1Seed, message.ToArray());
        Assert.Equal(signature.Span.ToArray(), signature1);
        Assert.True(NKeysReference1.VerifyUsingSeed(pair1Seed, message.ToArray(), signature.ToArray()));
        Assert.True(NKeysReference1.VerifyUsingSeed(pair1Seed, message.ToArray(), signature1));
        Assert.False(NKeysReference1.VerifyUsingSeed(pair1Seed, corrupt.ToArray(), signature1));

        var pair2 = NKeysUtilsReference2.FromSeed(pair.GetSeed());
        var signature2 = pair2.Sign(message.ToArray());
        Assert.Equal(signature.Span.ToArray(), signature2);
    }

    [MemberData(nameof(PrefixData))]
    [Theory]
    public void Create_with_rng(PrefixByte prefix, char initial)
    {
        var rng = new FixedRng();

        var pair = KeyPair.CreatePair(prefix, rng);
        var seed = pair.GetSeed();
        var pub = pair.GetPublicKey();

        var sk = NKeysReference1.NewSeed(rng);

        output.WriteLine($"seed: {NKeysReference1.GetEncodedSeed(initial, sk)}");
        output.WriteLine($"seed: {seed}");
        Assert.Equal(NKeysReference1.GetEncodedSeed(initial, sk), seed);

        output.WriteLine($"public: {NKeysReference1.GetEncodedPublicKey(initial, sk)}");
        output.WriteLine($"public: {pub}");
        Assert.Equal(NKeysReference1.GetEncodedPublicKey(initial, sk), pub);

        Assert.Equal('S', seed[0]);
        Assert.Equal(initial, seed[1]);
        Assert.Equal(initial, pub[0]);
    }

    [MemberData(nameof(PrefixData))]
    [Theory]
    public void Create_seed_for_prefix(PrefixByte prefix, char initial)
    {
        var kp = KeyPair.CreatePair(prefix);
        Assert.NotEmpty(kp.GetSeed());
        Assert.False(kp.GetSeed().EndsWith("=", StringComparison.Ordinal));
        Assert.Equal(initial, kp.GetPublicKey()[0]);
    }

    [Fact]
    public void Public_key_from_seed()
    {
        // using nsc generated seeds for testing
        var kp = KeyPair.FromSeed("SOAELH6NJCEK4HST5644G4HK7TOAFZGRRJHNM4EUKUY7PPNDLIKO5IH4JM".ToCharArray());
        Assert.Equal("ODPWIBQJVIQ42462QAFI2RKJC4RZHCQSIVPRDDHWFCJAP52NRZK6Z2YC", kp.GetPublicKey());

        kp = KeyPair.FromSeed("SAANWFZ3JINNPERWT3ALE45U7GYT2ZDW6GJUIVPDKUF6GKAX6AISZJMAS4".ToCharArray());
        Assert.Equal("AATEJXG7UX4HFJ6ZPRTP22P6OYZER36YYD3GVBOVW7QHLU32P4QFFTZJ", kp.GetPublicKey());

        kp = KeyPair.FromSeed("SUAGDLNBWI2SGHDRYBHD63NH5FGZSVJUW2J7GAJZXWANQFLDW6G5SXZESU".ToCharArray());
        Assert.Equal("UBICBTHDKQRB4LIYA6BMIJ7EA2G7YS7FIWMMVKZJE6M3HS5IVCOLKDY2", kp.GetPublicKey());
    }

    [Fact]
    public void Api()
    {
        var kp1 = KeyPair.CreatePair(PrefixByte.User);
        var seed = kp1.GetSeed();
        var publicKey = kp1.GetPublicKey();
        output.WriteLine($"seed={seed}");

        var kp2 = KeyPair.FromSeed(seed.ToCharArray());
        Assert.Equal(kp1.GetPublicKey(), kp2.GetPublicKey());
        output.WriteLine($"pk={kp1.GetPublicKey()}");

        var kp3 = KeyPair.FromPublicKey(publicKey.ToCharArray());
        Assert.Equal(kp1.GetPublicKey(), kp3.GetPublicKey());
        output.WriteLine($"pk={kp3.GetPublicKey()}");

        // Using generated seeds
        var encodedSeed = "SOAELH6NJCEK4HST5644G4HK7TOAFZGRRJHNM4EUKUY7PPNDLIKO5IH4JM".ToCharArray();
        var encodedPublicKey = "ODPWIBQJVIQ42462QAFI2RKJC4RZHCQSIVPRDDHWFCJAP52NRZK6Z2YC".ToCharArray();

        var kp4 = KeyPair.FromSeed(encodedSeed);
        Assert.Equal(encodedPublicKey, kp4.GetPublicKey());
        output.WriteLine($"pk={kp4.GetPublicKey()}");

        var kp5 = KeyPair.FromPublicKey(encodedPublicKey);
        Assert.Equal(encodedPublicKey, kp5.GetPublicKey());

        var message = new ReadOnlyMemory<byte>([42, 43, 44]);
        var signature = new Memory<byte>(new byte[64]);
        kp4.Sign(message, signature);
        Assert.True(kp5.Verify(message, signature));

        var corrupt = new ReadOnlyMemory<byte>([43, 44]);
        Assert.False(kp5.Verify(corrupt, signature));
    }

    [Fact]
    public void Public_key_does_not_have_seed_nor_secret_key()
    {
        var encodedPublicKey = "ODPWIBQJVIQ42462QAFI2RKJC4RZHCQSIVPRDDHWFCJAP52NRZK6Z2YC".ToCharArray();

        var pair = KeyPair.FromPublicKey(encodedPublicKey);
        Assert.Equal(encodedPublicKey, pair.GetPublicKey());

        Assert.Throws<NKeysException>(() => pair.GetSeed());
        Assert.Throws<NKeysException>(() => pair.Sign(default, default));
    }
}
