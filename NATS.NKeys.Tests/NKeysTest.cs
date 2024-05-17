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

    [Fact]
    public void Encode_decode()
    {
        // var a = new byte[32];
        // var b = NKeys.DecodeSeed(NKeys.Decode(NKeys.Encode((NKeys.PrefixByte)(20 << 3), true, a)), out _);
        // Assert.Equal(a, b);
        //
        // var rnd = new Random();
        // rnd.NextBytes(a);
        // b = NKeys.DecodeSeed(NKeys.Decode(NKeys.Encode((NKeys.PrefixByte)(20 << 3), true, a)), out _);
        // Assert.Equal(a, b);
    }

    [Fact]
    public void Create_user_seed()
    {
        // var user = NKeys.CreateSeed(NKeys.PrefixByte.User);
        // Assert.NotEmpty(user);
        // Assert.False(user.EndsWith("=", StringComparison.Ordinal));
        // Assert.NotNull(NKeys.FromSeed(user));
        // var pk = NKeys.PublicKeyFromSeed(user);
        // Assert.Equal('U', pk[0]);
    }

    [Fact]
    public void Create_account_seed()
    {
        // var acc = NKeys.CreateSeed(NKeys.PrefixByte.Account);
        // Assert.NotEmpty(acc);
        // Assert.False(acc.EndsWith("=", StringComparison.Ordinal));
        // Assert.NotNull(NKeys.FromSeed(acc));
        // var pk = NKeys.PublicKeyFromSeed(acc);
        // Assert.Equal('A', pk[0]);
    }

    [Fact]
    public void Create_operator_seed()
    {
        // var op = NKeys.CreateSeed(NKeys.PrefixByte.Operator);
        // Assert.NotEmpty(op);
        // Assert.False(op.EndsWith("=", StringComparison.Ordinal));
        // Assert.NotNull(NKeys.FromSeed(op));
        // var pk = NKeys.PublicKeyFromSeed(op);
        // Assert.Equal('O', pk[0]);
        var kp = KeyPair.CreatePair(PrefixByte.Operator);
        Assert.NotEmpty(kp.GetSeed());
        Assert.False(kp.GetSeed().EndsWith("=", StringComparison.Ordinal));
        Assert.Equal('O', kp.GetPublicKey()[0]);

        // var kp2 = KeyPair.FromSeed(op);
        // Assert.Equal(pk, kp2.GetPublicKey());
    }

    [Fact]
    public void Public_key_from_seed()
    {
        // // using nsc generated seeds for testing
        // var pk = NKeys.PublicKeyFromSeed("SOAELH6NJCEK4HST5644G4HK7TOAFZGRRJHNM4EUKUY7PPNDLIKO5IH4JM");
        // Assert.Equal("ODPWIBQJVIQ42462QAFI2RKJC4RZHCQSIVPRDDHWFCJAP52NRZK6Z2YC", pk);
        //
        // pk = NKeys.PublicKeyFromSeed("SAANWFZ3JINNPERWT3ALE45U7GYT2ZDW6GJUIVPDKUF6GKAX6AISZJMAS4");
        // Assert.Equal("AATEJXG7UX4HFJ6ZPRTP22P6OYZER36YYD3GVBOVW7QHLU32P4QFFTZJ", pk);
        //
        // pk = NKeys.PublicKeyFromSeed("SUAGDLNBWI2SGHDRYBHD63NH5FGZSVJUW2J7GAJZXWANQFLDW6G5SXZESU");
        // Assert.Equal("UBICBTHDKQRB4LIYA6BMIJ7EA2G7YS7FIWMMVKZJE6M3HS5IVCOLKDY2", pk);
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

        // test seed
        {
            var kp = KeyPair.FromSeed("SOAELH6NJCEK4HST5644G4HK7TOAFZGRRJHNM4EUKUY7PPNDLIKO5IH4JM".ToCharArray());
            Assert.Equal("ODPWIBQJVIQ42462QAFI2RKJC4RZHCQSIVPRDDHWFCJAP52NRZK6Z2YC", kp.GetPublicKey());
        }
    }
}
