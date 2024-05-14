using System;
using Xunit;
using Xunit.Abstractions;

namespace NATS.NKeys.Tests;

public class NKeysTest(ITestOutputHelper output)
{
    [Fact]
    public void Create_seed()
    {
        // var seed = NKeys.CreateSeed(NKeys.PrefixByte.User);
        // output.WriteLine($"pair.PublicKey: {seed}");
        //
        // var pair = NKeys.FromSeed(seed);
        // var bytes = pair.Sign([123, 4]);
        //
        // var verify = pair.Verify(bytes, [123, 4]);
        // output.WriteLine($"verify: {verify}");
        //
        // var kp = KeyPair.FromSeed(seed);
        // Assert.True(kp.Verify([123, 4], bytes));
        // Assert.True(pair.Verify(kp.Sign([123, 4]), [123, 4]));
        //
        // var encode = NKeys.Encode(NKeys.PrefixByte.User, false, pair.PublicKey);
        // output.WriteLine($"encode: {encode}");
        //
        // var publicKey = NKeys.PublicKeyFromSeed(seed);
        // output.WriteLine($"PublicKey: {publicKey}");
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

        var kp2 = KeyPair.FromSeed(seed);
        Assert.Equal(kp1.GetPublicKey(), kp2.GetPublicKey());

        var kp3 = KeyPair.FromPublicKey(publicKey);
        Assert.Equal(kp1.GetPublicKey(), kp3.GetPublicKey());

        // test seed
        {
            var kp = KeyPair.FromSeed("SOAELH6NJCEK4HST5644G4HK7TOAFZGRRJHNM4EUKUY7PPNDLIKO5IH4JM");
            Assert.Equal("ODPWIBQJVIQ42462QAFI2RKJC4RZHCQSIVPRDDHWFCJAP52NRZK6Z2YC", kp.GetPublicKey());
        }
    }
}
