#pragma warning disable SA1120
#pragma warning disable SA1512

// ReSharper disable InconsistentNaming
// ReSharper disable SuggestVarOrType_BuiltInTypes
// ReSharper disable SuggestVarOrType_SimpleTypes
using System.Diagnostics;
using NATS.NKeys;

Console.WriteLine("Running AOT Tests...");
var stopwatch = Stopwatch.StartNew();

foreach (var p in GetPrefixData())
{
    Create_seed_for_prefix(p.prefix, p.initial);
    Create_key_pair(p.prefix, p.initial);
}

Public_key_from_seed();
Api();

stopwatch.Stop();

Console.WriteLine($"[Completed in {stopwatch.Elapsed}]");

Console.WriteLine("PASS");

static IEnumerable<(PrefixByte prefix, char initial)> GetPrefixData()
{
    yield return (PrefixByte.User, 'U');
    yield return (PrefixByte.Account, 'A');
    yield return (PrefixByte.Operator, 'O');
    yield return (PrefixByte.Cluster, 'C');
    yield return (PrefixByte.Server, 'N');
}

void Create_key_pair(PrefixByte prefix, char initial)
{
    Console.Write($"Create_key_pair ({prefix}, {initial}) ");

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

    Console.WriteLine("[OK]");
}

void Create_seed_for_prefix(PrefixByte prefix, char initial)
{
    Console.Write($"Create_seed_for_prefix ({prefix}, {initial}) ");

    var kp = KeyPair.CreatePair(prefix);
    Assert.NotEmpty(kp.GetSeed());
    Assert.False(kp.GetSeed().EndsWith("=", StringComparison.Ordinal));
    Assert.Equal(initial, kp.GetPublicKey()[0]);

    Console.WriteLine("[OK]");
}

void Api()
{
    Console.WriteLine("Api tests");

    // Create a key pair
    {
        // Create a new key pair for a user
        var keyPair = KeyPair.CreatePair(PrefixByte.User);

        // Get the seed
        // Output example (your seed will be different):
        // Seed: SUAOBFVHF4ZWKTBJ6QP4C362WLBBBFIE7ENFTPYKUGZ3M2ESOXY353LXDI
        var seed = keyPair.GetSeed();
        Console.WriteLine($"Seed: {seed}");

        // Get the public key
        // Output example (your public key will be different):
        // Public key: UBIWK4X3RXCPJ4CMIAVLAFDFABMLCCMZDDLAO5OZZ2265MDLXUTOGO4B
        var publicKey = keyPair.GetPublicKey();
        Console.WriteLine($"Public key: {publicKey}");
    }

    // Using generated seeds
    {
        // Using already generated seed and public key
        var seed = "SOAELH6NJCEK4HST5644G4HK7TOAFZGRRJHNM4EUKUY7PPNDLIKO5IH4JM";
        var publicKey = "ODPWIBQJVIQ42462QAFI2RKJC4RZHCQSIVPRDDHWFCJAP52NRZK6Z2YC";

        // Create a key pair from seed
        var pair1 = KeyPair.FromSeed(seed);
        Assert.Equal(seed, pair1.GetSeed());
        Assert.Equal(publicKey, pair1.GetPublicKey());

        // Create a key pair from public key
        var pair2 = KeyPair.FromPublicKey(publicKey);
        Assert.Equal(publicKey, pair2.GetPublicKey());

        // Sign and verify
        var message = new ReadOnlyMemory<byte>([42, 43, 44]);
        var signature = new Memory<byte>(new byte[64]);
        pair1.Sign(message, signature);
        Assert.True(pair2.Verify(message, signature));

        // Verify fails with corrupt data
        var corrupt = new ReadOnlyMemory<byte>([43, 44]);
        Assert.False(pair2.Verify(corrupt, signature));
    }

    Console.WriteLine("[OK]");
}

void Public_key_from_seed()
{
    Console.Write($"Public_key_from_seed ");

    // using nsc generated seeds for testing
    var kp = KeyPair.FromSeed("SOAELH6NJCEK4HST5644G4HK7TOAFZGRRJHNM4EUKUY7PPNDLIKO5IH4JM".ToCharArray());
    Assert.Equal("ODPWIBQJVIQ42462QAFI2RKJC4RZHCQSIVPRDDHWFCJAP52NRZK6Z2YC", kp.GetPublicKey());

    kp = KeyPair.FromSeed("SAANWFZ3JINNPERWT3ALE45U7GYT2ZDW6GJUIVPDKUF6GKAX6AISZJMAS4".ToCharArray());
    Assert.Equal("AATEJXG7UX4HFJ6ZPRTP22P6OYZER36YYD3GVBOVW7QHLU32P4QFFTZJ", kp.GetPublicKey());

    kp = KeyPair.FromSeed("SUAGDLNBWI2SGHDRYBHD63NH5FGZSVJUW2J7GAJZXWANQFLDW6G5SXZESU".ToCharArray());
    Assert.Equal("UBICBTHDKQRB4LIYA6BMIJ7EA2G7YS7FIWMMVKZJE6M3HS5IVCOLKDY2", kp.GetPublicKey());

    Console.WriteLine("[OK]");
}

internal static class Assert
{
    public static void Equal(string expected, string actual)
    {
        if (!string.Equals(expected, actual))
            throw new Exception($"Expected: {expected}, Actual: {actual}");
    }

    public static void Equal(char expected, char actual)
    {
        if (!Equals(expected, actual))
            throw new Exception($"Expected: {expected}, Actual: {actual}");
    }

    public static void NotEmpty(string input)
    {
        if (string.IsNullOrEmpty(input))
            throw new Exception("Input is empty");
    }

    public static void False(bool input)
    {
        if (input)
            throw new Exception("Input is true");
    }

    public static void True(bool input)
    {
        if (!input)
            throw new Exception("Input is true");
    }

    public static void NotNull(object value)
    {
        if (value == null)
            throw new Exception("Value is null");
    }
}
