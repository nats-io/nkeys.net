using System;
using BenchmarkDotNet.Attributes;
using NATS.NKeys.NaCl;
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

namespace NATS.NKeys.Benchmarks;

[MemoryDiagnoser]
[ShortRunJob]
[PlainExporter]
public class KeyPairBench
{
    private byte[] _message = new byte[32];
    private string _seed = "SUAD4F52S2XAJTJ3TGDJ4VXQVW7TU35XJUSVKF25ZRXIWCIUK6NLANREBM";
    private KeyPair _pair;
    private byte[] _pair1_pk;
    private byte[] _pair1_seed;
    private NKeysReference2 _pair2;
    private Memory<byte> _signature = new(new byte[64]);

    [GlobalSetup]
    public void Setup()
    {
        var random = new Random(42);
        random.NextBytes(_message);

        _pair = KeyPair.FromSeed(_seed);

        _pair1_seed = NKeysReference1.NewSeed(new FixedRng());
        _pair1_pk = Ed25519.PublicKeyFromSeed(_pair1_seed);

        _pair2 = NKeysUtilsReference2.FromSeed(_seed);
    }

    [Benchmark]
    public int Sign()
    {
        _pair.Sign(_message, _signature);
        return _signature.Length;
    }

    [Benchmark]
    public int SignRef1()
    {
        var bytes = NKeysReference1.Sign(_pair1_seed, _message);
        return bytes.Length;
    }

    [Benchmark]
    public int SignRef2()
    {
        var bytes = _pair2.Sign(_message);
        return bytes.Length;
    }

    [Benchmark]
    public bool Verify()
        => _pair.Verify(_message, _signature);

    [Benchmark]
    public bool VerifyRef1()
        => NKeysReference1.VerifyUsingPublicKey(_pair1_pk, _message, _signature.ToArray());

    [Benchmark]
    public object FromSeed()
        => KeyPair.FromSeed(_seed);

    [Benchmark]
    public object FromSeedRef1()
        => NKeysReference1.FromEncodedSeed(_seed);

    [Benchmark]
    public object FromSeedRef2()
        => NKeysUtilsReference2.FromSeed(_seed);
}
