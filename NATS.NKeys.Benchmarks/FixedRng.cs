using System;
using System.Security.Cryptography;

namespace NATS.NKeys.Benchmarks;

/// <summary>
/// Always generates the same byte sequence.
/// </summary>
public class FixedRng : RandomNumberGenerator
{
    private readonly byte[] _unit = new byte[32];

    public FixedRng()
        : this(42)
    {
    }

    public FixedRng(int seed) => new Random(seed).NextBytes(_unit);

    public FixedRng(byte[] unit) => _unit = unit;

    public override void GetBytes(byte[] data)
    {
        for (var index = 0; index < data.Length; index++)
        {
            data[index] = _unit[index % _unit.Length];
        }
    }
}
