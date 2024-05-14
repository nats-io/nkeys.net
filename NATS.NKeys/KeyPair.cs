using System.Net.Mail;
using System.Security.Cryptography;
using NATS.NKeys.Internal;
using NATS.NKeys.NaCl;

namespace NATS.NKeys;

public sealed class KeyPair : IDisposable
{
    private readonly PrefixByte _type;
    private readonly byte[] _seed;
    private readonly byte[] _publicKey;

    private KeyPair(PrefixByte type, byte[] seed, byte[] publicKey)
    {
        _type = type;
        _seed = seed;
        _publicKey = publicKey;
    }

    public static KeyPair FromPublicKey(string publicKey)
    {
        var decode = Decode(publicKey);
        var prefix = decode[0];
        var tfp = TypeFromPrefix(prefix);
        if (!tfp.HasValue)
        {
            throw new NKeysException("Not a valid public NKey");
        }

        var bytes = new byte[decode.Length - 1];
        Buffer.BlockCopy(decode, 1, bytes, 0, bytes.Length);

        return new KeyPair(tfp.Value, Array.Empty<byte>(), bytes);
    }

    public static KeyPair FromSeed(string seed)
    {
        var userSeed = DecodeSeed(Decode(seed), out var type);
        return new KeyPair(type, userSeed, Ed25519.PublicKeyFromSeed(userSeed));
    }

    public static KeyPair CreatePair(PrefixByte prefix)
    {
        using var rng = RandomNumberGenerator.Create();
        return CreatePair(prefix, rng);
    }

    public static KeyPair CreatePair(PrefixByte prefix, RandomNumberGenerator rng)
    {
        if (!IsValidPublicPrefixByte((byte)prefix))
            throw new NKeysException("Invalid prefix");

        var seed = new byte[32];
        rng.GetBytes(seed);
        var publicKey = Ed25519.PublicKeyFromSeed(seed);

        return new KeyPair(prefix, seed, publicKey);
    }

    public string GetSeed() => Encode((byte)_type, true, _seed);

    public string GetPublicKey() => Encode((byte)_type, false, _publicKey);

    public byte[] Sign(byte[] input)
    {
        var privateKey = Ed25519.ExpandedPrivateKeyFromSeed(_seed);
        var rv = Ed25519.Sign(input, privateKey);
        CryptoBytes.Wipe(privateKey);
        return rv;
    }

    public bool Verify(byte[] input, byte[] signature) =>
        Ed25519.Verify(signature, input, _publicKey);

    public void Dispose()
    {
        CryptoBytes.Wipe(_seed);
        CryptoBytes.Wipe(_publicKey);
    }

    private static string Encode(byte prefixByte, bool seed, byte[] src)
    {
        if (!IsValidPublicPrefixByte(prefixByte))
            throw new NKeysException("Invalid prefix");

        if (src.Length != 32)
            throw new NKeysException("Invalid seed size");

        var stream = new MemoryStream();

        if (seed)
        {
            // To make this human printable for both bytes, we need to do a little
            // bit manipulation to set up for base32 encoding which takes 5 bits at a time.
            var b1 = (byte)(NKeysConstants.PrefixByteSeed | (prefixByte >> 5));
            var b2 = (byte)((prefixByte & 31) << 3); // 31 = 00011111

            stream.WriteByte(b1);
            stream.WriteByte(b2);
        }
        else
        {
            stream.WriteByte(prefixByte);
        }

        // write payload
        stream.Write(src, 0, src.Length);

        // Calculate and write crc16 checksum
        var checksum = BitConverter.GetBytes(Crc16.Checksum(stream.ToArray()));
        stream.Write(checksum, 0, checksum.Length);

        return Base32.Encode(stream.ToArray());
    }

    private static byte[] Decode(string src)
    {
        var raw = Base32.Decode(src);
        var crc = (ushort)(raw[raw.Length - 2] | raw[raw.Length - 1] << 8);

        // trim off the CRC16
        var len = raw.Length - 2;
        var data = new byte[len];
        Buffer.BlockCopy(raw, 0, data, 0, len);

        if (crc != Crc16.Checksum(data))
            throw new NKeysException("Invalid CRC");

        return data;
    }

    private static byte[] DecodeSeed(byte[] raw, out PrefixByte type)
    {
        // Need to do the reverse here to get back to internal representation.
        var b1 = (byte)(raw[0] & 248);  // 248 = 11111000
        var prefix = (byte)((raw[0] & 7) << 5 | ((raw[1] & 248) >> 3)); // 7 = 00000111

        if (b1 != NKeysConstants.PrefixByteSeed)
            throw new NKeysException("Invalid Seed.");

        var tfp = TypeFromPrefix(prefix);
        if (!tfp.HasValue)
        {
            throw new NKeysException("Invalid Public Prefix Byte.");
        }

        type = tfp.Value;

        // Trim off the first two bytes
        var data = new byte[raw.Length - 2];
        Buffer.BlockCopy(raw, 2, data, 0, data.Length);
        return data;
    }

    private static PrefixByte? TypeFromPrefix(byte prefixByte)
    {
        switch (prefixByte)
        {
        case NKeysConstants.PrefixByteServer:
            return PrefixByte.Server;
        case NKeysConstants.PrefixByteCluster:
            return PrefixByte.Cluster;
        case NKeysConstants.PrefixByteOperator:
            return PrefixByte.Operator;
        case NKeysConstants.PrefixByteAccount:
            return PrefixByte.Account;
        case NKeysConstants.PrefixByteUser:
            return PrefixByte.User;
        }

        return null;
    }

    private static bool IsValidPublicPrefixByte(byte prefixByte) => prefixByte switch
    {
        NKeysConstants.PrefixByteServer
            or NKeysConstants.PrefixByteCluster
            or NKeysConstants.PrefixByteOperator
            or NKeysConstants.PrefixByteAccount
            or NKeysConstants.PrefixByteUser
            or NKeysConstants.PrefixByteCurve => true,
        _ => false,
    };
}
