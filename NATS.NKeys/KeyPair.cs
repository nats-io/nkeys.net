using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using NATS.NKeys.Internal;
using NATS.NKeys.NaCl;

namespace NATS.NKeys;

/// <summary>
/// Represents a NKeys cryptographic key pair.
/// </summary>
public sealed class KeyPair : IDisposable
{
    private readonly PrefixByte _type;
    private readonly byte[] _seed;
    private readonly byte[] _sk;
    private readonly byte[] _pk;

    private KeyPair(PrefixByte type, byte[] seed, byte[] sk, byte[] pk)
    {
        _type = type;
        _seed = seed;
        _sk = sk;
        _pk = pk;
    }

    /// <summary>
    /// Creates a <see cref="KeyPair"/> object from a public key.
    /// </summary>
    /// <param name="publicKey">The public key to create the <see cref="KeyPair"/> object from.</param>
    /// <returns>A new <see cref="KeyPair"/> object.</returns>
    /// <exception cref="NKeysException">Thrown if the public key is not a valid NKey.</exception>
    public static KeyPair FromPublicKey(ReadOnlySpan<char> publicKey)
    {
        Span<byte> buffer = stackalloc byte[64];
        var len = Decode(publicKey, buffer);
        var prefix = buffer[0];
        var prefixByte = TypeFromPrefix(prefix);
        if (!prefixByte.HasValue)
        {
            throw new NKeysException("Not a valid public NKey");
        }

        return new KeyPair(prefixByte.Value, Array.Empty<byte>(), Array.Empty<byte>(), buffer.Slice(1, len - 1).ToArray());
    }

    /// <summary>
    /// Creates a <see cref="KeyPair"/> object from a seed.
    /// </summary>
    /// <param name="encodedSeed">The seed encoded as a ReadOnlySpan of characters.</param>
    /// <returns>A new <see cref="KeyPair"/> object representing the generated key pair.</returns>
    /// <exception cref="NKeysException">Thrown if the encoded seed is not valid or the key pair cannot be created.</exception>
    public static KeyPair FromSeed(ReadOnlySpan<char> encodedSeed)
    {
        Span<byte> buffer = stackalloc byte[64];
        var len = Decode(encodedSeed, buffer);
        DecodeSeed(buffer.Slice(0, len), out var seedSpan, out var type);

        var seed = new ArraySegment<byte>(new byte[32]);
        var pk = new ArraySegment<byte>(new byte[32]);
        var sk = new ArraySegment<byte>(new byte[64]);

        seedSpan.CopyTo(seed.Array);
        Ed25519.KeyPairFromSeed(pk, sk, seed);
        return new KeyPair(type, seed.Array!, sk.Array!, pk.Array!);
    }

    /// <summary>
    /// Creates a new <see cref="KeyPair"/> object with the specified prefix.
    /// </summary>
    /// <param name="prefix">The prefix byte to use for the key pair.</param>
    /// <returns>A new <see cref="KeyPair"/> object.</returns>
    public static KeyPair CreatePair(PrefixByte prefix)
    {
        using var rng = RandomNumberGenerator.Create();
        return CreatePair(prefix, rng);
    }

    /// <summary>
    /// Creates a <see cref="KeyPair"/> object with a specified prefix and random number generator.
    /// </summary>
    /// <param name="prefix">The prefix byte for the <see cref="KeyPair"/> object. Must be a valid prefix.</param>
    /// <param name="rng">The random number generator used to generate the seed.</param>
    /// <returns>A new <see cref="KeyPair"/> object.</returns>
    /// <exception cref="NKeysException">Thrown if the prefix is not valid.</exception>
    public static KeyPair CreatePair(PrefixByte prefix, RandomNumberGenerator rng)
    {
        if (!IsValidPublicPrefixByte((byte)prefix))
            throw new NKeysException("Invalid prefix");

        var seed = new byte[32];
        rng.GetBytes(seed);
        var sk = Ed25519.ExpandedPrivateKeyFromSeed(seed);
        var pk = Ed25519.PublicKeyFromSeed(seed);

        return new KeyPair(prefix, seed, sk, pk);
    }

    /// <summary>
    /// Retrieves the encoded seed used to generate the key pair.
    /// </summary>
    /// <returns>The encoded seed used to generate the key pair.</returns>
    public string GetSeed() => Encode((byte)_type, true, _seed);

    /// <summary>
    /// Returns the encoded public key of the <see cref="KeyPair"/> object.
    /// </summary>
    /// <returns>The encoded public key of the <see cref="KeyPair"/> object.</returns>
    public string GetPublicKey() => Encode((byte)_type, false, _pk);

    /// <summary>
    /// Signs a message with the private key of the <see cref="KeyPair"/> object.
    /// </summary>
    /// <param name="message">The message to be signed.</param>
    /// <param name="signature">The memory to store the signature.</param>
    /// <exception cref="NKeysException">Thrown if the private key is not valid or there is an error during the signing process.</exception>
    public void Sign(ReadOnlyMemory<byte> message, Memory<byte> signature)
    {
        if (!MemoryMarshal.TryGetArray(message, out var inputArray))
            ThrowCouldNotGetArrayException(nameof(message));

        ReadOnlyMemory<byte> readOnlyMemory = signature;
        if (!MemoryMarshal.TryGetArray(readOnlyMemory, out var signatureArray))
            ThrowCouldNotGetArrayException(nameof(signature));

        Ed25519.Sign(signatureArray, inputArray, new ArraySegment<byte>(_sk));
    }

    /// <summary>
    /// Verifies the authenticity of a message using the given signature.
    /// </summary>
    /// <param name="message">The message to verify.</param>
    /// <param name="signature">The signature to use for verification.</param>
    /// <returns>
    /// <c>true</c> if the message is authentic and the signature is valid;
    /// otherwise, <c>false</c>.
    /// </returns>
    public bool Verify(ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> signature)
    {
        if (!MemoryMarshal.TryGetArray(message, out var messageArray))
            ThrowCouldNotGetArrayException(nameof(message));

        if (!MemoryMarshal.TryGetArray(signature, out var signatureArray))
            ThrowCouldNotGetArrayException(nameof(signature));

        return Ed25519.Verify(signatureArray, messageArray, new ArraySegment<byte>(_pk));
    }

    /// <summary>
    /// Disposes the KeyPair object, wiping the sensitive data.
    /// </summary>
    /// <remarks>
    /// This method should be called when the KeyPair object is no longer
    /// needed to safely wipe the sensitive data, such as the seed,
    /// secret key, and public key.
    /// </remarks>
    public void Dispose()
    {
        CryptoBytes.Wipe(_seed);
        CryptoBytes.Wipe(_sk);
        CryptoBytes.Wipe(_pk);
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

        var buffer = stream.ToArray();
        var length = Base32.GetEncodedLength(buffer);
        var chars = new char[length];
        Base32.ToBase32(buffer, chars);
        return new string(chars);
    }

    private static int Decode(ReadOnlySpan<char> src, Span<byte> buffer)
    {
        var length = Base32.GetDataLength(src);

        if (length > buffer.Length)
            ThrowDataTooLargeException("decode");

        var len = Base32.FromBase32(src, buffer);

        var crc = (ushort)(buffer[len - 2] | buffer[len - 1] << 8);

        var data = buffer.Slice(0, len - 2);

        if (crc != Crc16.Checksum(data))
            ThrowInvalidCrcException();

        return data.Length;
    }

    private static void DecodeSeed(ReadOnlySpan<byte> raw, out ReadOnlySpan<byte> buffer, out PrefixByte type)
    {
        // Need to do the reverse here to get back to internal representation.
        var b1 = (byte)(raw[0] & 248);  // 248 = 11111000
        var prefix = (byte)((raw[0] & 7) << 5 | ((raw[1] & 248) >> 3)); // 7 = 00000111

        if (b1 != NKeysConstants.PrefixByteSeed)
        {
            ThrowInvalidSeedException();
        }

        var prefixByte = TypeFromPrefix(prefix);
        if (!prefixByte.HasValue)
        {
            ThrowInvalidPublicPrefixException();
        }

        type = prefixByte!.Value;

        if (raw.Length != 34)
        {
            ThrowInvalidSeedException();
        }

        // Trim off the first two bytes e.g. SU... bit in base32 encoded form
        buffer = raw.Slice(2, raw.Length - 2);
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

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowCouldNotGetArrayException(string param) => throw new NKeysException($"Could not get {param} array");

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowDataTooLargeException(string param) => throw new NKeysException($"Data too large for {param}");

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowInvalidCrcException() => throw new NKeysException("Invalid CRC");

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowInvalidSeedException() => throw new NKeysException("Invalid Seed");

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowInvalidPublicPrefixException() => throw new NKeysException("Invalid Public Prefix Byte");
}
