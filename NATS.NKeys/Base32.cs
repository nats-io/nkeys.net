#pragma warning disable SA1512, SA1515
// ReSharper disable MemberCanBePrivate.Global
// ReSharper disable SuggestVarOrType_BuiltInTypes

using System.Runtime.CompilerServices;

namespace NATS.NKeys;

public static class Base32
{
    public static int FromBase32(ReadOnlySpan<char> encoded, Span<byte> result)
    {
        var currentByte = 0;
        var bitsRemaining = 8;
        var outputLength = 0;

        foreach (var currentChar in encoded)
        {
            if (currentChar is >= 'A' and <= 'Z')
                currentByte = (currentByte << 5) | (currentChar - 'A');
            else if (currentChar is >= '2' and <= '7')
                currentByte = (currentByte << 5) | (currentChar - '2' + 26);
            else if (currentChar == '=')
                continue;
            else
                ThrowInvalidBase32CharacterException();

            bitsRemaining -= 5;
            if (bitsRemaining <= 0)
            {
                result[outputLength++] = (byte)(currentByte >> -bitsRemaining);
                currentByte &= (1 << -bitsRemaining) - 1;
                bitsRemaining += 8;
            }
        }

        return outputLength;
    }

    public static int ToBase32(ReadOnlySpan<byte> data, Span<char> output)
    {
        var outputLen = GetEncodedLength(data);
        if (output.Length < outputLen)
            ThrowInsufficientSpaceException();

        var buffer = 0;
        var bufferBits = 0;
        var outputIndex = 0;

        var base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"u8;
        var charsPtr = output;
        var dataPtr = data;
        for (var i = 0; i < data.Length; i++)
        {
            buffer = (buffer << 8) | dataPtr[i];
            bufferBits += 8;

            while (bufferBits >= 5)
            {
                charsPtr[outputIndex++] = (char)base32[(buffer >> (bufferBits - 5)) & 0x1F];
                bufferBits -= 5;
            }
        }

        if (bufferBits > 0)
        {
            charsPtr[outputIndex++] = (char)base32[(buffer << (5 - bufferBits)) & 0x1F];
        }

        return outputIndex;
    }

    public static int GetDataLength(ReadOnlySpan<char> encoded)
    {
        var length = 0;
        foreach (var currentChar in encoded)
        {
            if (currentChar is >= 'A' and <= 'Z' or >= '2' and <= '7')
                length++;
            else if (currentChar != '=')
                ThrowInvalidBase32CharacterException();
        }

        return length * 5 / 8;
    }

    public static int GetEncodedLength(ReadOnlySpan<byte> data)
    {
        var bitsCount = data.Length * 8;
        var rem = bitsCount % 5;
        if (rem > 0)
        {
            bitsCount += 5 - rem;
        }

        var outputLen = bitsCount / 5;

        return outputLen;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowInsufficientSpaceException() => throw new ArgumentException("Insufficient space in output buffer");

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowInvalidBase32CharacterException() => throw new ArgumentException("Invalid base32 character");
}
