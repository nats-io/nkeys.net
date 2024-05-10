#pragma warning disable CS0465
#pragma warning disable CS1572
#pragma warning disable CS1573
#pragma warning disable CS8603
#pragma warning disable CS8618
#pragma warning disable CS8625
#pragma warning disable SA1001
#pragma warning disable SA1002
#pragma warning disable SA1003
#pragma warning disable SA1005
#pragma warning disable SA1008
#pragma warning disable SA1009
#pragma warning disable SA1011
#pragma warning disable SA1012
#pragma warning disable SA1021
#pragma warning disable SA1027
#pragma warning disable SA1106
#pragma warning disable SA1111
#pragma warning disable SA1117
#pragma warning disable SA1119
#pragma warning disable SA1122
#pragma warning disable SA1137
#pragma warning disable SA1201
#pragma warning disable SA1202
#pragma warning disable SA1204
#pragma warning disable SA1206
#pragma warning disable SA1300
#pragma warning disable SA1303
#pragma warning disable SA1307
#pragma warning disable SA1400
#pragma warning disable SA1407
#pragma warning disable SA1413
#pragma warning disable SA1500
#pragma warning disable SA1505
#pragma warning disable SA1508
#pragma warning disable SA1512
#pragma warning disable SA1513
#pragma warning disable SA1514
#pragma warning disable SA1515
#pragma warning disable SX1309
#pragma warning disable SA1507
#pragma warning disable SA1401
#pragma warning disable SA1132
#pragma warning disable SA1312
#pragma warning disable SA1520
#pragma warning disable SA1107
#pragma warning disable SA1313
#pragma warning disable SA1501
#pragma warning disable SA1025
#pragma warning disable SA1025

// Copyright 2019 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Borrowed from https://github.com/CryptoManiac/Ed25519

using System;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace NATS.NKeys.NaCl
{
    /// <summary>
    /// Utility class for cryptography.
    /// </summary>
    internal static class CryptoBytes
    {
        /// <summary>
        /// Comparison of two arrays.
        ///
        /// The runtime of this method does not depend on the contents of the arrays. Using constant time
        /// prevents timing attacks that allow an attacker to learn if the arrays have a common prefix.
        ///
        /// It is important to use such a constant time comparison when verifying MACs.
        /// </summary>
        /// <param name="x">Byte array</param>
        /// <param name="y">Byte array</param>
        /// <returns>True if arrays are equal</returns>
        public static bool ConstantTimeEquals(byte[] x, byte[] y)
        {
            if (x == null) throw new ArgumentNullException(nameof(x));
            if (y == null) throw new ArgumentNullException(nameof(y));

            if (x.Length != y.Length)
                return false;
            return InternalConstantTimeEquals(x, 0, y, 0, x.Length) != 0;
        }

        /// <summary>
        /// Comparison of two array segments.
        ///
        /// The runtime of this method does not depend on the contents of the arrays. Using constant time
        /// prevents timing attacks that allow an attacker to learn if the arrays have a common prefix.
        ///
        /// It is important to use such a constant time comparison when verifying MACs.
        /// </summary>
        /// <param name="x">Byte array segment</param>
        /// <param name="y">Byte array segment</param>
        /// <returns>True if contents of x and y are equal</returns>
        public static bool ConstantTimeEquals(ArraySegment<byte> x, ArraySegment<byte> y)
        {
            if (x == null) throw new ArgumentNullException(nameof(x));
            if (y == null) throw new ArgumentNullException(nameof(y));

            if (x.Array == null || y.Array == null) throw new ArgumentNullException();
            if (x.Count != y.Count)
                return false;
            return InternalConstantTimeEquals(x.Array, x.Offset, y.Array, y.Offset, x.Count) != 0;
        }

        /// <summary>
        /// Comparison of two byte sequences.
        ///
        /// The runtime of this method does not depend on the contents of the arrays. Using constant time
        /// prevents timing attacks that allow an attacker to learn if the arrays have a common prefix.
        ///
        /// It is important to use such a constant time comparison when verifying MACs.
        /// </summary>
        /// <param name="x">Byte array</param>
        /// <param name="xOffset">Offset of byte sequence in the x array</param>
        /// <param name="y">Byte array</param>
        /// <param name="yOffset">Offset of byte sequence in the y array</param>
        /// <param name="length">Lengh of byte sequence</param>
        /// <returns>True if sequences are equal</returns>
        public static bool ConstantTimeEquals(byte[] x, int xOffset, byte[] y, int yOffset, int length)
        {
            // Contract.Requires<ArgumentNullException>(x != null && y != null);
            if (x == null || y == null) throw new ArgumentNullException();
            // Contract.Requires<ArgumentOutOfRangeException>(xOffset >= 0 && yOffset >= 0 && length >= 0);
            if (xOffset < 0 || yOffset < 0 || length < 0) throw new ArgumentOutOfRangeException();
            // Contract.Requires<ArgumentException>(xOffset + length <= x.Length);
            if (xOffset + length > x.Length) throw new ArgumentException();
            // Contract.Requires<ArgumentException>(yOffset + length <= y.Length);
            if (yOffset + length > y.Length) throw new ArgumentException();

            return InternalConstantTimeEquals(x, xOffset, y, yOffset, length) != 0;
        }

        private static uint InternalConstantTimeEquals(byte[] x, int xOffset, byte[] y, int yOffset, int length)
        {
            int differentbits = 0;
            for (int i = 0; i < length; i++)
                differentbits |= x[xOffset + i] ^ y[yOffset + i];
            return (1 & (unchecked((uint)differentbits - 1) >> 8));
        }

        /// <summary>
        /// Overwrites the contents of the array, wiping the previous content.
        /// </summary>
        /// <param name="data">Byte array</param>
        public static void Wipe(byte[] data)
        {
            // Contract.Requires<ArgumentNullException>(data != null);
            if (data == null) throw new ArgumentNullException();
            InternalWipe(data, 0, data.Length);
        }

        /// <summary>
        /// Overwrites the contents of the array, wiping the previous content.
        /// </summary>
        /// <param name="data">Byte array</param>
        /// <param name="offset">Index of byte sequence</param>
        /// <param name="length">Length of byte sequence</param>
        public static void Wipe(byte[] data, int offset, int length)
        {
            // Contract.Requires<ArgumentNullException>(data != null);
            if (data == null) throw new ArgumentNullException();
            // Contract.Requires<ArgumentOutOfRangeException>(offset >= 0 && length >= 0);
            if (offset< 0 || length < 0) throw new ArgumentOutOfRangeException();
            // Contract.Requires<ArgumentException>(offset + length <= data.Length);
            if (offset + length > data.Length) throw new ArgumentException();

            InternalWipe(data, offset, length);
        }

        /// <summary>
        /// Overwrites the contents of the array segment, wiping the previous content.
        /// </summary>
        /// <param name="data">Byte array segment</param>
        public static void Wipe(ArraySegment<byte> data)
        {
            InternalWipe(data.Array, data.Offset, data.Count);
        }

        // Secure wiping is hard
        // * the GC can move around and copy memory
        //   Perhaps this can be avoided by using unmanaged memory or by fixing the position of the array in memory
        // * Swap files and error dumps can contain secret information
        //   It seems possible to lock memory in RAM, no idea about error dumps
        // * Compiler could optimize out the wiping if it knows that data won't be read back
        //   I hope this is enough, suppressing inlining
        //   but perhaps `RtlSecureZeroMemory` is needed
        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void InternalWipe(byte[] data, int offset, int count)
        {
            Array.Clear(data, offset, count);
        }

        // shallow wipe of structs
        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void InternalWipe<T>(ref T data)
            where T : struct
        {
            data = default(T);
        }

        /// <summary>
        /// Constant-time conversion of the bytes array to an upper-case hex string.
        /// Please see http://stackoverflow.com/a/14333437/445517 for the detailed explanation
        /// </summary>
        /// <param name="data">Byte array</param>
        /// <returns>Hex representation of byte array</returns>
        public static string ToHexStringUpper(byte[] data)
        {
            if (data == null)
                return null;
            char[] c = new char[data.Length * 2];
            int b;
            for (int i = 0; i < data.Length; i++)
            {
                b = data[i] >> 4;
                c[i * 2] = (char)(55 + b + (((b - 10) >> 31) & -7));
                b = data[i] & 0xF;
                c[i * 2 + 1] = (char)(55 + b + (((b - 10) >> 31) & -7));
            }
            return new string(c);
        }

        /// <summary>
        /// Constant-time conversion of the bytes array to an lower-case hex string.
        /// Please see http://stackoverflow.com/a/14333437/445517 for the detailed explanation.
        /// </summary>
        /// <param name="data">Byte array</param>
        /// <returns>Hex representation of byte array</returns>
        public static string ToHexStringLower(byte[] data)
        {
            if (data == null)
                return null;
            char[] c = new char[data.Length * 2];
            int b;
            for (int i = 0; i < data.Length; i++)
            {
                b = data[i] >> 4;
                c[i * 2] = (char)(87 + b + (((b - 10) >> 31) & -39));
                b = data[i] & 0xF;
                c[i * 2 + 1] = (char)(87 + b + (((b - 10) >> 31) & -39));
            }
            return new string(c);
        }

        /// <summary>
        /// Converts the hex string to bytes. Case insensitive.
        /// </summary>
        /// <param name="hexString">Hex encoded byte sequence</param>
        /// <returns>Byte array</returns>
        public static byte[] FromHexString(string hexString)
        {
            if (hexString == null)
                return null;
            if (hexString.Length % 2 != 0)
                throw new FormatException("The hex string is invalid because it has an odd length");
            var result = new byte[hexString.Length / 2];
            for (int i = 0; i < result.Length; i++)
                result[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            return result;
        }

        /// <summary>
        /// Encodes the bytes with the Base64 encoding.
        /// More compact than hex, but it is case-sensitive and uses the special characters `+`, `/` and `=`.
        /// </summary>
        /// <param name="data">Byte array</param>
        /// <returns>Base 64 encoded data</returns>
        public static string ToBase64String(byte[] data)
        {
            if (data == null)
                return null;
            return Convert.ToBase64String(data);
        }

        /// <summary>
        /// Decodes a Base64 encoded string back to bytes.
        /// </summary>
        /// <param name="base64String">Base 64 encoded data</param>
        /// <returns>Byte array</returns>
        public static byte[] FromBase64String(string base64String)
        {
            if (base64String == null)
                return null;
            return Convert.FromBase64String(base64String);
        }

        private const string strDigits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        /// <summary>
        /// Encode a byte sequence as a base58-encoded string
        /// </summary>
        /// <param name="input">Byte sequence</param>
        /// <returns>Encoding result</returns>
        public static string Base58Encode(byte[] input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));

            // Decode byte[] to BigInteger
            BigInteger intData = 0;
            for (int i = 0; i < input.Length; i++)
            {
                intData = intData * 256 + input[i];
            }

            // Encode BigInteger to Base58 string
            string result = "";
            while (intData > 0)
            {
                int remainder = (int)(intData % 58);
                intData /= 58;
                result = strDigits[remainder] + result;
            }

            // Append `1` for each leading 0 byte
            for (int i = 0; i < input.Length && input[i] == 0; i++)
            {
                result = '1' + result;
            }
            return result;
        }

        /// <summary>
        /// // Decode a base58-encoded string into byte array
        /// </summary>
        /// <param name="strBase58">Base58 data string</param>
        /// <returns>Byte array</returns>
        public static byte[] Base58Decode(string input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));

            // Decode Base58 string to BigInteger
            BigInteger intData = 0;
            for (int i = 0; i < input.Length; i++)
            {
                int digit = strDigits.IndexOf(input[i]); //Slow
                if (digit < 0)
                    throw new FormatException(string.Format("Invalid Base58 character `{0}` at position {1}", input[i], i));
                intData = intData * 58 + digit;
            }

            // Encode BigInteger to byte[]
            // Leading zero bytes get encoded as leading `1` characters
            int leadingZeroCount = input.TakeWhile(c => c == '1').Count();
            var leadingZeros = Enumerable.Repeat((byte)0, leadingZeroCount);
            var bytesWithoutLeadingZeros =
                intData.ToByteArray()
                .Reverse()// to big endian
                .SkipWhile(b => b == 0);//strip sign byte
            var result = leadingZeros.Concat(bytesWithoutLeadingZeros).ToArray();
            return result;
        }
    }
}
