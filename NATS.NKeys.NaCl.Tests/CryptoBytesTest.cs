using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Chaos.NaCl.Tests;
#pragma warning disable CS8604 // Possible null reference argument.
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.

namespace NATS.NKeys.NaCl.Tests
{
    [SuppressMessage("StyleCop.CSharp.OrderingRules", "SA1203:Constants should appear before fields", Justification = "Legacy code")]
    public class CryptoBytesTest
    {
        private readonly byte[] _bytes = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

        private const string HexStringUpper =
            "000102030405060708090A0B0C0D0E0F" +
            "101112131415161718191A1B1C1D1E1F" +
            "202122232425262728292A2B2C2D2E2F" +
            "303132333435363738393A3B3C3D3E3F" +
            "404142434445464748494A4B4C4D4E4F" +
            "505152535455565758595A5B5C5D5E5F" +
            "606162636465666768696A6B6C6D6E6F" +
            "707172737475767778797A7B7C7D7E7F" +
            "808182838485868788898A8B8C8D8E8F" +
            "909192939495969798999A9B9C9D9E9F" +
            "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF" +
            "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF" +
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF" +
            "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF" +
            "E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF" +
            "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";

        private const string HexStringLower =
            "000102030405060708090a0b0c0d0e0f" +
            "101112131415161718191a1b1c1d1e1f" +
            "202122232425262728292a2b2c2d2e2f" +
            "303132333435363738393a3b3c3d3e3f" +
            "404142434445464748494a4b4c4d4e4f" +
            "505152535455565758595a5b5c5d5e5f" +
            "606162636465666768696a6b6c6d6e6f" +
            "707172737475767778797a7b7c7d7e7f" +
            "808182838485868788898a8b8c8d8e8f" +
            "909192939495969798999a9b9c9d9e9f" +
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" +
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
            "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

        private const string Base64String =
            "AAECAwQFBgcICQoL" +
            "DA0ODxAREhMUFRYX" +
            "GBkaGxwdHh8gISIj" +
            "JCUmJygpKissLS4v" +
            "MDEyMzQ1Njc4OTo7" +
            "PD0+P0BBQkNERUZH" +
            "SElKS0xNTk9QUVJT" +
            "VFVWV1hZWltcXV5f" +
            "YGFiY2RlZmdoaWpr" +
            "bG1ub3BxcnN0dXZ3" +
            "eHl6e3x9fn+AgYKD" +
            "hIWGh4iJiouMjY6P" +
            "kJGSk5SVlpeYmZqb" +
            "nJ2en6ChoqOkpaan" +
            "qKmqq6ytrq+wsbKz" +
            "tLW2t7i5uru8vb6/" +
            "wMHCw8TFxsfIycrL" +
            "zM3Oz9DR0tPU1dbX" +
            "2Nna29zd3t/g4eLj" +
            "5OXm5+jp6uvs7e7v" +
            "8PHy8/T19vf4+fr7" +
            "/P3+/w==";

        // Test cases from https://github.com/bitcoin/bitcoin/blob/master/src/test/base58_tests.cpp
        private readonly Tuple<string, byte[]>[] _testCases =
        [
            Tuple.Create(string.Empty, new byte[] { }),
            Tuple.Create("1112", new byte[] { 0x00, 0x00, 0x00, 0x01 }),
            Tuple.Create("2g", new byte[] { 0x61 }),
            Tuple.Create("a3gV", new byte[] { 0x62, 0x62, 0x62 }),
            Tuple.Create("aPEr", new byte[] { 0x63, 0x63, 0x63 }),
            Tuple.Create("2cFupjhnEsSn59qHXstmK2ffpLv2", new byte[] { 0x73, 0x69, 0x6d, 0x70, 0x6c, 0x79, 0x20, 0x61, 0x20, 0x6c, 0x6f, 0x6e, 0x67, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67 }),
            Tuple.Create("1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L", new byte[] { 0x00, 0xeb, 0x15, 0x23, 0x1d, 0xfc, 0xeb, 0x60, 0x92, 0x58, 0x86, 0xb6, 0x7d, 0x06, 0x52, 0x99, 0x92, 0x59, 0x15, 0xae, 0xb1, 0x72, 0xc0, 0x66, 0x47 }),
            Tuple.Create("ABnLTmg", new byte[] { 0x51, 0x6b, 0x6f, 0xcd, 0x0f }),
            Tuple.Create("3SEo3LWLoPntC", new byte[] { 0xbf, 0x4f, 0x89, 0x00, 0x1e, 0x67, 0x02, 0x74, 0xdd }),
            Tuple.Create("3EFU7m", new byte[] { 0x57, 0x2e, 0x47, 0x94 }),
            Tuple.Create("EJDM8drfXA6uyA", new byte[] { 0xec, 0xac, 0x89, 0xca, 0xd9, 0x39, 0x23, 0xc0, 0x23, 0x21 }),
            Tuple.Create("Rt5zm", new byte[] { 0x10, 0xc8, 0x51, 0x1e }),
            Tuple.Create("1111111111", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
        ];

        [Fact]
        public void ToHexStringUpper()
        {
            Assert.Equal(HexStringUpper, CryptoBytes.ToHexStringUpper(_bytes));
        }

        [Fact]
        public void ToHexStringLower()
        {
            Assert.Equal(HexStringLower, CryptoBytes.ToHexStringLower(_bytes));
        }

        [Fact]
        public void ToHexStringLowerNull()
        {
            Assert.Null(CryptoBytes.ToHexStringLower(null));
        }

        [Fact]
        public void ToHexStringUpperNull()
        {
            Assert.Null(CryptoBytes.ToHexStringUpper(null));
        }

        [Fact]
        public void FromHexStringUpperCase()
        {
            Assert.True(_bytes.SequenceEqual(CryptoBytes.FromHexString(HexStringUpper)));
        }

        [Fact]
        public void FromHexStringLowerCase()
        {
            Assert.True(_bytes.SequenceEqual(CryptoBytes.FromHexString(HexStringLower)));
        }

        [Fact]
        public void FromHexStringNull()
        {
            Assert.Null(CryptoBytes.FromHexString(null));
        }

        [Fact]
        public void FromHexStringWithOddLengthFails()
        {
            Assert.Throws<FormatException>(() =>
            {
                CryptoBytes.FromHexString("A");
            });
        }

        [Fact]
        public void FromHexStringWithInvalidCharactersFails()
        {
            Assert.Throws<FormatException>(() =>
            {
                CryptoBytes.FromHexString("AQ");
            });
        }

        [Fact]
        public void ToBase64String()
        {
            Assert.Equal(Base64String, CryptoBytes.ToBase64String(_bytes));
        }

        [Fact]
        public void FromBase64String()
        {
            Assert.True(_bytes.SequenceEqual(CryptoBytes.FromBase64String(Base64String)));
        }

        [Fact]
        public void ToBase64StringNull()
        {
            Assert.Null(CryptoBytes.ToBase64String(null));
        }

        [Fact]
        public void FromBase64StringNull()
        {
            Assert.Null(CryptoBytes.FromBase64String(null));
        }

        [Fact]
        public void Base58Encode()
        {
            foreach (var tuple in _testCases)
            {
                var bytes = tuple.Item2;
                var expectedText = tuple.Item1;
                var actualText = CryptoBytes.Base58Encode(bytes);
                Assert.Equal(expectedText, actualText);
            }
        }

        [Fact]
        public void Base58Decode()
        {
            foreach (var tuple in _testCases)
            {
                var text = tuple.Item1;
                var expectedBytes = tuple.Item2;
                var actualBytes = CryptoBytes.Base58Decode(text);
                Assert.Equal(BitConverter.ToString(expectedBytes), BitConverter.ToString(actualBytes));
            }
        }

        [Fact]
        public void DecodeInvalidChar()
        {
            Assert.Throws<FormatException>(() =>
            {
                CryptoBytes.Base58Decode("ab0");
            });
        }

        [Fact]
        public void Wipe()
        {
            var bytes = (byte[])_bytes.Clone();
            CryptoBytes.Wipe(bytes);
            Assert.True(bytes.All(b => b == 0));
        }

        [Fact]
        public void WipeInterval()
        {
            var bytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            var wipedBytes = new byte[] { 1, 2, 0, 0, 0, 0, 0, 8, 9, 10 };
            CryptoBytes.Wipe(bytes, 2, 5);
            TestHelpers.AssertEqualBytes(wipedBytes, bytes);
        }

        [Fact]
        public void WipeSegment()
        {
            var bytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            var wipedBytes = new byte[] { 1, 2, 0, 0, 0, 0, 0, 8, 9, 10 };
            CryptoBytes.Wipe(new ArraySegment<byte>(bytes, 2, 5));
            TestHelpers.AssertEqualBytes(wipedBytes, bytes);
        }

        [Fact]
        public void ConstantTimeEqualsSuccess()
        {
            var x = new byte[] { 1, 2, 3 };
            var y = new byte[] { 1, 2, 3 };
            Assert.True(CryptoBytes.ConstantTimeEquals(x, y));
        }

        [Fact]
        public void ConstantTimeEqualsFail()
        {
            var x = new byte[] { 1, 2, 3 };
            foreach (var y in x.WithChangedBit())
            {
                Assert.False(CryptoBytes.ConstantTimeEquals(x, y));
            }
        }

        [Fact]
        public void ConstantTimeEqualsSegmentsSuccess()
        {
            var x = new byte[] { 1, 2, 3 };
            var y = new byte[] { 1, 2, 3 };
            Assert.True(CryptoBytes.ConstantTimeEquals(x.Pad(), y.Pad()));
        }

        [Fact]
        public void ConstantTimeEqualsSegmentsFail()
        {
            var x = new byte[] { 1, 2, 3 };
            foreach (var y in x.WithChangedBit())
            {
                Assert.False(CryptoBytes.ConstantTimeEquals(x.Pad(), y.Pad()));
            }
        }

        [Fact]
        public void ConstantTimeEqualsRangeSuccess()
        {
            var x = new byte[] { 1, 2, 3 };
            var y = new byte[] { 1, 2, 3 };
            var paddedX = x.Pad();
            var paddedY = y.Pad();
            Assert.True(CryptoBytes.ConstantTimeEquals(paddedX.Array, paddedX.Offset, paddedY.Array, paddedY.Offset, paddedX.Count));
        }

        [Fact]
        public void ConstantTimeEqualsRangeFail()
        {
            var x = new byte[] { 1, 2, 3 };
            foreach (var y in x.WithChangedBit())
            {
                var paddedX = x.Pad();
                var paddedY = y.Pad();
                Assert.False(CryptoBytes.ConstantTimeEquals(paddedX.Array, paddedX.Offset, paddedY.Array, paddedY.Offset, paddedX.Count));
            }
        }

        [Fact]
        public void ConstantTimeEqualsXMustNotBeNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                CryptoBytes.ConstantTimeEquals(null, new byte[1]);
            });
        }

        [Fact]
        public void ConstantTimeEqualsYMustNotBeNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                CryptoBytes.ConstantTimeEquals(new byte[1], null);
            });
        }

        [Fact]
        public void ConstantTimeEqualsXAndYMustHaveSameLength()
        {
            Assert.False(CryptoBytes.ConstantTimeEquals(new byte[1], new byte[2]));
        }

        [Fact]
        public void ConstantTimeEqualsSegmentsMustHaveSameLength()
        {
            var x = new byte[5];
            var y = new byte[5];
            Assert.False(CryptoBytes.ConstantTimeEquals(new ArraySegment<byte>(x, 0, 4), new ArraySegment<byte>(y, 0, 5)));
        }

        [Fact]
        public void ConstantTimeEqualsSegmentsXMustNotBeNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                CryptoBytes.ConstantTimeEquals(default(ArraySegment<byte>), new ArraySegment<byte>(new byte[1]));
            });
        }

        [Fact]
        public void ConstantTimeEqualsSegmentsYMustNotBeNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                CryptoBytes.ConstantTimeEquals(new ArraySegment<byte>(new byte[1]), default(ArraySegment<byte>));
            });
        }

        [Fact]
        public void WipeNullFails()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                CryptoBytes.Wipe(null);
            });
        }

        [Fact]
        public void ConstantTimeEqualsRangeXmustNotBeNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                CryptoBytes.ConstantTimeEquals(null, 0, new byte[10], 0, 1);
            });
        }

        [Fact]
        public void ConstantTimeEqualsRangeYmustNotBeNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                CryptoBytes.ConstantTimeEquals(new byte[10], 0, null, 0, 1);
            });
        }

        [Fact]
        public void ConstantTimeEqualsRangeXoffsetMustNotBeNegative()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                CryptoBytes.ConstantTimeEquals(new byte[10], -1, new byte[10], 0, 1);
            });
        }

        [Fact]
        public void ConstantTimeEqualsRangeYoffsetMustNotBeNegative()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                CryptoBytes.ConstantTimeEquals(new byte[10], 0, new byte[10], -1, 1);
            });
        }

        [Fact]
        public void ConstantTimeEqualsRangeLengthMustNotBeNegative()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                CryptoBytes.ConstantTimeEquals(new byte[10], 0, new byte[10], 0, -1);
            });
        }

        [Fact]
        public void ConstantTimeEqualsRangeLengthTooBigX()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                CryptoBytes.ConstantTimeEquals(new byte[10], 8, new byte[10], 1, 7);
            });
        }

        [Fact]
        public void ConstantTimeEqualsRangeLengthTooBigY()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                CryptoBytes.ConstantTimeEquals(new byte[10], 1, new byte[10], 8, 7);
            });
        }

        [Fact]
        public void WipeSegmentNullFails()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                CryptoBytes.Wipe(default(ArraySegment<byte>));
            });
        }

        [Fact]
        public void WipeRangeNullFails()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                CryptoBytes.Wipe(null, 0, 0);
            });
        }

        [Fact]
        public void WipeRangeNegativeOffsetFails()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                CryptoBytes.Wipe(new byte[10], -1, 0);
            });
        }

        [Fact]
        public void WipeRangeNegativeLengthFails()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                CryptoBytes.Wipe(new byte[10], 0, -1);
            });
        }

        [Fact]
        public void WipeRangeTooLargeLengthFails()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                CryptoBytes.Wipe(new byte[10], 8, 8);
            });
        }
    }
}
