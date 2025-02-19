using System.Linq;
using System.Security.Cryptography;

namespace NATS.NKeys.NaCl.Tests
{
    public class Sha512Tests
    {
        private static readonly byte[] _sha512HashAbc = new byte[]
                {
                    0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA,
                    0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31,
                    0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2,
                    0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A,
                    0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8,
                    0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
                    0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
                    0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F,
                };

        [Fact]
        public void Sha512_1()
        {
            var sha512Framework = SHA512.Create();
            for (var n = 0; n < 1000; n++)
            {
                var message = Enumerable.Range(1, n).Select(i => (byte)i).ToArray();
                var hashExpected = sha512Framework.ComputeHash(message);
                var hash = Sha512.Hash(message);
                TestHelpers.AssertEqualBytes(hashExpected, hash);
            }
        }

        [Fact]
        public void Sha512_Split()
        {
            // use only a subset of possible indices to speed up the test
            var indices = Enumerable.Range(0, 300).Where(i => (i % 64) < 5 || (i % 64) > 64 - 5).ToArray();

            var sha512Framework = SHA512.Create();
            foreach (var k in indices)
            {
                foreach (var m in indices)
                {
                    foreach (var n in indices)
                    {
                        var message = Enumerable.Range(1, k + m + n).Select(i => (byte)i).ToArray();
                        var hashExpected = sha512Framework.ComputeHash(message);
                        var hasher = new Sha512();
                        hasher.Update(message, 0, k);
                        hasher.Update(message, k, m);
                        hasher.Update(message, k + m, n);
                        var hash = hasher.Finalize();
                        TestHelpers.AssertEqualBytes(hashExpected, hash);
                    }
                }
            }
        }

        [Fact]
        public void Sha512_Reuse()
        {
            var message = Enumerable.Range(1, 100).Select(i => (byte)i).ToArray();
            var sha512Framework = SHA512.Create();
            var hashExpected = sha512Framework.ComputeHash(message);

            var hasher = new Sha512();
            hasher.Update(message, 0, message.Length);
            var hash1 = hasher.Finalize();
            TestHelpers.AssertEqualBytes(hashExpected, hash1);

            hasher.Init();
            hasher.Update(message, 0, message.Length);
            var hash2 = hasher.Finalize();
            TestHelpers.AssertEqualBytes(hashExpected, hash2);
        }

        [Fact]
        public void Sha512Abc()
        {
            var message = new[] { (byte)'a', (byte)'b', (byte)'c' };
            var hashExpected = _sha512HashAbc;
            var hash = Sha512.Hash(message);
            TestHelpers.AssertEqualBytes(hashExpected, hash);
        }
    }
}
