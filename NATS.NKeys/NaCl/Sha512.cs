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

#pragma warning disable CS0465
#pragma warning disable CS1572
#pragma warning disable CS1573
#pragma warning disable CS8603
#pragma warning disable CS8618
#pragma warning disable CS8625
#pragma warning disable SA1001
#pragma warning disable SA1002
#pragma warning disable SA1003
#pragma warning disable SA1008
#pragma warning disable SA1009
#pragma warning disable SA1011
#pragma warning disable SA1012
#pragma warning disable SA1021
#pragma warning disable SA1027
#pragma warning disable SA1106
#pragma warning disable SA1111
#pragma warning disable SA1119
#pragma warning disable SA1137
#pragma warning disable SA1201
#pragma warning disable SA1202
#pragma warning disable SA1204
#pragma warning disable SA1303
#pragma warning disable SA1307
#pragma warning disable SA1407
#pragma warning disable SA1413
#pragma warning disable SA1500
#pragma warning disable SA1505
#pragma warning disable SA1508
#pragma warning disable SA1512
#pragma warning disable SA1513
#pragma warning disable SA1515
#pragma warning disable SX1309

using System;
using System.Security.Cryptography;

namespace NATS.NKeys.NaCl
{
    internal sealed class Sha512 : IDisposable
    {
        /// <summary>
        /// Allocation and initialization of the new SHA-512 object.
        /// </summary>
        public Sha512()
        {
            _sha512Inner = SHA512.Create();
        }

        private readonly SHA512 _sha512Inner;

        /// <summary>
        /// Performs an initialization of internal SHA-512 state.
        /// </summary>
        public void Init()
        {
            _sha512Inner.Initialize();
        }

        /// <summary>
        /// Updates internal state with data from the provided array.
        /// </summary>
        /// <param name="data">Array of bytes</param>
        /// <param name="index">Offset of byte sequence</param>
        /// <param name="length">Sequence length</param>
        public void Update(byte[] data, int index, int length)
        {
            _sha512Inner.TransformBlock(data, index, length, null, 0);
        }

        /// <summary>
        /// Finalizes SHA-512 hashing.
        /// </summary>
        /// <returns>Hash bytes</returns>
        public byte[] Finalize()
        {
            _ = _sha512Inner.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return _sha512Inner.Hash!;
        }

        /// <summary>
        /// Calculates SHA-512 hash value for the given bytes array.
        /// </summary>
        /// <param name="data">Data bytes array</param>
        /// <param name="index">Offset of byte sequence</param>
        /// <param name="length">Sequence length</param>
        /// <returns>Hash bytes</returns>
        public static byte[] Hash(byte[] data, int index, int length)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            using var sha512 = SHA512.Create();
            return sha512.ComputeHash(data, index, length);
        }

        public static byte[] Hash(byte[] data) => Hash(data, 0, data.Length);

        /// <inheritdoc/>
        public void Dispose() => _sha512Inner?.Dispose();
    }
}
