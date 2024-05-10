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

// Borrowed from https://github.com/CryptoManiac/Ed25519

using System;
using Ed25519Operations = NATS.NKeys.NaCl.Internal.Ed25519Ref10.Ed25519Operations;

namespace NATS.NKeys.NaCl
{
    internal static class Ed25519
    {
        /// <summary>
        /// Public Keys are 32 byte values. All possible values of this size a valid.
        /// </summary>
        public const int PublicKeySize = 32;
        /// <summary>
        /// Signatures are 64 byte values
        /// </summary>
        public const int SignatureSize = 64;
        /// <summary>
        /// Private key seeds are 32 byte arbitrary values. This is the form that should be generated and stored.
        /// </summary>
        public const int PrivateKeySeedSize = 32;
        /// <summary>
        /// A 64 byte expanded form of private key. This form is used internally to improve performance
        /// </summary>
        public const int ExpandedPrivateKeySize = 32 * 2;

        /// <summary>
        /// Verify Ed25519 signature
        /// </summary>
        /// <param name="signature">Signature bytes</param>
        /// <param name="message">Message</param>
        /// <param name="publicKey">Public key</param>
        /// <returns>True if signature is valid, false if it's not</returns>
        public static bool Verify(ArraySegment<byte> signature, ArraySegment<byte> message, ArraySegment<byte> publicKey)
        {
            // Contract.Requires<ArgumentException>(signature.Count == SignatureSize && publicKey.Count == PublicKeySize);
            if (signature.Count != SignatureSize || publicKey.Count != PublicKeySize) throw new ArgumentException();

            return Ed25519Operations.crypto_sign_verify(signature.Array, signature.Offset, message.Array, message.Offset, message.Count, publicKey.Array, publicKey.Offset);
        }

        /// <summary>
        /// Verify Ed25519 signature
        /// </summary>
        /// <param name="signature">Signature bytes</param>
        /// <param name="message">Message</param>
        /// <param name="publicKey">Public key</param>
        /// <returns>True if signature is valid, false if it's not</returns>
        public static bool Verify(byte[] signature, byte[] message, byte[] publicKey)
        {
            // Contract.Requires<ArgumentNullException>(signature != null && message != null && publicKey != null);
            if (signature == null || message == null || publicKey == null) throw new ArgumentException();
            // Contract.Requires<ArgumentException>(signature.Length == SignatureSize && publicKey.Length == PublicKeySize);
            if (signature.Length != SignatureSize || publicKey.Length != PublicKeySize) throw new ArgumentException();

            return Ed25519Operations.crypto_sign_verify(signature, 0, message, 0, message.Length, publicKey, 0);
        }

        /// <summary>
        /// Create new Ed25519 signature
        /// </summary>
        /// <param name="signature">Buffer for signature</param>
        /// <param name="message">Message bytes</param>
        /// <param name="expandedPrivateKey">Expanded form of private key</param>
        public static void Sign(ArraySegment<byte> signature, ArraySegment<byte> message, ArraySegment<byte> expandedPrivateKey)
        {
            // Contract.Requires<ArgumentNullException>(signature.Array != null && message.Array != null && expandedPrivateKey.Array != null);
            if (signature.Array == null || message.Array == null || expandedPrivateKey.Array == null) throw new ArgumentNullException();
            // Contract.Requires<ArgumentException>(expandedPrivateKey.Count == ExpandedPrivateKeySize);
            if (expandedPrivateKey.Count != ExpandedPrivateKeySize) throw new ArgumentException();

            Ed25519Operations.crypto_sign(signature.Array, signature.Offset, message.Array, message.Offset, message.Count, expandedPrivateKey.Array, expandedPrivateKey.Offset);
        }

        /// <summary>
        /// Create new Ed25519 signature
        /// </summary>
        /// <param name="message">Message bytes</param>
        /// <param name="expandedPrivateKey">Expanded form of private key</param>
        public static byte[] Sign(byte[] message, byte[] expandedPrivateKey)
        {
            // Contract.Requires<ArgumentNullException>(message != null && expandedPrivateKey != null);
            if (message == null || expandedPrivateKey == null) throw new ArgumentNullException();
            // Contract.Requires<ArgumentException>(expandedPrivateKey.Length == ExpandedPrivateKeySize);
            if (expandedPrivateKey.Length != ExpandedPrivateKeySize) throw new ArgumentException();

            var signature = new byte[SignatureSize];
            Sign(new ArraySegment<byte>(signature), new ArraySegment<byte>(message), new ArraySegment<byte>(expandedPrivateKey));
            return signature;
        }

        /// <summary>
        /// Calculate public key from private key seed
        /// </summary>
        /// <param name="privateKeySeed">Private key seed value</param>
        /// <returns></returns>
        public static byte[] PublicKeyFromSeed(byte[] privateKeySeed)
        {
            // Contract.Requires<ArgumentNullException>(privateKeySeed != null);
            if (privateKeySeed == null) throw new ArgumentNullException();
            // Contract.Requires<ArgumentException>(privateKeySeed.Length == PrivateKeySeedSize);
            if (privateKeySeed.Length != PrivateKeySeedSize) throw new ArgumentException();

            byte[] privateKey;
            byte[] publicKey;
            KeyPairFromSeed(out publicKey, out privateKey, privateKeySeed);
            CryptoBytes.Wipe(privateKey);
            return publicKey;
        }

        /// <summary>
        /// Calculate expanded form of private key from the key seed.
        /// </summary>
        /// <param name="privateKeySeed">Private key seed value</param>
        /// <returns>Expanded form of the private key</returns>
        public static byte[] ExpandedPrivateKeyFromSeed(byte[] privateKeySeed)
        {
            // Contract.Requires<ArgumentNullException>(privateKeySeed != null);
            if (privateKeySeed == null) throw new ArgumentNullException();
            // Contract.Requires<ArgumentException>(privateKeySeed.Length == PrivateKeySeedSize);
            if (privateKeySeed.Length != PrivateKeySeedSize) throw new ArgumentException();

            byte[] privateKey;
            byte[] publicKey;
            KeyPairFromSeed(out publicKey, out privateKey, privateKeySeed);
            CryptoBytes.Wipe(publicKey);
            return privateKey;
        }

        /// <summary>
        /// Calculate key pair from the key seed.
        /// </summary>
        /// <param name="publicKey">Public key</param>
        /// <param name="expandedPrivateKey">Expanded form of the private key</param>
        /// <param name="privateKeySeed">Private key seed value</param>
        public static void KeyPairFromSeed(out byte[] publicKey, out byte[] expandedPrivateKey, byte[] privateKeySeed)
        {
            // Contract.Requires<ArgumentNullException>(privateKeySeed != null);
            if (privateKeySeed == null) throw new ArgumentNullException();
            // Contract.Requires<ArgumentException>(privateKeySeed.Length == PrivateKeySeedSize);
            if (privateKeySeed.Length != PrivateKeySeedSize) throw new ArgumentException();

            var pk = new byte[PublicKeySize];
            var sk = new byte[ExpandedPrivateKeySize];

            Ed25519Operations.crypto_sign_keypair(pk, 0, sk, 0, privateKeySeed, 0);
            publicKey = pk;
            expandedPrivateKey = sk;
        }

        /// <summary>
        /// Calculate key pair from the key seed.
        /// </summary>
        /// <param name="publicKey">Public key</param>
        /// <param name="expandedPrivateKey">Expanded form of the private key</param>
        /// <param name="privateKeySeed">Private key seed value</param>
        public static void KeyPairFromSeed(ArraySegment<byte> publicKey, ArraySegment<byte> expandedPrivateKey, ArraySegment<byte> privateKeySeed)
        {
            // Contract.Requires<ArgumentNullException>(publicKey.Array != null && expandedPrivateKey.Array != null && privateKeySeed.Array != null);
            if (publicKey.Array == null || expandedPrivateKey.Array == null || privateKeySeed.Array == null) throw new ArgumentNullException();
            // Contract.Requires<ArgumentException>(expandedPrivateKey.Count == ExpandedPrivateKeySize && privateKeySeed.Count == PrivateKeySeedSize);
            if (expandedPrivateKey.Count != ExpandedPrivateKeySize || privateKeySeed.Count != PrivateKeySeedSize) throw new ArgumentException();
            // Contract.Requires<ArgumentException>(publicKey.Count == PublicKeySize);
            if (publicKey.Count != PublicKeySize) throw new ArgumentException();

                Ed25519Operations.crypto_sign_keypair(
                publicKey.Array, publicKey.Offset,
                expandedPrivateKey.Array, expandedPrivateKey.Offset,
                privateKeySeed.Array, privateKeySeed.Offset);
        }
    }
}
