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

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using NATS.NKeys.Internal;
using NATS.NKeys.NaCl;

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
#pragma warning disable SA1303
#pragma warning disable SA1307
#pragma warning disable SA1407
#pragma warning disable SA1413
#pragma warning disable SA1500
#pragma warning disable SA1512
#pragma warning disable SA1513
#pragma warning disable SA1515
#pragma warning disable SX1309

namespace NATS.NKeys
{
    /// <summary>
    /// Nkeys is a class provided to manipulate Nkeys and generate NkeyPairs.
    /// </summary>
    public static class NKeys
    {
        // PrefixByteSeed is the version byte used for encoded NATS Seeds
        public const byte PrefixByteSeed = 18 << 3; // Base32-encodes to 'S...'

        // PrefixBytePrivate is the version byte used for encoded NATS Private keys
        public const byte PrefixBytePrivate = 15 << 3; // Base32-encodes to 'P...'

        // PrefixByteServer is the version byte used for encoded NATS Servers
        public const byte PrefixByteServer = 13 << 3; // Base32-encodes to 'N...'

        // PrefixByteCluster is the version byte used for encoded NATS Clusters
        public const byte PrefixByteCluster = 2 << 3; // Base32-encodes to 'C...'

        // PrefixByteOperator is the version byte used for encoded NATS Operators
        public const byte PrefixByteOperator = 14 << 3; // Base32-encodes to 'O...'

        // PrefixByteAccount is the version byte used for encoded NATS Accounts
        public const byte PrefixByteAccount = 0; // Base32-encodes to 'A...'

        // PrefixByteUser is the version byte used for encoded NATS Users
        public const byte PrefixByteUser = 20 << 3; // Base32-encodes to 'U...'

        // PrefixByteUnknown is for unknown prefixes.
        public const byte PrefixByteUknown = 23 << 3; // Base32-encodes to 'X...'

        public enum PrefixType
        {
            User,
            Account,
            Server,
            Operator,
            Cluster,
            Private
        };

        /// <summary>
        /// Decodes a base 32 encoded NKey into a nkey seed and verifies the checksum.
        /// </summary>
        /// <param name="src">Base 32 encoded Nkey.</param>
        /// <returns></returns>
        public static byte[] Decode(string src)
        {
            var raw = Base32.Decode(src);
            var raw2 = Base32.FromBase32String(src);
            var crc = (ushort)(raw[raw.Length - 2] | raw[raw.Length - 1] << 8);

            // trim off the CRC16
            var len = raw.Length - 2;
            var data = new byte[len];
            Buffer.BlockCopy(raw, 0, data, 0, len);

            if (crc != Crc16.Checksum(data))
                throw new NKeysException("Invalid CRC");

            return data;
        }

        private static bool IsValidPublicPrefixByte(byte prefixByte)
        {
            switch (prefixByte)
            {
            case PrefixByteServer:
            case PrefixByteCluster:
            case PrefixByteOperator:
            case PrefixByteAccount:
            case PrefixByteUser:
                return true;
            }
            return false;
        }

        internal static PrefixType? TypeFromPrefix(byte prefixByte)
        {
            switch (prefixByte)
            {
            case PrefixByteServer:
                return PrefixType.Server;
            case PrefixByteCluster:
                return PrefixType.Cluster;
            case PrefixByteOperator:
                return PrefixType.Operator;
            case PrefixByteAccount:
                return PrefixType.Account;
            case PrefixByteUser:
                return PrefixType.User;
            }
            return null;
        }

        internal static byte PrefixFromType(PrefixType type)
        {
            switch (type)
            {
            case PrefixType.Server:
                return PrefixByteServer;
            case PrefixType.Cluster:
                return PrefixByteCluster;
            case PrefixType.Operator:
                return PrefixByteOperator;
            case PrefixType.Account:
                return PrefixByteAccount;
            case PrefixType.User:
                return PrefixByteUser;
            }
            return 0;
        }

        /// <summary>
        /// Wipes a byte array.
        /// </summary>
        /// <param name="src">byte array to wipe</param>
        public static void Wipe(ref byte[] src)
        {
            CryptoBytes.Wipe(src);
        }

        /// <summary>
        /// Wipes a string.
        /// </summary>
        /// <param name="src">string to wipe</param>
        public static void Wipe(string? src)
        {
            // best effort to wipe.
            if (src != null && src.Length > 0)
                src.Remove(0);
        }

        public static byte[] DecodeSeed(byte[] raw)
        {
            PrefixType ignored;
            return DecodeSeed(raw, out ignored);
        }

        public static byte[] DecodeSeed(byte[] raw, out PrefixType type)
        {
            // Need to do the reverse here to get back to internal representation.
            var b1 = (byte)(raw[0] & 248);  // 248 = 11111000
            var prefix = (byte)((raw[0] & 7) << 5 | ((raw[1] & 248) >> 3)); // 7 = 00000111

            try
            {
                if (b1 != PrefixByteSeed)
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
            finally
            {
                Wipe(ref raw);
            }
        }

        public static byte[] DecodeSeed(string src)
        {
            return DecodeSeed(NKeys.Decode(src));
        }

        public static byte[] DecodeSeed(string src, out PrefixType type)
        {
            return DecodeSeed(NKeys.Decode(src), out type);
        }

        public static NKeyPair FromPublicKey(char[] publicKey)
        {
            var pkStr = new string(publicKey);
            var raw = NKeys.Decode(pkStr);
            var prefix = (byte)(raw[0] & 0xFF);

            var tfp = TypeFromPrefix(prefix);
            if (!tfp.HasValue)
            {
                throw new NKeysException("Not a valid public NKey");
            }

            return new NKeyPair(Encoding.ASCII.GetBytes(pkStr), null, tfp.Value);
        }

        /// <summary>
        /// Creates an NkeyPair from a private seed string.
        /// </summary>
        /// <param name="seed"></param>
        /// <returns>A NATS Ed25519 Keypair</returns>
        public static NKeyPair FromSeed(string seed)
        {
            PrefixType type;
            var userSeed = DecodeSeed(seed, out type);
            try
            {
                var kp = new NKeyPair(userSeed, type);
                return kp;
            }
            finally
            {
                Wipe(ref userSeed);
            }
        }

        public static string Encode(byte prefixbyte, bool seed, byte[] src)
        {
            if (!IsValidPublicPrefixByte(prefixbyte))
                throw new NKeysException("Invalid prefix");

            if (src.Length != 32)
                throw new NKeysException("Invalid seed size");

            var stream = new MemoryStream();

            if (seed)
            {
                // In order to make this human printable for both bytes, we need to do a little
                // bit manipulation to setup for base32 encoding which takes 5 bits at a time.
                var b1 = (byte)(PrefixByteSeed | (prefixbyte >> 5));
                var b2 = (byte)((prefixbyte & 31) << 3); // 31 = 00011111

                stream.WriteByte(b1);
                stream.WriteByte(b2);
            }
            else
            {
                stream.WriteByte(prefixbyte);
            }

            // write payload
            stream.Write(src, 0, src.Length);

            // Calculate and write crc16 checksum
            var checksum = BitConverter.GetBytes(Crc16.Checksum(stream.ToArray()));
            stream.Write(checksum, 0, checksum.Length);

            return Base32.Encode(stream.ToArray());
        }

        private static string CreateSeed(byte prefixbyte)
        {
            var rawSeed = new byte[32];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(rawSeed);
            }

            return Encode(prefixbyte, true, rawSeed);
        }

        /// <summary>
        /// Creates a private user seed string.
        /// </summary>
        /// <returns>A NATS Ed25519 User Seed</returns>
        public static string CreateUserSeed()
        {
            return CreateSeed(PrefixByteUser);
        }

        /// <summary>
        /// Creates a private account seed string.
        /// </summary>
        /// <returns>A NATS Ed25519 Account Seed</returns>
        public static string CreateAccountSeed()
        {
            return CreateSeed(PrefixByteAccount);
        }

        /// <summary>
        /// Creates a private operator seed string.
        /// </summary>
        /// <returns>A NATS Ed25519 Operator Seed</returns>
        public static string CreateOperatorSeed()
        {
            return CreateSeed(PrefixByteOperator);
        }

        /// <summary>
        /// Returns a seed's public key.
        /// </summary>
        /// <param name="seed"></param>
        /// <returns>A the public key corresponding to Seed</returns>
        public static string PublicKeyFromSeed(string seed)
        {
            var s = NKeys.Decode(seed);
            if ((s[0] & (31 << 3)) != PrefixByteSeed)
            {
                throw new NKeysException("Not a seed");
            }
            // reconstruct prefix byte
            var prefixByte = (byte)((s[0] & 7) << 5 | ((s[1] >> 3) & 31));
            var pubKey = Ed25519.PublicKeyFromSeed(DecodeSeed(s));
            return Encode(prefixByte, false, pubKey);
        }
    }
}
