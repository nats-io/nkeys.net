// // Copyright 2019 The NATS Authors
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// // http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.
//
// using System.Security.Cryptography;
// using System.Text;
// using NATS.NKeys.Internal;
// using NATS.NKeys.NaCl;
//
// #pragma warning disable CS1572
// #pragma warning disable CS1573
// #pragma warning disable CS8603
// #pragma warning disable CS8618
// #pragma warning disable CS8625
// #pragma warning disable SA1001
// #pragma warning disable SA1002
// #pragma warning disable SA1003
// #pragma warning disable SA1008
// #pragma warning disable SA1009
// #pragma warning disable SA1011
// #pragma warning disable SA1012
// #pragma warning disable SA1021
// #pragma warning disable SA1027
// #pragma warning disable SA1106
// #pragma warning disable SA1111
// #pragma warning disable SA1119
// #pragma warning disable SA1137
// #pragma warning disable SA1201
// #pragma warning disable SA1202
// #pragma warning disable SA1303
// #pragma warning disable SA1307
// #pragma warning disable SA1407
// #pragma warning disable SA1413
// #pragma warning disable SA1500
// #pragma warning disable SA1512
// #pragma warning disable SA1513
// #pragma warning disable SA1515
// #pragma warning disable SX1309
//
// namespace NATS.NKeys
// {
//     /// <summary>
//     /// NKeys is a class provided to manipulate NKeys and generate NKeyPairs.
//     /// </summary>
//     public static class NKeys
//     {
//         // PrefixByteSeed is the version byte used for encoded NATS Seeds
//         private const byte PrefixByteSeed = 18 << 3; // Base32-encodes to 'S...'
//
//         // PrefixBytePrivate is the version byte used for encoded NATS Private keys
//         private const byte PrefixBytePrivate = 15 << 3; // Base32-encodes to 'P...'
//
//         // PrefixByteServer is the version byte used for encoded NATS Servers
//         private const byte PrefixByteServer = 13 << 3; // Base32-encodes to 'N...'
//
//         // PrefixByteCluster is the version byte used for encoded NATS Clusters
//         private const byte PrefixByteCluster = 2 << 3; // Base32-encodes to 'C...'
//
//         // PrefixByteOperator is the version byte used for encoded NATS Operators
//         private const byte PrefixByteOperator = 14 << 3; // Base32-encodes to 'O...'
//
//         // PrefixByteAccount is the version byte used for encoded NATS Accounts
//         private const byte PrefixByteAccount = 0; // Base32-encodes to 'A...'
//
//         // PrefixByteUser is the version byte used for encoded NATS Users
//         private const byte PrefixByteUser = 20 << 3; // Base32-encodes to 'U...'
//
//         // PrefixByteUnknown is for unknown prefixes.
//         private const byte PrefixByteUnknown = 23 << 3; // Base32-encodes to 'X...'
//
//         public enum PrefixByte : byte
//         {
//             User = PrefixByteUser,
//             Account = PrefixByteAccount,
//             Server = PrefixByteServer,
//             Operator = PrefixByteOperator,
//             Cluster = PrefixByteCluster,
//             Private = PrefixBytePrivate,
//         };
//
//         /// <summary>
//         /// Decodes a base 32 encoded NKey into a nkey seed and verifies the checksum.
//         /// </summary>
//         /// <param name="src">Base 32 encoded NKey.</param>
//         /// <returns></returns>
//         public static byte[] Decode(string src)
//         {
//             var raw = Base32.Decode(src);
//             var crc = (ushort)(raw[raw.Length - 2] | raw[raw.Length - 1] << 8);
//
//             // trim off the CRC16
//             var len = raw.Length - 2;
//             var data = new byte[len];
//             Buffer.BlockCopy(raw, 0, data, 0, len);
//
//             if (crc != Crc16.Checksum(data))
//                 throw new NKeysException("Invalid CRC");
//
//             return data;
//         }
//
//         private static bool IsValidPublicPrefixByte(byte prefixByte)
//         {
//             switch (prefixByte)
//             {
//             case PrefixByteServer:
//             case PrefixByteCluster:
//             case PrefixByteOperator:
//             case PrefixByteAccount:
//             case PrefixByteUser:
//                 return true;
//             }
//             return false;
//         }
//
//         private static PrefixByte? TypeFromPrefix(byte prefixByte)
//         {
//             switch (prefixByte)
//             {
//             case PrefixByteServer:
//                 return PrefixByte.Server;
//             case PrefixByteCluster:
//                 return PrefixByte.Cluster;
//             case PrefixByteOperator:
//                 return PrefixByte.Operator;
//             case PrefixByteAccount:
//                 return PrefixByte.Account;
//             case PrefixByteUser:
//                 return PrefixByte.User;
//             }
//             return null;
//         }
//
//         internal static byte PrefixFromType(PrefixByte type)
//         {
//             switch (type)
//             {
//             case PrefixByte.Server:
//                 return PrefixByteServer;
//             case PrefixByte.Cluster:
//                 return PrefixByteCluster;
//             case PrefixByte.Operator:
//                 return PrefixByteOperator;
//             case PrefixByte.Account:
//                 return PrefixByteAccount;
//             case PrefixByte.User:
//                 return PrefixByteUser;
//             }
//             return 0;
//         }
//
//         internal static void Wipe(ref byte[] src) => CryptoBytes.Wipe(src);
//
//         public static byte[] DecodeSeed(byte[] raw, out PrefixByte type)
//         {
//             // Need to do the reverse here to get back to internal representation.
//             var b1 = (byte)(raw[0] & 248);  // 248 = 11111000
//             var prefix = (byte)((raw[0] & 7) << 5 | ((raw[1] & 248) >> 3)); // 7 = 00000111
//
//             try
//             {
//                 if (b1 != PrefixByteSeed)
//                     throw new NKeysException("Invalid Seed.");
//
//                 var tfp = TypeFromPrefix(prefix);
//                 if (!tfp.HasValue)
//                 {
//                     throw new NKeysException("Invalid Public Prefix Byte.");
//                 }
//                 type = tfp.Value;
//
//                 // Trim off the first two bytes
//                 var data = new byte[raw.Length - 2];
//                 Buffer.BlockCopy(raw, 2, data, 0, data.Length);
//                 return data;
//             }
//             finally
//             {
//                 Wipe(ref raw);
//             }
//         }
//
//         public static NKeyPair FromPublicKey(char[] publicKey)
//         {
//             var pkStr = new string(publicKey);
//             var raw = NKeys.Decode(pkStr);
//             var prefix = (byte)(raw[0] & 0xFF);
//
//             var tfp = TypeFromPrefix(prefix);
//             if (!tfp.HasValue)
//             {
//                 throw new NKeysException("Not a valid public NKey");
//             }
//
//             return new NKeyPair(Encoding.ASCII.GetBytes(pkStr), null, tfp.Value);
//         }
//
//         /// <summary>
//         /// Creates an NkeyPair from a private seed string.
//         /// </summary>
//         /// <param name="seed"></param>
//         /// <returns>A NATS Ed25519 Keypair</returns>
//         public static NKeyPair FromSeed(string seed)
//         {
//             var userSeed = DecodeSeed(Decode(seed), out var type);
//             try
//             {
//                 var kp = new NKeyPair(userSeed, type);
//                 return kp;
//             }
//             finally
//             {
//                 Wipe(ref userSeed);
//             }
//         }
//
//         public static string Encode(PrefixByte prefix, bool seed, byte[] src)
//         {
//             var prefixByte = (byte)prefix;
//
//             if (!IsValidPublicPrefixByte(prefixByte))
//                 throw new NKeysException("Invalid prefix");
//
//             if (src.Length != 32)
//                 throw new NKeysException("Invalid seed size");
//
//             var stream = new MemoryStream();
//
//             if (seed)
//             {
//                 // To make this human printable for both bytes, we need to do a little
//                 // bit manipulation to set up for base32 encoding which takes 5 bits at a time.
//                 var b1 = (byte)(PrefixByteSeed | (prefixByte >> 5));
//                 var b2 = (byte)((prefixByte & 31) << 3); // 31 = 00011111
//
//                 stream.WriteByte(b1);
//                 stream.WriteByte(b2);
//             }
//             else
//             {
//                 stream.WriteByte(prefixByte);
//             }
//
//             // write payload
//             stream.Write(src, 0, src.Length);
//
//             // Calculate and write crc16 checksum
//             var checksum = BitConverter.GetBytes(Crc16.Checksum(stream.ToArray()));
//             stream.Write(checksum, 0, checksum.Length);
//
//             return Base32.Encode(stream.ToArray());
//         }
//
//         public static string CreateSeed(PrefixByte prefix)
//         {
//             var rawSeed = new byte[32];
//
//             using (var rng = RandomNumberGenerator.Create())
//             {
//                 rng.GetBytes(rawSeed);
//             }
//
//             return Encode(prefix, true, rawSeed);
//         }
//
//         // /// <summary>
//         // /// Creates a private user seed string.
//         // /// </summary>
//         // /// <returns>A NATS Ed25519 User Seed</returns>
//         // public static string CreateUserSeed()
//         // {
//         //     return CreateSeed(PrefixByteUser);
//         // }
//
//         // /// <summary>
//         // /// Creates a private account seed string.
//         // /// </summary>
//         // /// <returns>A NATS Ed25519 Account Seed</returns>
//         // public static string CreateAccountSeed()
//         // {
//         //     return CreateSeed(PrefixByteAccount);
//         // }
//
//         // /// <summary>
//         // /// Creates a private operator seed string.
//         // /// </summary>
//         // /// <returns>A NATS Ed25519 Operator Seed</returns>
//         // public static string CreateOperatorSeed()
//         // {
//         //     return CreateSeed(PrefixByteOperator);
//         // }
//
//         /// <summary>
//         /// Returns a seed's public key.
//         /// </summary>
//         /// <param name="seed"></param>
//         /// <returns>A public key corresponding to Seed</returns>
//         public static string PublicKeyFromSeed(string seed)
//         {
//             var s = NKeys.Decode(seed);
//             if ((s[0] & (31 << 3)) != PrefixByteSeed)
//             {
//                 throw new NKeysException("Not a seed");
//             }
//             // reconstruct prefix byte
//             var prefixByte = (byte)((s[0] & 7) << 5 | ((s[1] >> 3) & 31));
//             var pubKey = Ed25519.PublicKeyFromSeed(DecodeSeed(s, out _));
//             return Encode((PrefixByte)prefixByte, false, pubKey);
//         }
//     }
// }
