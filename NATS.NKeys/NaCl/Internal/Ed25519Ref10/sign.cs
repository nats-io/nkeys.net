#pragma warning disable CS0465
#pragma warning disable CS1572
#pragma warning disable CS1573
#pragma warning disable CS8603
#pragma warning disable CS8604
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
#pragma warning disable SA1025
#pragma warning disable SA1027
#pragma warning disable SA1106
#pragma warning disable SA1107
#pragma warning disable SA1111
#pragma warning disable SA1117
#pragma warning disable SA1119
#pragma warning disable SA1122
#pragma warning disable SA1132
#pragma warning disable SA1137
#pragma warning disable SA1201
#pragma warning disable SA1202
#pragma warning disable SA1204
#pragma warning disable SA1206
#pragma warning disable SA1300
#pragma warning disable SA1303
#pragma warning disable SA1307
#pragma warning disable SA1312
#pragma warning disable SA1313
#pragma warning disable SA1400
#pragma warning disable SA1401
#pragma warning disable SA1407
#pragma warning disable SA1413
#pragma warning disable SA1500
#pragma warning disable SA1501
#pragma warning disable SA1505
#pragma warning disable SA1507
#pragma warning disable SA1508
#pragma warning disable SA1512
#pragma warning disable SA1513
#pragma warning disable SA1514
#pragma warning disable SA1515
#pragma warning disable SA1520
#pragma warning disable SX1309

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

namespace NATS.NKeys.NaCl.Internal.Ed25519Ref10
{
    internal static partial class Ed25519Operations
    {
        public static void crypto_sign(
            byte[] sig, int sigoffset,
            byte[] m, int moffset, int mlen,
            byte[] sk, int skoffset)
        {
            byte[] az, r, hram;
            GroupElementP3 R;
            var hasher = new Sha512();
            {
                hasher.Update(sk, skoffset, 32);
                az = hasher.Finalize();
                NATS.NKeys.NaCl.Internal.Ed25519Ref10.ScalarOperations.sc_clamp(az, 0);

                hasher.Init();
                hasher.Update(az, 32, 32);
                hasher.Update(m, moffset, mlen);
                r = hasher.Finalize();

                NATS.NKeys.NaCl.Internal.Ed25519Ref10.ScalarOperations.sc_reduce(r);
                NATS.NKeys.NaCl.Internal.Ed25519Ref10.GroupOperations.ge_scalarmult_base(out R, r, 0);
                NATS.NKeys.NaCl.Internal.Ed25519Ref10.GroupOperations.ge_p3_tobytes(sig, sigoffset, ref R);

                hasher.Init();
                hasher.Update(sig, sigoffset, 32);
                hasher.Update(sk, skoffset + 32, 32);
                hasher.Update(m, moffset, mlen);
                hram = hasher.Finalize();

                NATS.NKeys.NaCl.Internal.Ed25519Ref10.ScalarOperations.sc_reduce(hram);
                var s = new byte[32];//todo: remove allocation
                Array.Copy(sig, sigoffset + 32, s, 0, 32);
                NATS.NKeys.NaCl.Internal.Ed25519Ref10.ScalarOperations.sc_muladd(s, hram, az, r);
                Array.Copy(s, 0, sig, sigoffset + 32, 32);
                CryptoBytes.Wipe(s);
            }
        }
    }
}
