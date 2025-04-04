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
        // Original crypto_sign_open, for reference only
        /*public static int crypto_sign_open(
          byte[] m, out int mlen,
          byte[] sm, int smlen,
          byte[] pk)
        {
            byte[] h = new byte[64];
            byte[] checkr = new byte[32];
            GroupElementP3 A;
            GroupElementP2 R;
            int i;

            mlen = -1;
            if (smlen < 64) return -1;
            if ((sm[63] & 224) != 0) return -1;
            if (GroupOperations.ge_frombytes_negate_vartime(out A, pk, 0) != 0) return -1;

            for (i = 0; i < smlen; ++i) m[i] = sm[i];
            for (i = 0; i < 32; ++i) m[32 + i] = pk[i];
            Sha512BclWrapper.crypto_hash_sha512(h, m, 0, smlen);
            ScalarOperations.sc_reduce(h);

            var sm32 = new byte[32];
            Array.Copy(sm, 32, sm32, 0, 32);
            GroupOperations.ge_double_scalarmult_vartime(out R, h, ref A, sm32);
            GroupOperations.ge_tobytes(checkr, 0, ref R);
            if (Helpers.crypto_verify_32(checkr, sm) != 0)
            {
                for (i = 0; i < smlen; ++i)
                    m[i] = 0;
                return -1;
            }

            for (i = 0; i < smlen - 64; ++i)
                m[i] = sm[64 + i];
            for (i = smlen - 64; i < smlen; ++i)
                m[i] = 0;
            mlen = smlen - 64;
            return 0;
        }*/

        public static bool crypto_sign_verify(
            byte[] sig, int sigoffset,
            byte[] m, int moffset, int mlen,
            byte[] pk, int pkoffset)
        {
            byte[] h;
            var checkr = new byte[32];
            GroupElementP3 A;
            GroupElementP2 R;

            if ((sig[sigoffset + 63] & 224) != 0)
                return false;
            if (NATS.NKeys.NaCl.Internal.Ed25519Ref10.GroupOperations.ge_frombytes_negate_vartime(out A, pk, pkoffset) != 0)
                return false;

            var hasher = new Sha512();
            hasher.Update(sig, sigoffset, 32);
            hasher.Update(pk, pkoffset, 32);
            hasher.Update(m, moffset, mlen);
            h = hasher.Finalize();

            ScalarOperations.sc_reduce(h);

            var sm32 = new byte[32];//todo: remove allocation
            Array.Copy(sig, sigoffset + 32, sm32, 0, 32);
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.GroupOperations.ge_double_scalarmult_vartime(out R, h, ref A, sm32);
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.GroupOperations.ge_tobytes(checkr, 0, ref R);
            var result = CryptoBytes.ConstantTimeEquals(checkr, 0, sig, sigoffset, 32);
            CryptoBytes.Wipe(h);
            CryptoBytes.Wipe(checkr);
            return result;
        }
    }
}
