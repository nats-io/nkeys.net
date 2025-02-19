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

namespace NATS.NKeys.NaCl.Internal.Ed25519Ref10
{
    internal static partial class GroupOperations
    {
        static byte equal(byte b, byte c)
        {

            var ub = b;
            var uc = c;
            var x = (byte)(ub ^ uc); /* 0: yes; 1..255: no */
            uint y = x; /* 0: yes; 1..255: no */
            unchecked
            { y -= 1; } /* 4294967295: yes; 0..254: no */
            y >>= 31; /* 1: yes; 0: no */
            return (byte)y;
        }

        static byte negative(sbyte b)
        {
            var x = unchecked((ulong)b); /* 18446744073709551361..18446744073709551615: yes; 0..255: no */
            x >>= 63; /* 1: yes; 0: no */
            return (byte)x;
        }

        static void cmov(ref GroupElementPreComp t, ref GroupElementPreComp u, byte b)
        {
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_cmov(ref t.yplusx, ref u.yplusx, b);
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_cmov(ref t.yminusx, ref u.yminusx, b);
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_cmov(ref t.xy2d, ref u.xy2d, b);
        }

        static void select(out GroupElementPreComp t, int pos, sbyte b)
        {
            GroupElementPreComp minust;
            var bnegative = negative(b);
            var babs = (byte)(b - (((-bnegative) & b) << 1));

            ge_precomp_0(out t);
            var table = NATS.NKeys.NaCl.Internal.Ed25519Ref10.LookupTables.Base[pos];
            cmov(ref t, ref table[0], equal(babs, 1));
            cmov(ref t, ref table[1], equal(babs, 2));
            cmov(ref t, ref table[2], equal(babs, 3));
            cmov(ref t, ref table[3], equal(babs, 4));
            cmov(ref t, ref table[4], equal(babs, 5));
            cmov(ref t, ref table[5], equal(babs, 6));
            cmov(ref t, ref table[6], equal(babs, 7));
            cmov(ref t, ref table[7], equal(babs, 8));
            minust.yplusx = t.yminusx;
            minust.yminusx = t.yplusx;
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_neg(out minust.xy2d, ref t.xy2d);
            cmov(ref t, ref minust, bnegative);
        }

        /*
        h = a * B
        where a = a[0]+256*a[1]+...+256^31 a[31]
        B is the Ed25519 base point (x,4/5) with x positive.

        Preconditions:
          a[31] <= 127
        */

        public static void ge_scalarmult_base(out GroupElementP3 h, byte[] a, int offset)
        {
            // todo: Perhaps remove this allocation
            var e = new sbyte[64];
            sbyte carry;

            GroupElementP1P1 r;
            GroupElementP2 s;
            GroupElementPreComp t;

            for (var i = 0; i < 32; ++i)
            {
                e[2 * i + 0] = (sbyte)((a[offset + i] >> 0) & 15);
                e[2 * i + 1] = (sbyte)((a[offset + i] >> 4) & 15);
            }
            /* each e[i] is between 0 and 15 */
            /* e[63] is between 0 and 7 */

            carry = 0;
            for (var i = 0; i < 63; ++i)
            {
                e[i] += carry;
                carry = (sbyte)(e[i] + 8);
                carry >>= 4;
                e[i] -= (sbyte)(carry << 4);
            }
            e[63] += carry;
            /* each e[i] is between -8 and 8 */

            ge_p3_0(out h);
            for (var i = 1; i < 64; i += 2)
            {
                select(out t, i / 2, e[i]);
                ge_madd(out r, ref h, ref t);
                ge_p1p1_to_p3(out h, ref r);
            }

            ge_p3_dbl(out r, ref h);
            ge_p1p1_to_p2(out s, ref r);
            ge_p2_dbl(out r, ref s);
            ge_p1p1_to_p2(out s, ref r);
            ge_p2_dbl(out r, ref s);
            ge_p1p1_to_p2(out s, ref r);
            ge_p2_dbl(out r, ref s);
            ge_p1p1_to_p3(out h, ref r);

            for (var i = 0; i < 64; i += 2)
            {
                select(out t, i / 2, e[i]);
                ge_madd(out r, ref h, ref t);
                ge_p1p1_to_p3(out h, ref r);
            }
        }

    }
}
