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

namespace NATS.NKeys.NaCl.Internal.Ed25519Ref10
{
    internal static partial class GroupOperations
    {
        private static void slide(sbyte[] r, byte[] a)
        {
            for (var i = 0; i < 256; ++i)
                r[i] = (sbyte)(1 & (a[i >> 3] >> (i & 7)));

            for (var i = 0; i < 256; ++i)
            {
                if (r[i] != 0)
                {
                    for (var b = 1; b <= 6 && (i + b) < 256; ++b)
                    {
                        if (r[i + b] != 0)
                        {
                            if (r[i] + (r[i + b] << b) <= 15)
                            {
                                r[i] += (sbyte)(r[i + b] << b);
                                r[i + b] = 0;
                            }
                            else if (r[i] - (r[i + b] << b) >= -15)
                            {
                                r[i] -= (sbyte)(r[i + b] << b);
                                for (var k = i + b; k < 256; ++k)
                                {
                                    if (r[k] == 0)
                                    {
                                        r[k] = 1;
                                        break;
                                    }
                                    r[k] = 0;
                                }
                            }
                            else
                                break;
                        }
                    }
                }
            }
        }

        /*
		r = a * A + b * B
		where a = a[0]+256*a[1]+...+256^31 a[31].
		and b = b[0]+256*b[1]+...+256^31 b[31].
		B is the Ed25519 base point (x,4/5) with x positive.
		*/

        public static void ge_double_scalarmult_vartime(out GroupElementP2 r, byte[] a, ref GroupElementP3 A, byte[] b)
        {
            var Bi = NATS.NKeys.NaCl.Internal.Ed25519Ref10.LookupTables.Base2;
            // todo: Perhaps remove these allocations?
            var aslide = new sbyte[256];
            var bslide = new sbyte[256];
            var Ai = new GroupElementCached[8]; /* A,3A,5A,7A,9A,11A,13A,15A */
            GroupElementP1P1 t;
            GroupElementP3 u;
            GroupElementP3 A2;
            int i;

            slide(aslide, a);
            slide(bslide, b);

            GroupOperations.ge_p3_to_cached(out Ai[0], ref A);
            GroupOperations.ge_p3_dbl(out t, ref A);
            GroupOperations.ge_p1p1_to_p3(out A2, ref t);
            ge_add(out t, ref A2, ref Ai[0]);
            GroupOperations.ge_p1p1_to_p3(out u, ref t);
            GroupOperations.ge_p3_to_cached(out Ai[1], ref u);
            ge_add(out t, ref A2, ref Ai[1]);
            GroupOperations.ge_p1p1_to_p3(out u, ref t);
            GroupOperations.ge_p3_to_cached(out Ai[2], ref u);
            ge_add(out t, ref A2, ref Ai[2]);
            GroupOperations.ge_p1p1_to_p3(out u, ref t);
            GroupOperations.ge_p3_to_cached(out Ai[3], ref u);
            ge_add(out t, ref A2, ref Ai[3]);
            GroupOperations.ge_p1p1_to_p3(out u, ref t);
            GroupOperations.ge_p3_to_cached(out Ai[4], ref u);
            ge_add(out t, ref A2, ref Ai[4]);
            GroupOperations.ge_p1p1_to_p3(out u, ref t);
            GroupOperations.ge_p3_to_cached(out Ai[5], ref u);
            ge_add(out t, ref A2, ref Ai[5]);
            GroupOperations.ge_p1p1_to_p3(out u, ref t);
            GroupOperations.ge_p3_to_cached(out Ai[6], ref u);
            ge_add(out t, ref A2, ref Ai[6]);
            GroupOperations.ge_p1p1_to_p3(out u, ref t);
            GroupOperations.ge_p3_to_cached(out Ai[7], ref u);

            GroupOperations.ge_p2_0(out r);

            for (i = 255; i >= 0; --i)
            {
                if ((aslide[i] != 0) || (bslide[i] != 0))
                    break;
            }

            for (; i >= 0; --i)
            {
                GroupOperations.ge_p2_dbl(out t, ref r);

                if (aslide[i] > 0)
                {
                    GroupOperations.ge_p1p1_to_p3(out u, ref t);
                    ge_add(out t, ref u, ref Ai[aslide[i] / 2]);
                }
                else if (aslide[i] < 0)
                {
                    GroupOperations.ge_p1p1_to_p3(out u, ref t);
                    GroupOperations.ge_sub(out t, ref u, ref Ai[(-aslide[i]) / 2]);
                }

                if (bslide[i] > 0)
                {
                    GroupOperations.ge_p1p1_to_p3(out u, ref t);
                    GroupOperations.ge_madd(out t, ref u, ref Bi[bslide[i] / 2]);
                }
                else if (bslide[i] < 0)
                {
                    GroupOperations.ge_p1p1_to_p3(out u, ref t);
                    GroupOperations.ge_msub(out t, ref u, ref Bi[(-bslide[i]) / 2]);
                }

                GroupOperations.ge_p1p1_to_p2(out r, ref t);
            }
        }

    }
}
