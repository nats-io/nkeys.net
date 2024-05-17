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
    internal static partial class FieldOperations
    {
        internal static void fe_invert(out FieldElement result, ref FieldElement z)
        {
            FieldElement t0, t1, t2, t3;
            int i;

            /* qhasm: z2 = z1^2^1 */
            /* asm 1: fe_sq(>z2=fe#1,<z1=fe#11); for (i = 1;i < 1;++i) fe_sq(>z2=fe#1,>z2=fe#1); */
            /* asm 2: fe_sq(>z2=t0,<z1=z); for (i = 1;i < 1;++i) fe_sq(>z2=t0,>z2=t0); */
            FieldOperations.fe_sq(out t0, ref z); //for (i = 1; i < 1; ++i) fe_sq(out t0, ref t0);

            /* qhasm: z8 = z2^2^2 */
            /* asm 1: fe_sq(>z8=fe#2,<z2=fe#1); for (i = 1;i < 2;++i) fe_sq(>z8=fe#2,>z8=fe#2); */
            /* asm 2: fe_sq(>z8=t1,<z2=t0); for (i = 1;i < 2;++i) fe_sq(>z8=t1,>z8=t1); */
            FieldOperations.fe_sq(out t1, ref t0);
            for (i = 1; i < 2; ++i)
                FieldOperations.fe_sq(out t1, ref t1);

            /* qhasm: z9 = z1*z8 */
            /* asm 1: fe_mul(>z9=fe#2,<z1=fe#11,<z8=fe#2); */
            /* asm 2: fe_mul(>z9=t1,<z1=z,<z8=t1); */
            FieldOperations.fe_mul(out t1, ref z, ref t1);

            /* qhasm: z11 = z2*z9 */
            /* asm 1: fe_mul(>z11=fe#1,<z2=fe#1,<z9=fe#2); */
            /* asm 2: fe_mul(>z11=t0,<z2=t0,<z9=t1); */
            FieldOperations.fe_mul(out t0, ref t0, ref t1);

            /* qhasm: z22 = z11^2^1 */
            /* asm 1: fe_sq(>z22=fe#3,<z11=fe#1); for (i = 1;i < 1;++i) fe_sq(>z22=fe#3,>z22=fe#3); */
            /* asm 2: fe_sq(>z22=t2,<z11=t0); for (i = 1;i < 1;++i) fe_sq(>z22=t2,>z22=t2); */
            FieldOperations.fe_sq(out t2, ref t0); //for (i = 1; i < 1; ++i) fe_sq(out t2, ref t2);

            /* qhasm: z_5_0 = z9*z22 */
            /* asm 1: fe_mul(>z_5_0=fe#2,<z9=fe#2,<z22=fe#3); */
            /* asm 2: fe_mul(>z_5_0=t1,<z9=t1,<z22=t2); */
            FieldOperations.fe_mul(out t1, ref t1, ref t2);

            /* qhasm: z_10_5 = z_5_0^2^5 */
            /* asm 1: fe_sq(>z_10_5=fe#3,<z_5_0=fe#2); for (i = 1;i < 5;++i) fe_sq(>z_10_5=fe#3,>z_10_5=fe#3); */
            /* asm 2: fe_sq(>z_10_5=t2,<z_5_0=t1); for (i = 1;i < 5;++i) fe_sq(>z_10_5=t2,>z_10_5=t2); */
            FieldOperations.fe_sq(out t2, ref t1);
            for (i = 1; i < 5; ++i)
                FieldOperations.fe_sq(out t2, ref t2);

            /* qhasm: z_10_0 = z_10_5*z_5_0 */
            /* asm 1: fe_mul(>z_10_0=fe#2,<z_10_5=fe#3,<z_5_0=fe#2); */
            /* asm 2: fe_mul(>z_10_0=t1,<z_10_5=t2,<z_5_0=t1); */
            FieldOperations.fe_mul(out t1, ref t2, ref t1);

            /* qhasm: z_20_10 = z_10_0^2^10 */
            /* asm 1: fe_sq(>z_20_10=fe#3,<z_10_0=fe#2); for (i = 1;i < 10;++i) fe_sq(>z_20_10=fe#3,>z_20_10=fe#3); */
            /* asm 2: fe_sq(>z_20_10=t2,<z_10_0=t1); for (i = 1;i < 10;++i) fe_sq(>z_20_10=t2,>z_20_10=t2); */
            FieldOperations.fe_sq(out t2, ref t1);
            for (i = 1; i < 10; ++i)
                FieldOperations.fe_sq(out t2, ref t2);

            /* qhasm: z_20_0 = z_20_10*z_10_0 */
            /* asm 1: fe_mul(>z_20_0=fe#3,<z_20_10=fe#3,<z_10_0=fe#2); */
            /* asm 2: fe_mul(>z_20_0=t2,<z_20_10=t2,<z_10_0=t1); */
            FieldOperations.fe_mul(out t2, ref t2, ref t1);

            /* qhasm: z_40_20 = z_20_0^2^20 */
            /* asm 1: fe_sq(>z_40_20=fe#4,<z_20_0=fe#3); for (i = 1;i < 20;++i) fe_sq(>z_40_20=fe#4,>z_40_20=fe#4); */
            /* asm 2: fe_sq(>z_40_20=t3,<z_20_0=t2); for (i = 1;i < 20;++i) fe_sq(>z_40_20=t3,>z_40_20=t3); */
            FieldOperations.fe_sq(out t3, ref t2);
            for (i = 1; i < 20; ++i)
                FieldOperations.fe_sq(out t3, ref t3);

            /* qhasm: z_40_0 = z_40_20*z_20_0 */
            /* asm 1: fe_mul(>z_40_0=fe#3,<z_40_20=fe#4,<z_20_0=fe#3); */
            /* asm 2: fe_mul(>z_40_0=t2,<z_40_20=t3,<z_20_0=t2); */
            FieldOperations.fe_mul(out t2, ref t3, ref t2);

            /* qhasm: z_50_10 = z_40_0^2^10 */
            /* asm 1: fe_sq(>z_50_10=fe#3,<z_40_0=fe#3); for (i = 1;i < 10;++i) fe_sq(>z_50_10=fe#3,>z_50_10=fe#3); */
            /* asm 2: fe_sq(>z_50_10=t2,<z_40_0=t2); for (i = 1;i < 10;++i) fe_sq(>z_50_10=t2,>z_50_10=t2); */
            FieldOperations.fe_sq(out t2, ref t2);
            for (i = 1; i < 10; ++i)
                FieldOperations.fe_sq(out t2, ref t2);

            /* qhasm: z_50_0 = z_50_10*z_10_0 */
            /* asm 1: fe_mul(>z_50_0=fe#2,<z_50_10=fe#3,<z_10_0=fe#2); */
            /* asm 2: fe_mul(>z_50_0=t1,<z_50_10=t2,<z_10_0=t1); */
            FieldOperations.fe_mul(out t1, ref t2, ref t1);

            /* qhasm: z_100_50 = z_50_0^2^50 */
            /* asm 1: fe_sq(>z_100_50=fe#3,<z_50_0=fe#2); for (i = 1;i < 50;++i) fe_sq(>z_100_50=fe#3,>z_100_50=fe#3); */
            /* asm 2: fe_sq(>z_100_50=t2,<z_50_0=t1); for (i = 1;i < 50;++i) fe_sq(>z_100_50=t2,>z_100_50=t2); */
            FieldOperations.fe_sq(out t2, ref t1);
            for (i = 1; i < 50; ++i)
                FieldOperations.fe_sq(out t2, ref t2);

            /* qhasm: z_100_0 = z_100_50*z_50_0 */
            /* asm 1: fe_mul(>z_100_0=fe#3,<z_100_50=fe#3,<z_50_0=fe#2); */
            /* asm 2: fe_mul(>z_100_0=t2,<z_100_50=t2,<z_50_0=t1); */
            FieldOperations.fe_mul(out t2, ref t2, ref t1);

            /* qhasm: z_200_100 = z_100_0^2^100 */
            /* asm 1: fe_sq(>z_200_100=fe#4,<z_100_0=fe#3); for (i = 1;i < 100;++i) fe_sq(>z_200_100=fe#4,>z_200_100=fe#4); */
            /* asm 2: fe_sq(>z_200_100=t3,<z_100_0=t2); for (i = 1;i < 100;++i) fe_sq(>z_200_100=t3,>z_200_100=t3); */
            FieldOperations.fe_sq(out t3, ref t2);
            for (i = 1; i < 100; ++i)
                FieldOperations.fe_sq(out t3, ref t3);

            /* qhasm: z_200_0 = z_200_100*z_100_0 */
            /* asm 1: fe_mul(>z_200_0=fe#3,<z_200_100=fe#4,<z_100_0=fe#3); */
            /* asm 2: fe_mul(>z_200_0=t2,<z_200_100=t3,<z_100_0=t2); */
            FieldOperations.fe_mul(out t2, ref t3, ref t2);

            /* qhasm: z_250_50 = z_200_0^2^50 */
            /* asm 1: fe_sq(>z_250_50=fe#3,<z_200_0=fe#3); for (i = 1;i < 50;++i) fe_sq(>z_250_50=fe#3,>z_250_50=fe#3); */
            /* asm 2: fe_sq(>z_250_50=t2,<z_200_0=t2); for (i = 1;i < 50;++i) fe_sq(>z_250_50=t2,>z_250_50=t2); */
            FieldOperations.fe_sq(out t2, ref t2);
            for (i = 1; i < 50; ++i)
                FieldOperations.fe_sq(out t2, ref t2);

            /* qhasm: z_250_0 = z_250_50*z_50_0 */
            /* asm 1: fe_mul(>z_250_0=fe#2,<z_250_50=fe#3,<z_50_0=fe#2); */
            /* asm 2: fe_mul(>z_250_0=t1,<z_250_50=t2,<z_50_0=t1); */
            FieldOperations.fe_mul(out t1, ref t2, ref t1);

            /* qhasm: z_255_5 = z_250_0^2^5 */
            /* asm 1: fe_sq(>z_255_5=fe#2,<z_250_0=fe#2); for (i = 1;i < 5;++i) fe_sq(>z_255_5=fe#2,>z_255_5=fe#2); */
            /* asm 2: fe_sq(>z_255_5=t1,<z_250_0=t1); for (i = 1;i < 5;++i) fe_sq(>z_255_5=t1,>z_255_5=t1); */
            FieldOperations.fe_sq(out t1, ref t1);
            for (i = 1; i < 5; ++i)
                FieldOperations.fe_sq(out t1, ref t1);

            /* qhasm: z_255_21 = z_255_5*z11 */
            /* asm 1: fe_mul(>z_255_21=fe#12,<z_255_5=fe#2,<z11=fe#1); */
            /* asm 2: fe_mul(>z_255_21=out,<z_255_5=t1,<z11=t0); */
            FieldOperations.fe_mul(out result, ref t1, ref t0);

            /* qhasm: return */


            return;
        }
    }
}
