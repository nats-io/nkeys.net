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
        /*
		r = p - q
		*/
        public static void ge_msub(out GroupElementP1P1 r, ref GroupElementP3 p, ref GroupElementPreComp q)
        {
            FieldElement t0;

            /* qhasm: YpX1 = Y1+X1 */
            /* asm 1: fe_add(>YpX1=fe#1,<Y1=fe#12,<X1=fe#11); */
            /* asm 2: fe_add(>YpX1=r.X,<Y1=p.Y,<X1=p.X); */
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_add(out r.X, ref p.Y, ref p.X);

            /* qhasm: YmX1 = Y1-X1 */
            /* asm 1: fe_sub(>YmX1=fe#2,<Y1=fe#12,<X1=fe#11); */
            /* asm 2: fe_sub(>YmX1=r.Y,<Y1=p.Y,<X1=p.X); */
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sub(out r.Y, ref p.Y, ref p.X);

            /* qhasm: A = YpX1*ymx2 */
            /* asm 1: fe_mul(>A=fe#3,<YpX1=fe#1,<ymx2=fe#16); */
            /* asm 2: fe_mul(>A=r.Z,<YpX1=r.X,<ymx2=q.yminusx); */
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out r.Z, ref r.X, ref q.yminusx);

            /* qhasm: B = YmX1*ypx2 */
            /* asm 1: fe_mul(>B=fe#2,<YmX1=fe#2,<ypx2=fe#15); */
            /* asm 2: fe_mul(>B=r.Y,<YmX1=r.Y,<ypx2=q.yplusx); */
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out r.Y, ref r.Y, ref q.yplusx);

            /* qhasm: C = xy2d2*T1 */
            /* asm 1: fe_mul(>C=fe#4,<xy2d2=fe#17,<T1=fe#14); */
            /* asm 2: fe_mul(>C=r.T,<xy2d2=q.xy2d,<T1=p.T); */
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out r.T, ref q.xy2d, ref p.T);

            /* qhasm: D = 2*Z1 */
            /* asm 1: fe_add(>D=fe#5,<Z1=fe#13,<Z1=fe#13); */
            /* asm 2: fe_add(>D=t0,<Z1=p.Z,<Z1=p.Z); */
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_add(out t0, ref p.Z, ref p.Z);

            /* qhasm: X3 = A-B */
            /* asm 1: fe_sub(>X3=fe#1,<A=fe#3,<B=fe#2); */
            /* asm 2: fe_sub(>X3=r.X,<A=r.Z,<B=r.Y); */
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sub(out r.X, ref r.Z, ref r.Y);

            /* qhasm: Y3 = A+B */
            /* asm 1: fe_add(>Y3=fe#2,<A=fe#3,<B=fe#2); */
            /* asm 2: fe_add(>Y3=r.Y,<A=r.Z,<B=r.Y); */
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_add(out r.Y, ref r.Z, ref r.Y);

            /* qhasm: Z3 = D-C */
            /* asm 1: fe_sub(>Z3=fe#3,<D=fe#5,<C=fe#4); */
            /* asm 2: fe_sub(>Z3=r.Z,<D=t0,<C=r.T); */
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sub(out r.Z, ref t0, ref r.T);

            /* qhasm: T3 = D+C */
            /* asm 1: fe_add(>T3=fe#4,<D=fe#5,<C=fe#4); */
            /* asm 2: fe_add(>T3=r.T,<D=t0,<C=r.T); */
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_add(out r.T, ref t0, ref r.T);

            /* qhasm: return */

        }
    }
}
