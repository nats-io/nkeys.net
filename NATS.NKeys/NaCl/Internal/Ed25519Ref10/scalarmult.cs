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
	internal static class MontgomeryOperations
	{
		public static void scalarmult(
			byte[] q, int qoffset,
			byte[] n, int noffset,
			byte[] p, int poffset)
		{
			FieldElement p0, q0;
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_frombytes2(out p0, p, poffset);
			scalarmult(out q0, n, noffset, ref p0);
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_tobytes(q, qoffset, ref q0);
		}

		internal static void scalarmult(
			out FieldElement q,
			byte[] n, int noffset,
			ref FieldElement p)
		{
			byte[] e = new byte[32];//ToDo: remove allocation
			FieldElement x1, x2, x3;
			FieldElement z2, z3;
			FieldElement tmp0, tmp1;

			for (int i = 0; i < 32; ++i)
				e[i] = n[noffset + i];
		    NATS.NKeys.NaCl.Internal.Ed25519Ref10.ScalarOperations.sc_clamp(e, 0);
			x1 = p;
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_1(out x2);
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_0(out z2);
			x3 = x1;
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_1(out z3);

			uint swap = 0;
			for (int pos = 254; pos >= 0; --pos)
			{
				uint b = (uint)(e[pos / 8] >> (pos & 7));
				b &= 1;
				swap ^= b;
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_cswap(ref x2, ref x3, swap);
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_cswap(ref z2, ref z3, swap);
				swap = b;

				/* qhasm: enter ladder */

				/* qhasm: D = X3-Z3 */
				/* asm 1: fe_sub(>D=fe#5,<X3=fe#3,<Z3=fe#4); */
				/* asm 2: fe_sub(>D=tmp0,<X3=x3,<Z3=z3); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sub(out tmp0, ref  x3, ref  z3);

				/* qhasm: B = X2-Z2 */
				/* asm 1: fe_sub(>B=fe#6,<X2=fe#1,<Z2=fe#2); */
				/* asm 2: fe_sub(>B=tmp1,<X2=x2,<Z2=z2); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sub(out tmp1, ref x2, ref z2);

				/* qhasm: A = X2+Z2 */
				/* asm 1: fe_add(>A=fe#1,<X2=fe#1,<Z2=fe#2); */
				/* asm 2: fe_add(>A=x2,<X2=x2,<Z2=z2); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_add(out x2, ref x2, ref z2);

				/* qhasm: C = X3+Z3 */
				/* asm 1: fe_add(>C=fe#2,<X3=fe#3,<Z3=fe#4); */
				/* asm 2: fe_add(>C=z2,<X3=x3,<Z3=z3); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_add(out z2, ref  x3, ref z3);

				/* qhasm: DA = D*A */
				/* asm 1: fe_mul(>DA=fe#4,<D=fe#5,<A=fe#1); */
				/* asm 2: fe_mul(>DA=z3,<D=tmp0,<A=x2); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out z3, ref tmp0, ref x2);

				/* qhasm: CB = C*B */
				/* asm 1: fe_mul(>CB=fe#2,<C=fe#2,<B=fe#6); */
				/* asm 2: fe_mul(>CB=z2,<C=z2,<B=tmp1); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out z2, ref  z2, ref tmp1);

				/* qhasm: BB = B^2 */
				/* asm 1: fe_sq(>BB=fe#5,<B=fe#6); */
				/* asm 2: fe_sq(>BB=tmp0,<B=tmp1); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sq(out tmp0, ref  tmp1);

				/* qhasm: AA = A^2 */
				/* asm 1: fe_sq(>AA=fe#6,<A=fe#1); */
				/* asm 2: fe_sq(>AA=tmp1,<A=x2); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sq(out tmp1, ref  x2);

				/* qhasm: t0 = DA+CB */
				/* asm 1: fe_add(>t0=fe#3,<DA=fe#4,<CB=fe#2); */
				/* asm 2: fe_add(>t0=x3,<DA=z3,<CB=z2); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_add(out x3, ref z3, ref  z2);

				/* qhasm: assign x3 to t0 */

				/* qhasm: t1 = DA-CB */
				/* asm 1: fe_sub(>t1=fe#2,<DA=fe#4,<CB=fe#2); */
				/* asm 2: fe_sub(>t1=z2,<DA=z3,<CB=z2); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sub(out z2, ref z3, ref  z2);

				/* qhasm: X4 = AA*BB */
				/* asm 1: fe_mul(>X4=fe#1,<AA=fe#6,<BB=fe#5); */
				/* asm 2: fe_mul(>X4=x2,<AA=tmp1,<BB=tmp0); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out x2, ref tmp1, ref  tmp0);

				/* qhasm: E = AA-BB */
				/* asm 1: fe_sub(>E=fe#6,<AA=fe#6,<BB=fe#5); */
				/* asm 2: fe_sub(>E=tmp1,<AA=tmp1,<BB=tmp0); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sub(out tmp1, ref  tmp1, ref tmp0);

				/* qhasm: t2 = t1^2 */
				/* asm 1: fe_sq(>t2=fe#2,<t1=fe#2); */
				/* asm 2: fe_sq(>t2=z2,<t1=z2); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sq(out z2, ref z2);

				/* qhasm: t3 = a24*E */
				/* asm 1: fe_mul121666(>t3=fe#4,<E=fe#6); */
				/* asm 2: fe_mul121666(>t3=z3,<E=tmp1); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul121666(out z3, ref tmp1);

				/* qhasm: X5 = t0^2 */
				/* asm 1: fe_sq(>X5=fe#3,<t0=fe#3); */
				/* asm 2: fe_sq(>X5=x3,<t0=x3); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sq(out x3, ref  x3);

				/* qhasm: t4 = BB+t3 */
				/* asm 1: fe_add(>t4=fe#5,<BB=fe#5,<t3=fe#4); */
				/* asm 2: fe_add(>t4=tmp0,<BB=tmp0,<t3=z3); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_add(out tmp0, ref  tmp0, ref z3);

				/* qhasm: Z5 = X1*t2 */
				/* asm 1: fe_mul(>Z5=fe#4,x1,<t2=fe#2); */
				/* asm 2: fe_mul(>Z5=z3,x1,<t2=z2); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out z3, ref x1, ref  z2);

				/* qhasm: Z4 = E*t4 */
				/* asm 1: fe_mul(>Z4=fe#2,<E=fe#6,<t4=fe#5); */
				/* asm 2: fe_mul(>Z4=z2,<E=tmp1,<t4=tmp0); */
				NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out z2, ref  tmp1, ref  tmp0);

				/* qhasm: return */

			}
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_cswap(ref x2, ref x3, swap);
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_cswap(ref z2, ref z3, swap);

			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_invert(out z2, ref z2);
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out x2, ref x2, ref z2);
			q = x2;
			CryptoBytes.Wipe(e);
		}
	}
}
