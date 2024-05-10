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
		/*
		r = 2 * p
		*/

		public static void ge_p2_dbl(out GroupElementP1P1 r, ref GroupElementP2 p)
		{
			FieldElement t0;

			/* qhasm: XX=X1^2 */
			/* asm 1: fe_sq(>XX=fe#1,<X1=fe#11); */
			/* asm 2: fe_sq(>XX=r.X,<X1=p.X); */
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sq(out r.X, ref p.X);

			/* qhasm: YY=Y1^2 */
			/* asm 1: fe_sq(>YY=fe#3,<Y1=fe#12); */
			/* asm 2: fe_sq(>YY=r.Z,<Y1=p.Y); */
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sq(out r.Z, ref p.Y);

			/* qhasm: B=2*Z1^2 */
			/* asm 1: fe_sq2(>B=fe#4,<Z1=fe#13); */
			/* asm 2: fe_sq2(>B=r.T,<Z1=p.Z); */
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sq2(out r.T, ref p.Z);

			/* qhasm: A=X1+Y1 */
			/* asm 1: fe_add(>A=fe#2,<X1=fe#11,<Y1=fe#12); */
			/* asm 2: fe_add(>A=r.Y,<X1=p.X,<Y1=p.Y); */
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_add(out r.Y, ref p.X, ref p.Y);

			/* qhasm: AA=A^2 */
			/* asm 1: fe_sq(>AA=fe#5,<A=fe#2); */
			/* asm 2: fe_sq(>AA=t0,<A=r.Y); */
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sq(out t0, ref r.Y);

			/* qhasm: Y3=YY+XX */
			/* asm 1: fe_add(>Y3=fe#2,<YY=fe#3,<XX=fe#1); */
			/* asm 2: fe_add(>Y3=r.Y,<YY=r.Z,<XX=r.X); */
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_add(out r.Y, ref r.Z, ref r.X);

			/* qhasm: Z3=YY-XX */
			/* asm 1: fe_sub(>Z3=fe#3,<YY=fe#3,<XX=fe#1); */
			/* asm 2: fe_sub(>Z3=r.Z,<YY=r.Z,<XX=r.X); */
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sub(out r.Z, ref r.Z, ref r.X);

			/* qhasm: X3=AA-Y3 */
			/* asm 1: fe_sub(>X3=fe#1,<AA=fe#5,<Y3=fe#2); */
			/* asm 2: fe_sub(>X3=r.X,<AA=t0,<Y3=r.Y); */
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sub(out r.X, ref t0, ref r.Y);

			/* qhasm: T3=B-Z3 */
			/* asm 1: fe_sub(>T3=fe#4,<B=fe#4,<Z3=fe#3); */
			/* asm 2: fe_sub(>T3=r.T,<B=r.T,<Z3=r.Z); */
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sub(out r.T, ref r.T, ref r.Z);

			/* qhasm: return */

		}
	}
}
