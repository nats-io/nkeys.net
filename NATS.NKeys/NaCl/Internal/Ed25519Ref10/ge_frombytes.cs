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
        public static int ge_frombytes_negate_vartime(out GroupElementP3 h, byte[] data, int offset)
        {
            FieldElement u, v, v3, vxx, check;

            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_frombytes(out h.Y, data, offset);
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_1(out h.Z);
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sq(out u, ref h.Y);
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out v, ref u, ref NATS.NKeys.NaCl.Internal.Ed25519Ref10.LookupTables.d);
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sub(out u, ref u, ref h.Z);       /* u = y^2-1 */
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_add(out v, ref v, ref h.Z);       /* v = dy^2+1 */

            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sq(out v3, ref v);
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out v3, ref v3, ref v);        /* v3 = v^3 */
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sq(out h.X, ref v3);
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out h.X, ref h.X, ref v);
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out h.X, ref h.X, ref u);    /* x = uv^7 */

            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_pow22523(out h.X, ref h.X); /* x = (uv^7)^((q-5)/8) */
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out h.X, ref h.X, ref v3);
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out h.X, ref h.X, ref u);    /* x = uv^3(uv^7)^((q-5)/8) */

            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sq(out vxx, ref h.X);
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out vxx, ref vxx, ref v);
            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sub(out check, ref vxx, ref u);    /* vx^2-u */
            if (NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_isnonzero(ref check) != 0)
            {
                NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_add(out check, ref vxx, ref u);  /* vx^2+u */
                if (NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_isnonzero(ref check) != 0)
                {
                    h = default(GroupElementP3);
                    return -1;
                }
                NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out h.X, ref h.X, ref NATS.NKeys.NaCl.Internal.Ed25519Ref10.LookupTables.sqrtm1);
            }

            if (NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_isnegative(ref h.X) == (data[offset + 31] >> 7))
                NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_neg(out h.X, ref h.X);

            NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out h.T, ref h.X, ref h.Y);
            return 0;
        }

    }
}
