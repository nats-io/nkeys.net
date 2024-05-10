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
    internal static partial class FieldOperations
    {
        /*
        Replace (f,g) with (g,f) if b == 1;
        replace (f,g) with (f,g) if b == 0.

        Preconditions: b in {0,1}.
        */
        public static void fe_cswap(ref FieldElement f, ref FieldElement g, uint b)
        {
            int f0 = f.x0;
            int f1 = f.x1;
            int f2 = f.x2;
            int f3 = f.x3;
            int f4 = f.x4;
            int f5 = f.x5;
            int f6 = f.x6;
            int f7 = f.x7;
            int f8 = f.x8;
            int f9 = f.x9;
            int g0 = g.x0;
            int g1 = g.x1;
            int g2 = g.x2;
            int g3 = g.x3;
            int g4 = g.x4;
            int g5 = g.x5;
            int g6 = g.x6;
            int g7 = g.x7;
            int g8 = g.x8;
            int g9 = g.x9;
            int x0 = f0 ^ g0;
            int x1 = f1 ^ g1;
            int x2 = f2 ^ g2;
            int x3 = f3 ^ g3;
            int x4 = f4 ^ g4;
            int x5 = f5 ^ g5;
            int x6 = f6 ^ g6;
            int x7 = f7 ^ g7;
            int x8 = f8 ^ g8;
            int x9 = f9 ^ g9;

            int negb = unchecked((int)-b);
            x0 &= negb;
            x1 &= negb;
            x2 &= negb;
            x3 &= negb;
            x4 &= negb;
            x5 &= negb;
            x6 &= negb;
            x7 &= negb;
            x8 &= negb;
            x9 &= negb;
            f.x0 = f0 ^ x0;
            f.x1 = f1 ^ x1;
            f.x2 = f2 ^ x2;
            f.x3 = f3 ^ x3;
            f.x4 = f4 ^ x4;
            f.x5 = f5 ^ x5;
            f.x6 = f6 ^ x6;
            f.x7 = f7 ^ x7;
            f.x8 = f8 ^ x8;
            f.x9 = f9 ^ x9;
            g.x0 = g0 ^ x0;
            g.x1 = g1 ^ x1;
            g.x2 = g2 ^ x2;
            g.x3 = g3 ^ x3;
            g.x4 = g4 ^ x4;
            g.x5 = g5 ^ x5;
            g.x6 = g6 ^ x6;
            g.x7 = g7 ^ x7;
            g.x8 = g8 ^ x8;
            g.x9 = g9 ^ x9;
        }
    }
}
