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
        /*
		h = f + g
		Can overlap h with f or g.

		Preconditions:
		   |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
		   |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.

		Postconditions:
		   |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
		*/
        //void fe_add(fe h,const fe f,const fe g)
        internal static void fe_add(out FieldElement h, ref FieldElement f, ref FieldElement g)
        {
            var f0 = f.x0;
            var f1 = f.x1;
            var f2 = f.x2;
            var f3 = f.x3;
            var f4 = f.x4;
            var f5 = f.x5;
            var f6 = f.x6;
            var f7 = f.x7;
            var f8 = f.x8;
            var f9 = f.x9;
            var g0 = g.x0;
            var g1 = g.x1;
            var g2 = g.x2;
            var g3 = g.x3;
            var g4 = g.x4;
            var g5 = g.x5;
            var g6 = g.x6;
            var g7 = g.x7;
            var g8 = g.x8;
            var g9 = g.x9;
            var h0 = f0 + g0;
            var h1 = f1 + g1;
            var h2 = f2 + g2;
            var h3 = f3 + g3;
            var h4 = f4 + g4;
            var h5 = f5 + g5;
            var h6 = f6 + g6;
            var h7 = f7 + g7;
            var h8 = f8 + g8;
            var h9 = f9 + g9;

            h.x0 = h0;
            h.x1 = h1;
            h.x2 = h2;
            h.x3 = h3;
            h.x4 = h4;
            h.x5 = h5;
            h.x6 = h6;
            h.x7 = h7;
            h.x8 = h8;
            h.x9 = h9;
        }
    }
}
