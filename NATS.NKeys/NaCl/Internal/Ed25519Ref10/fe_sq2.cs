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
h = 2 * f * f
Can overlap h with f.

Preconditions:
   |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

Postconditions:
   |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
*/

        /*
		See fe_mul.c for discussion of implementation strategy.
		*/
        internal static void fe_sq2(out FieldElement h, ref FieldElement f)
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

            var f0_2 = 2 * f0;
            var f1_2 = 2 * f1;
            var f2_2 = 2 * f2;
            var f3_2 = 2 * f3;
            var f4_2 = 2 * f4;
            var f5_2 = 2 * f5;
            var f6_2 = 2 * f6;
            var f7_2 = 2 * f7;
            var f5_38 = 38 * f5; /* 1.959375*2^30 */
            var f6_19 = 19 * f6; /* 1.959375*2^30 */
            var f7_38 = 38 * f7; /* 1.959375*2^30 */
            var f8_19 = 19 * f8; /* 1.959375*2^30 */
            var f9_38 = 38 * f9; /* 1.959375*2^30 */

            var f0f0 = f0 * (long)f0;
            var f0f1_2 = f0_2 * (long)f1;
            var f0f2_2 = f0_2 * (long)f2;
            var f0f3_2 = f0_2 * (long)f3;
            var f0f4_2 = f0_2 * (long)f4;
            var f0f5_2 = f0_2 * (long)f5;
            var f0f6_2 = f0_2 * (long)f6;
            var f0f7_2 = f0_2 * (long)f7;
            var f0f8_2 = f0_2 * (long)f8;
            var f0f9_2 = f0_2 * (long)f9;
            var f1f1_2 = f1_2 * (long)f1;
            var f1f2_2 = f1_2 * (long)f2;
            var f1f3_4 = f1_2 * (long)f3_2;
            var f1f4_2 = f1_2 * (long)f4;
            var f1f5_4 = f1_2 * (long)f5_2;
            var f1f6_2 = f1_2 * (long)f6;
            var f1f7_4 = f1_2 * (long)f7_2;
            var f1f8_2 = f1_2 * (long)f8;
            var f1f9_76 = f1_2 * (long)f9_38;
            var f2f2 = f2 * (long)f2;
            var f2f3_2 = f2_2 * (long)f3;
            var f2f4_2 = f2_2 * (long)f4;
            var f2f5_2 = f2_2 * (long)f5;
            var f2f6_2 = f2_2 * (long)f6;
            var f2f7_2 = f2_2 * (long)f7;
            var f2f8_38 = f2_2 * (long)f8_19;
            var f2f9_38 = f2 * (long)f9_38;
            var f3f3_2 = f3_2 * (long)f3;
            var f3f4_2 = f3_2 * (long)f4;
            var f3f5_4 = f3_2 * (long)f5_2;
            var f3f6_2 = f3_2 * (long)f6;
            var f3f7_76 = f3_2 * (long)f7_38;
            var f3f8_38 = f3_2 * (long)f8_19;
            var f3f9_76 = f3_2 * (long)f9_38;
            var f4f4 = f4 * (long)f4;
            var f4f5_2 = f4_2 * (long)f5;
            var f4f6_38 = f4_2 * (long)f6_19;
            var f4f7_38 = f4 * (long)f7_38;
            var f4f8_38 = f4_2 * (long)f8_19;
            var f4f9_38 = f4 * (long)f9_38;
            var f5f5_38 = f5 * (long)f5_38;
            var f5f6_38 = f5_2 * (long)f6_19;
            var f5f7_76 = f5_2 * (long)f7_38;
            var f5f8_38 = f5_2 * (long)f8_19;
            var f5f9_76 = f5_2 * (long)f9_38;
            var f6f6_19 = f6 * (long)f6_19;
            var f6f7_38 = f6 * (long)f7_38;
            var f6f8_38 = f6_2 * (long)f8_19;
            var f6f9_38 = f6 * (long)f9_38;
            var f7f7_38 = f7 * (long)f7_38;
            var f7f8_38 = f7_2 * (long)f8_19;
            var f7f9_76 = f7_2 * (long)f9_38;
            var f8f8_19 = f8 * (long)f8_19;
            var f8f9_38 = f8 * (long)f9_38;
            var f9f9_38 = f9 * (long)f9_38;

            var h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
            var h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
            var h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
            var h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
            var h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
            var h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
            var h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
            var h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
            var h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
            var h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;

            h0 += h0;
            h1 += h1;
            h2 += h2;
            h3 += h3;
            h4 += h4;
            h5 += h5;
            h6 += h6;
            h7 += h7;
            h8 += h8;
            h9 += h9;

            var carry0 = (h0 + (1 << 25)) >> 26;
            h1 += carry0;
            h0 -= carry0 << 26;
            var carry4 = (h4 + (1 << 25)) >> 26;
            h5 += carry4;
            h4 -= carry4 << 26;
            var carry1 = (h1 + (1 << 24)) >> 25;
            h2 += carry1;
            h1 -= carry1 << 25;
            var carry5 = (h5 + (1 << 24)) >> 25;
            h6 += carry5;
            h5 -= carry5 << 25;
            var carry2 = (h2 + (1 << 25)) >> 26;
            h3 += carry2;
            h2 -= carry2 << 26;
            var carry6 = (h6 + (1 << 25)) >> 26;
            h7 += carry6;
            h6 -= carry6 << 26;
            var carry3 = (h3 + (1 << 24)) >> 25;
            h4 += carry3;
            h3 -= carry3 << 25;
            var carry7 = (h7 + (1 << 24)) >> 25;
            h8 += carry7;
            h7 -= carry7 << 25;

            carry4 = (h4 + (1 << 25)) >> 26;
            h5 += carry4;
            h4 -= carry4 << 26;

            var carry8 = (h8 + (1 << 25)) >> 26;
            h9 += carry8;
            h8 -= carry8 << 26;
            var carry9 = (h9 + (1 << 24)) >> 25;
            h0 += carry9 * 19;
            h9 -= carry9 << 25;

            carry0 = (h0 + (1 << 25)) >> 26;
            h1 += carry0;
            h0 -= carry0 << 26;

            h.x0 = (int)h0;
            h.x1 = (int)h1;
            h.x2 = (int)h2;
            h.x3 = (int)h3;
            h.x4 = (int)h4;
            h.x5 = (int)h5;
            h.x6 = (int)h6;
            h.x7 = (int)h7;
            h.x8 = (int)h8;
            h.x9 = (int)h9;
        }
    }
}
