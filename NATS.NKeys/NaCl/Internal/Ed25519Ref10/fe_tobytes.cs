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
        Preconditions:
          |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.

        Write p=2^255-19; q=floor(h/p).
        Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).

        Proof:
          Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
          Also have |h-2^230 h9|<2^231 so |19 2^(-255)(h-2^230 h9)|<1/4.

          Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
          Then 0<y<1.

          Write r=h-pq.
          Have 0<=r<=p-1=2^255-20.
          Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.

          Write x=r+19(2^-255)r+y.
          Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.

          Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
          so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q.
        */
        internal static void fe_tobytes(byte[] s, int offset, ref FieldElement h)
        {
            FieldElement hr;
            fe_reduce(out hr, ref h);

            var h0 = hr.x0;
            var h1 = hr.x1;
            var h2 = hr.x2;
            var h3 = hr.x3;
            var h4 = hr.x4;
            var h5 = hr.x5;
            var h6 = hr.x6;
            var h7 = hr.x7;
            var h8 = hr.x8;
            var h9 = hr.x9;

            /*
            Goal: Output h0+...+2^255 h10-2^255 q, which is between 0 and 2^255-20.
            Have h0+...+2^230 h9 between 0 and 2^255-1;
            evidently 2^255 h10-2^255 q = 0.
            Goal: Output h0+...+2^230 h9.
            */
            unchecked
            {
                s[offset + 0] = (byte)(h0 >> 0);
                s[offset + 1] = (byte)(h0 >> 8);
                s[offset + 2] = (byte)(h0 >> 16);
                s[offset + 3] = (byte)((h0 >> 24) | (h1 << 2));
                s[offset + 4] = (byte)(h1 >> 6);
                s[offset + 5] = (byte)(h1 >> 14);
                s[offset + 6] = (byte)((h1 >> 22) | (h2 << 3));
                s[offset + 7] = (byte)(h2 >> 5);
                s[offset + 8] = (byte)(h2 >> 13);
                s[offset + 9] = (byte)((h2 >> 21) | (h3 << 5));
                s[offset + 10] = (byte)(h3 >> 3);
                s[offset + 11] = (byte)(h3 >> 11);
                s[offset + 12] = (byte)((h3 >> 19) | (h4 << 6));
                s[offset + 13] = (byte)(h4 >> 2);
                s[offset + 14] = (byte)(h4 >> 10);
                s[offset + 15] = (byte)(h4 >> 18);
                s[offset + 16] = (byte)(h5 >> 0);
                s[offset + 17] = (byte)(h5 >> 8);
                s[offset + 18] = (byte)(h5 >> 16);
                s[offset + 19] = (byte)((h5 >> 24) | (h6 << 1));
                s[offset + 20] = (byte)(h6 >> 7);
                s[offset + 21] = (byte)(h6 >> 15);
                s[offset + 22] = (byte)((h6 >> 23) | (h7 << 3));
                s[offset + 23] = (byte)(h7 >> 5);
                s[offset + 24] = (byte)(h7 >> 13);
                s[offset + 25] = (byte)((h7 >> 21) | (h8 << 4));
                s[offset + 26] = (byte)(h8 >> 4);
                s[offset + 27] = (byte)(h8 >> 12);
                s[offset + 28] = (byte)((h8 >> 20) | (h9 << 6));
                s[offset + 29] = (byte)(h9 >> 2);
                s[offset + 30] = (byte)(h9 >> 10);
                s[offset + 31] = (byte)(h9 >> 18);
            }
        }

        internal static void fe_reduce(out FieldElement hr, ref FieldElement h)
        {
            var h0 = h.x0;
            var h1 = h.x1;
            var h2 = h.x2;
            var h3 = h.x3;
            var h4 = h.x4;
            var h5 = h.x5;
            var h6 = h.x6;
            var h7 = h.x7;
            var h8 = h.x8;
            var h9 = h.x9;

            int q;

            q = (19 * h9 + (1 << 24)) >> 25;
            q = (h0 + q) >> 26;
            q = (h1 + q) >> 25;
            q = (h2 + q) >> 26;
            q = (h3 + q) >> 25;
            q = (h4 + q) >> 26;
            q = (h5 + q) >> 25;
            q = (h6 + q) >> 26;
            q = (h7 + q) >> 25;
            q = (h8 + q) >> 26;
            q = (h9 + q) >> 25;

            /* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
            h0 += 19 * q;
            /* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */

            var carry0 = h0 >> 26;
            h1 += carry0;
            h0 -= carry0 << 26;
            var carry1 = h1 >> 25;
            h2 += carry1;
            h1 -= carry1 << 25;
            var carry2 = h2 >> 26;
            h3 += carry2;
            h2 -= carry2 << 26;
            var carry3 = h3 >> 25;
            h4 += carry3;
            h3 -= carry3 << 25;
            var carry4 = h4 >> 26;
            h5 += carry4;
            h4 -= carry4 << 26;
            var carry5 = h5 >> 25;
            h6 += carry5;
            h5 -= carry5 << 25;
            var carry6 = h6 >> 26;
            h7 += carry6;
            h6 -= carry6 << 26;
            var carry7 = h7 >> 25;
            h8 += carry7;
            h7 -= carry7 << 25;
            var carry8 = h8 >> 26;
            h9 += carry8;
            h8 -= carry8 << 26;
            var carry9 = h9 >> 25;
            h9 -= carry9 << 25;
            /* h10 = carry9 */

            hr.x0 = h0;
            hr.x1 = h1;
            hr.x2 = h2;
            hr.x3 = h3;
            hr.x4 = h4;
            hr.x5 = h5;
            hr.x6 = h6;
            hr.x7 = h7;
            hr.x8 = h8;
            hr.x9 = h9;
        }
    }
}
