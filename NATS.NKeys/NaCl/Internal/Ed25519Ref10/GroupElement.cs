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
    /*
    ge means group element.

    Here the group is the set of pairs (x,y) of field elements (see fe.h)
    satisfying -x^2 + y^2 = 1 + d x^2y^2
    where d = -121665/121666.

    Representations:
      ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
      ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
      ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
      ge_precomp (Duif): (y+x,y-x,2dxy)
    */

    internal struct GroupElementP2
	{
		public FieldElement X;
		public FieldElement Y;
		public FieldElement Z;
    } ;

    internal struct GroupElementP3
	{
		public FieldElement X;
		public FieldElement Y;
		public FieldElement Z;
		public FieldElement T;
	} ;

	internal struct GroupElementP1P1
	{
		public FieldElement X;
		public FieldElement Y;
		public FieldElement Z;
		public FieldElement T;
	} ;

	internal struct GroupElementPreComp
	{
        public FieldElement yplusx;
        public FieldElement yminusx;
		public FieldElement xy2d;

		public GroupElementPreComp(FieldElement yplusx, FieldElement yminusx, FieldElement xy2d)
		{
			this.yplusx = yplusx;
			this.yminusx = yminusx;
			this.xy2d = xy2d;
		}
	} ;

	internal struct GroupElementCached
	{
		public FieldElement YplusX;
		public FieldElement YminusX;
		public FieldElement Z;
		public FieldElement T2d;
	} ;
}
