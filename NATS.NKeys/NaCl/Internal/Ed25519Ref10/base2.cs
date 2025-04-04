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
    internal static partial class LookupTables
    {
        internal static readonly GroupElementPreComp[] Base2 = new GroupElementPreComp[]{
            new GroupElementPreComp(
                new FieldElement( 25967493,-14356035,29566456,3660896,-12694345,4014787,27544626,-11754271,-6079156,2047605 ),
                new FieldElement( -12545711,934262,-2722910,3049990,-727428,9406986,12720692,5043384,19500929,-15469378 ),
            new FieldElement( -8738181,4489570,9688441,-14785194,10184609,-12363380,29287919,11864899,-24514362,-4438546 )
            ),
            new GroupElementPreComp(
            new FieldElement( 15636291,-9688557,24204773,-7912398,616977,-16685262,27787600,-14772189,28944400,-1550024 ),
            new FieldElement( 16568933,4717097,-11556148,-1102322,15682896,-11807043,16354577,-11775962,7689662,11199574 ),
            new FieldElement( 30464156,-5976125,-11779434,-15670865,23220365,15915852,7512774,10017326,-17749093,-9920357 )
             ),
            new GroupElementPreComp(
            new FieldElement( 10861363,11473154,27284546,1981175,-30064349,12577861,32867885,14515107,-15438304,10819380 ),
            new FieldElement( 4708026,6336745,20377586,9066809,-11272109,6594696,-25653668,12483688,-12668491,5581306 ),
            new FieldElement( 19563160,16186464,-29386857,4097519,10237984,-4348115,28542350,13850243,-23678021,-15815942 )
             ),
            new GroupElementPreComp(
                new FieldElement( 5153746,9909285,1723747,-2777874,30523605,5516873,19480852,5230134,-23952439,-15175766 ),
                new FieldElement( -30269007,-3463509,7665486,10083793,28475525,1649722,20654025,16520125,30598449,7715701 ),
            new FieldElement( 28881845,14381568,9657904,3680757,-20181635,7843316,-31400660,1370708,29794553,-1409300 )
             ),
            new GroupElementPreComp(
            new FieldElement( -22518993,-6692182,14201702,-8745502,-23510406,8844726,18474211,-1361450,-13062696,13821877 ),
            new FieldElement( -6455177,-7839871,3374702,-4740862,-27098617,-10571707,31655028,-7212327,18853322,-14220951 ),
            new FieldElement( 4566830,-12963868,-28974889,-12240689,-7602672,-2830569,-8514358,-10431137,2207753,-3209784 )
             ),
            new GroupElementPreComp(
            new FieldElement( -25154831,-4185821,29681144,7868801,-6854661,-9423865,-12437364,-663000,-31111463,-16132436 ),
            new FieldElement( 25576264,-2703214,7349804,-11814844,16472782,9300885,3844789,15725684,171356,6466918 ),
            new FieldElement( 23103977,13316479,9739013,-16149481,817875,-15038942,8965339,-14088058,-30714912,16193877 )
             ),
            new GroupElementPreComp(
            new FieldElement( -33521811,3180713,-2394130,14003687,-16903474,-16270840,17238398,4729455,-18074513,9256800 ),
            new FieldElement( -25182317,-4174131,32336398,5036987,-21236817,11360617,22616405,9761698,-19827198,630305 ),
            new FieldElement( -13720693,2639453,-24237460,-7406481,9494427,-5774029,-6554551,-15960994,-2449256,-14291300 )
             ),
            new GroupElementPreComp(
            new FieldElement( -3151181,-5046075,9282714,6866145,-31907062,-863023,-18940575,15033784,25105118,-7894876 ),
            new FieldElement( -24326370,15950226,-31801215,-14592823,-11662737,-5090925,1573892,-2625887,2198790,-15804619 ),
            new FieldElement( -3099351,10324967,-2241613,7453183,-5446979,-2735503,-13812022,-16236442,-32461234,-12290683 )
             )
        };
    }
}
