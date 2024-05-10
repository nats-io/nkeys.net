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

#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
#pragma warning disable CS1573 // Parameter has no matching param tag in the XML comment (but other parameters do)
#pragma warning disable CS1572 // XML comment has a param tag, but there is no parameter by that name
#pragma warning disable CS8603 // Possible null reference return.
#pragma warning disable SA1303
#pragma warning disable SA1512
#pragma warning disable SA1515
#pragma warning disable SA1119
#pragma warning disable SA1202
#pragma warning disable SA1201
#pragma warning disable SX1309
#pragma warning disable SA1307
#pragma warning disable SA1401

// Borrowed from https://github.com/CryptoManiac/Ed25519

namespace NATS.NKeys.NaCl.Internal.Ed25519Ref10
{
    internal static partial class LookupTables
    {
        internal static FieldElement sqrtm1 = new FieldElement(-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482);
    }
}
