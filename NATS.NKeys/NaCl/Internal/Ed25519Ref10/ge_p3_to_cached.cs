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
		r = p
		*/
		public static void ge_p3_to_cached(out GroupElementCached r, ref GroupElementP3 p)
		{
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_add(out r.YplusX, ref p.Y, ref p.X);
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_sub(out r.YminusX, ref p.Y, ref p.X);
			r.Z = p.Z;
			NATS.NKeys.NaCl.Internal.Ed25519Ref10.FieldOperations.fe_mul(out r.T2d, ref p.T, ref NATS.NKeys.NaCl.Internal.Ed25519Ref10.LookupTables.d2);
		}
	}
}
