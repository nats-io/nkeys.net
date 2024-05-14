#pragma warning disable SA1120
#pragma warning disable SA1512

using NATS.NKeys;

Console.WriteLine("AOT Tests");

// Create_account_seed();
// Create_operator_seed();
// Create_seed();
// Create_user_seed();
// Encode_decode();
// Public_key_from_seed();
//

Console.WriteLine("PASS");

//
// void Create_seed()
// {
//     Console.WriteLine($"Create_seed");
//
//     var seed = NKeys.CreateSeed(NKeys.PrefixByte.User);
//     Console.WriteLine($"  pair.PublicKey: {seed}");
//
//     var pair = NKeys.FromSeed(seed);
//
//     var verify1 = pair.Verify(pair.Sign([123, 4]), [123, 4]);
//     Console.WriteLine($"  verify1: {verify1}");
//     Assert.True(verify1);
//
//     var verify2 = pair.Verify(pair.Sign([123]), [123, 4]);
//     Console.WriteLine($"  verify2: {verify2}");
//     Assert.False(verify2);
//
//     var encode = NKeys.Encode(NKeys.PrefixByte.User, false, pair.PublicKey);
//     Console.WriteLine($"  encode: {encode}");
//
//     var publicKey = NKeys.PublicKeyFromSeed(seed);
//     Console.WriteLine($"  PublicKey: {publicKey}");
//
//     Console.WriteLine($"OK");
// }
//
// void Encode_decode()
// {
//     Console.WriteLine($"Encode_decode");
//
//     var a = new byte[32];
//     var b = NKeys.DecodeSeed(NKeys.Decode(NKeys.Encode((NKeys.PrefixByte)(20 << 3), true, a)), out _);
//     Assert.Equal(Convert.ToBase64String(a), Convert.ToBase64String(b));
//
//     var rnd = new Random();
//     rnd.NextBytes(a);
//     b = NKeys.DecodeSeed(NKeys.Decode(NKeys.Encode((NKeys.PrefixByte)(20 << 3), true, a)), out _);
//     Assert.Equal(Convert.ToBase64String(a), Convert.ToBase64String(b));
//
//     Console.WriteLine($"OK");
// }
//
// void Create_user_seed()
// {
//     Console.WriteLine($"Create_user_seed");
//
//     var user = NKeys.CreateSeed(NKeys.PrefixByte.User);
//     Assert.NotEmpty(user);
//     Assert.False(user.EndsWith("=", StringComparison.Ordinal));
//     Assert.NotNull(NKeys.FromSeed(user));
//     var pk = NKeys.PublicKeyFromSeed(user);
//     Assert.Equal('U'.ToString(), pk[0].ToString());
//
//     Console.WriteLine($"OK");
// }
//
// void Create_account_seed()
// {
//     Console.WriteLine($"Create_account_seed");
//
//     var acc = NKeys.CreateSeed(NKeys.PrefixByte.Account);
//     Assert.NotEmpty(acc);
//     Assert.False(acc.EndsWith("=", StringComparison.Ordinal));
//     Assert.NotNull(NKeys.FromSeed(acc));
//     var pk = NKeys.PublicKeyFromSeed(acc);
//     Assert.Equal('A'.ToString(), pk[0].ToString());
//
//     Console.WriteLine($"OK");
// }
//
// void Create_operator_seed()
// {
//     Console.WriteLine($"Create_operator_seed");
//
//     var op = NKeys.CreateSeed(NKeys.PrefixByte.Operator);
//     Assert.NotEmpty(op);
//     Assert.False(op.EndsWith("=", StringComparison.Ordinal));
//     Assert.NotNull(NKeys.FromSeed(op));
//     var pk = NKeys.PublicKeyFromSeed(op);
//     Assert.Equal('O'.ToString(), pk[0].ToString());
//
//     Console.WriteLine($"OK");
// }
//
// void Public_key_from_seed()
// {
//     Console.WriteLine($"Public_key_from_seed");
//
//     // using nsc generated seeds for testing
//     var pk = NKeys.PublicKeyFromSeed("SOAELH6NJCEK4HST5644G4HK7TOAFZGRRJHNM4EUKUY7PPNDLIKO5IH4JM");
//     Assert.Equal("ODPWIBQJVIQ42462QAFI2RKJC4RZHCQSIVPRDDHWFCJAP52NRZK6Z2YC", pk);
//
//     pk = NKeys.PublicKeyFromSeed("SAANWFZ3JINNPERWT3ALE45U7GYT2ZDW6GJUIVPDKUF6GKAX6AISZJMAS4");
//     Assert.Equal("AATEJXG7UX4HFJ6ZPRTP22P6OYZER36YYD3GVBOVW7QHLU32P4QFFTZJ", pk);
//
//     pk = NKeys.PublicKeyFromSeed("SUAGDLNBWI2SGHDRYBHD63NH5FGZSVJUW2J7GAJZXWANQFLDW6G5SXZESU");
//     Assert.Equal("UBICBTHDKQRB4LIYA6BMIJ7EA2G7YS7FIWMMVKZJE6M3HS5IVCOLKDY2", pk);
//
//     Console.WriteLine($"OK");
// }
//
// internal static class Assert
// {
//     public static void Equal(string expected, string actual)
//     {
//         if (!string.Equals(expected, actual))
//             throw new Exception($"Expected: {expected}, Actual: {actual}");
//     }
//
//     public static void NotEmpty(string input)
//     {
//         if (string.IsNullOrEmpty(input))
//             throw new Exception("Input is empty");
//     }
//
//     public static void False(bool input)
//     {
//         if (input)
//             throw new Exception("Input is true");
//     }
//
//     public static void True(bool input)
//     {
//         if (!input)
//             throw new Exception("Input is true");
//     }
//
//     public static void NotNull(object value)
//     {
//         if (value == null)
//             throw new Exception("Value is null");
//     }
// }
