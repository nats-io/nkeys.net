using System.Security.Cryptography;
using System.Text.Json.Nodes;
using NATS.NKeys;

Console.Error.WriteLine("Generating test data...");

using var rng = RandomNumberGenerator.Create();

var testData = new JsonObject();
var xkeysTestData = new JsonArray();

for (var i = 0; i < 100; i++)
{
    var test = new JsonObject();

    var kp1 = KeyPair.CreatePair(PrefixByte.Curve);
    var pk1 = kp1.GetPublicKey();
    test["seed1"] = kp1.GetSeed();
    test["pk1"] = pk1;

    var kp2 = KeyPair.CreatePair(PrefixByte.Curve);
    var pk2 = kp2.GetPublicKey();
    test["seed2"] = kp2.GetSeed();
    test["pk2"] = pk2;

    var data = new byte[1 + (i * 100)];
    rng.GetBytes(data);
    test["text"] = Convert.ToBase64String(data);

    var seal = kp1.Seal(data, pk2);
    test["cypher_text"] = Convert.ToBase64String(seal);

    var open = kp2.Open(seal, pk1);
    test["open_text"] = Convert.ToBase64String(open);

    xkeysTestData.Add(test);
}

testData["xkeys"] = xkeysTestData;

Console.WriteLine(testData);

Console.Error.WriteLine("bye");
