// See https://aka.ms/new-console-template for more information

using System.Text;

Console.WriteLine("Hello, World!");

var path = @"C:\Users\mtmk\src\nkeys.net\NATS.NKeys\NaCl";
var files = Directory.GetFiles(path, "*.cs", SearchOption.AllDirectories);

foreach (var file in files)
{
    var lines = File.ReadAllLines(file);
    var newLines = new StringBuilder();

    newLines.AppendLine("""
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

                        """);
    var firstNonEmptyLineFound = false;
    foreach (var line in lines.Where(l => !l.StartsWith("#pragma")))
    {
        if (string.IsNullOrWhiteSpace(line) && !firstNonEmptyLineFound)
        {
            continue;
        }

        firstNonEmptyLineFound = true;

        newLines.AppendLine(line);
    }

    File.WriteAllText(file, newLines.ToString());
}
