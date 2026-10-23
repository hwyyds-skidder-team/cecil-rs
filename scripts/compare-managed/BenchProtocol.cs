using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;

sealed class Counts
{
    public int Types, Methods, Fields, Properties, Events, Attributes, Bodies, Instructions, Locals, Handlers;
    public string Json() => string.Format(CultureInfo.InvariantCulture,
        "{{\"types\":{0},\"methods\":{1},\"fields\":{2},\"properties\":{3},\"events\":{4},\"attributes\":{5},\"bodies\":{6},\"instructions\":{7},\"locals\":{8},\"handlers\":{9}}}",
        Types, Methods, Fields, Properties, Events, Attributes, Bodies, Instructions, Locals, Handlers);
}

static class BenchProtocol
{
    public static void Measure(string implementation, string version, string mode, int inputBytes,
        Counts counts, string coverage, string[] args, Action operation)
    {
        int samples = args.Length > 2 ? int.Parse(args[2]) : 11;
        double sampleMs = args.Length > 3 ? double.Parse(args[3], CultureInfo.InvariantCulture) : 120;
        double warmupMs = args.Length > 4 ? double.Parse(args[4], CultureInfo.InvariantCulture) : 800;
        if (samples < 1 || sampleMs <= 0 || warmupMs <= 0) throw new ArgumentException("invalid durations");
        GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
        var clock = Stopwatch.StartNew(); int warmupOps = 0;
        while (clock.Elapsed.TotalMilliseconds < warmupMs) { operation(); warmupOps++; }
        double estimate = clock.Elapsed.TotalMilliseconds / warmupOps;
        int iterations = Math.Max(1, Math.Min(1000000, (int)Math.Ceiling(sampleMs / estimate)));
        var values = new List<string>();
        for (int s = 0; s < samples; s++)
        {
            clock.Restart();
            for (int i = 0; i < iterations; i++) operation();
            values.Add((clock.Elapsed.TotalMilliseconds * 1000 / iterations).ToString("F6", CultureInfo.InvariantCulture));
        }
        Console.WriteLine("{\"implementation\":\"" + implementation + "\",\"version\":\"" + version + "\",\"mode\":\"" + mode
            + "\",\"input_bytes\":" + inputBytes + ",\"iterations_per_sample\":" + iterations + ",\"warmup_ops\":" + warmupOps
            + ",\"counts\":" + counts.Json() + ",\"access_coverage\":" + coverage + ",\"samples_us\":[" + string.Join(",", values) + "]}");
    }

    public static void Validation(string implementation, string version, int inputBytes, int outputBytes, Counts counts, string coverage)
        => Console.WriteLine("{\"implementation\":\"" + implementation + "\",\"version\":\"" + version
            + "\",\"mode\":\"validate\",\"input_bytes\":" + inputBytes + ",\"output_bytes\":" + outputBytes
            + ",\"counts\":" + counts.Json() + ",\"access_coverage\":" + coverage + "}");
}
