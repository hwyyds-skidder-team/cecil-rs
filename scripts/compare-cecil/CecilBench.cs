using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;

static class CecilBench
{
    sealed class Counts
    {
        public int Types, Methods, Fields, Properties, Events, Attributes, Bodies, Instructions, Locals, Handlers;
        public string Json() => string.Format(CultureInfo.InvariantCulture,
            "{{\"types\":{0},\"methods\":{1},\"fields\":{2},\"properties\":{3},\"events\":{4},\"attributes\":{5},\"bodies\":{6},\"instructions\":{7},\"locals\":{8},\"handlers\":{9}}}",
            Types, Methods, Fields, Properties, Events, Attributes, Bodies, Instructions, Locals, Handlers);
    }

    static void Attributes(ICustomAttributeProvider p, Counts c)
    {
        foreach (var a in p.CustomAttributes) { c.Attributes++; GC.KeepAlive(a.Constructor); GC.KeepAlive(a.GetBlob()); }
    }

    static void Generics(IGenericParameterProvider p, Counts c)
    {
        foreach (var g in p.GenericParameters)
        {
            Attributes(g, c);
            foreach (var constraint in g.Constraints) { GC.KeepAlive(constraint.ConstraintType); Attributes(constraint, c); }
        }
    }

    static void Security(ISecurityDeclarationProvider p)
    {
        foreach (var d in p.SecurityDeclarations) GC.KeepAlive(d.GetBlob());
    }

    static void Type(TypeDefinition t, Counts c)
    {
        c.Types++; GC.KeepAlive(t.BaseType); GC.KeepAlive(t.ClassSize); GC.KeepAlive(t.PackingSize);
        Attributes(t, c); Generics(t, c); Security(t);
        foreach (var i in t.Interfaces) { GC.KeepAlive(i.InterfaceType); Attributes(i, c); }
        foreach (var f in t.Fields)
        {
            c.Fields++; GC.KeepAlive(f.FieldType); GC.KeepAlive(f.Constant); GC.KeepAlive(f.MarshalInfo);
            GC.KeepAlive(f.Offset); GC.KeepAlive(f.InitialValue); Attributes(f, c);
        }
        foreach (var p in t.Properties)
        {
            c.Properties++; GC.KeepAlive(p.PropertyType); GC.KeepAlive(p.Constant);
            GC.KeepAlive(p.GetMethod); GC.KeepAlive(p.SetMethod); GC.KeepAlive(p.OtherMethods);
            foreach (var parameter in p.Parameters) GC.KeepAlive(parameter.ParameterType);
            Attributes(p, c);
        }
        foreach (var e in t.Events)
        {
            c.Events++; GC.KeepAlive(e.EventType); GC.KeepAlive(e.AddMethod); GC.KeepAlive(e.RemoveMethod);
            GC.KeepAlive(e.InvokeMethod); GC.KeepAlive(e.OtherMethods); Attributes(e, c);
        }
        foreach (var m in t.Methods)
        {
            c.Methods++; GC.KeepAlive(m.ReturnType); Attributes(m, c); Generics(m, c); Security(m);
            foreach (var parameter in m.Parameters)
            {
                GC.KeepAlive(parameter.ParameterType); GC.KeepAlive(parameter.Constant);
                GC.KeepAlive(parameter.MarshalInfo); Attributes(parameter, c);
            }
            var r = m.MethodReturnType; GC.KeepAlive(r.Constant); GC.KeepAlive(r.MarshalInfo); Attributes(r, c);
            GC.KeepAlive(m.Overrides); GC.KeepAlive(m.PInvokeInfo);
            if (m.HasBody)
            {
                var b = m.Body; c.Bodies++; c.Instructions += b.Instructions.Count;
                c.Locals += b.Variables.Count; c.Handlers += b.ExceptionHandlers.Count;
            }
        }
        foreach (var nested in t.NestedTypes) Type(nested, c);
    }

    static Counts Load(AssemblyDefinition asm)
    {
        var c = new Counts(); Attributes(asm, c); Security(asm);
        var m = asm.MainModule; Attributes(m, c);
        GC.KeepAlive(m.AssemblyReferences); GC.KeepAlive(m.ModuleReferences); GC.KeepAlive(m.ExportedTypes);
        foreach (var resource in m.Resources)
            if (resource is EmbeddedResource embedded) GC.KeepAlive(embedded.GetResourceData());
        foreach (var t in m.Types) Type(t, c);
        return c;
    }

    // Validation only. Token/RID/heap identities and physical layout never enter
    // this representation. Each reader compares its own representation across
    // the original input and both writers' outputs; hashes are NOT compared
    // between Rust and Cecil because their object models expose different data.
    sealed class Semantics
    {
        readonly List<string> metadata = new List<string>();
        readonly List<string> bodies = new List<string>();

        static string Row(string tag, params object[] values)
        {
            var b = new StringBuilder(tag);
            foreach (var value in values)
            {
                var text = value == null ? "<null>" : Convert.ToString(value, CultureInfo.InvariantCulture);
                b.Append('|').Append(text.Length).Append(':').Append(text);
            }
            return b.ToString();
        }

        static string Join<T>(IEnumerable<T> values, Func<T, string> convert)
        {
            var result = new StringBuilder();
            foreach (var value in values) result.Append(Row("item", convert(value)));
            return result.ToString();
        }

        static string Scope(IMetadataScope scope)
        {
            if (scope is AssemblyNameReference a) return a.FullName;
            if (scope is ModuleReference m) return Row("module", m.Name);
            if (scope is ModuleDefinition d) return Row("module", d.Name);
            return scope == null ? "none" : throw new Exception("unknown type scope: " + scope);
        }

        static string Ty(TypeReference t)
        {
            if (t == null) return "none";
            if (t is GenericParameter g) return Row(g.Type == GenericParameterType.Method ? "mvar" : "var", g.Position);
            if (t is GenericInstanceType i) return Row("generic", Ty(i.ElementType), Join(i.GenericArguments, Ty));
            if (t is ArrayType a) return Row("array", Ty(a.ElementType), a.IsVector,
                Join(a.Dimensions, d => Row("dimension", d.LowerBound, d.UpperBound)));
            if (t is IModifierType mod) return Row(t.GetType().Name, Ty(mod.ModifierType), Ty(mod.ElementType));
            if (t is FunctionPointerType pointer) return Row("fnptr", Sig(pointer));
            if (t is TypeSpecification spec) return Row(t.GetType().Name, Ty(spec.ElementType));
            return Row("type", t.FullName, Scope(t.Scope));
        }

        static string Sig(IMethodSignature s)
            => Row("signature", s.HasThis, s.ExplicitThis, (int)s.CallingConvention,
                s is IGenericParameterProvider g ? g.GenericParameters.Count : 0,
                Ty(s.ReturnType), Join(s.Parameters, p => Ty(p.ParameterType)));

        static string Method(MethodReference m)
        {
            if (m == null) return "none";
            if (m is GenericInstanceMethod i) return Row("method-spec", Method(i.ElementMethod), Join(i.GenericArguments, Ty));
            return Row("method", Ty(m.DeclaringType), m.Name, Sig(m));
        }

        static string Constant(bool has, object value)
        {
            if (!has) return "absent";
            if (value == null) return "null";
            if (value is float f) return Row("f32", BitConverter.SingleToInt32Bits(f).ToString("x8"));
            if (value is double d) return Row("f64", BitConverter.DoubleToInt64Bits(d).ToString("x16"));
            return Row(value.GetType().Name, value);
        }

        void Attributes(string owner, ICustomAttributeProvider p)
        {
            foreach (var a in p.CustomAttributes) metadata.Add(Row("attribute", owner, Method(a.Constructor), Convert.ToHexString(a.GetBlob())));
        }

        void Security(string owner, ISecurityDeclarationProvider p)
        {
            foreach (var d in p.SecurityDeclarations) metadata.Add(Row("security", owner, (int)d.Action, Convert.ToHexString(d.GetBlob())));
        }

        void Generics(string owner, IGenericParameterProvider p)
        {
            foreach (var g in p.GenericParameters)
            {
                var key = Row("generic", owner, g.Position);
                metadata.Add(Row(key, g.Name, (int)g.Attributes)); Attributes(key, g);
                foreach (var c in g.Constraints)
                {
                    var constraint = Row("constraint", key, Ty(c.ConstraintType));
                    metadata.Add(constraint); Attributes(constraint, c);
                }
            }
        }

        void Parameter(string owner, ParameterDefinition p)
        {
            metadata.Add(Row("parameter", owner, p.Name, (int)p.Attributes, Constant(p.HasConstant, p.Constant)));
            Attributes(owner, p);
        }

        void Type(TypeDefinition t)
        {
            var key = t.FullName;
            metadata.Add(Row("type", key, (int)t.Attributes, Ty(t.BaseType), t.PackingSize, t.ClassSize));
            Attributes(key, t); Generics(key, t); Security(key, t);
            foreach (var i in t.Interfaces)
            {
                var owner = Row("interface", key, Ty(i.InterfaceType)); metadata.Add(owner); Attributes(owner, i);
            }
            foreach (var f in t.Fields)
            {
                var owner = Row("field", key, f.Name, Ty(f.FieldType));
                metadata.Add(Row(owner, (int)f.Attributes, Constant(f.HasConstant, f.Constant), f.Offset, Convert.ToHexString(f.InitialValue)));
                Attributes(owner, f);
            }
            foreach (var p in t.Properties)
            {
                var owner = Row("property", key, p.Name, p.HasThis, Ty(p.PropertyType), Join(p.Parameters, v => Ty(v.ParameterType)));
                metadata.Add(Row(owner, (int)p.Attributes, Constant(p.HasConstant, p.Constant), Method(p.GetMethod), Method(p.SetMethod), Join(p.OtherMethods, Method)));
                Attributes(owner, p);
            }
            foreach (var e in t.Events)
            {
                var owner = Row("event", key, e.Name, Ty(e.EventType));
                metadata.Add(Row(owner, (int)e.Attributes, Method(e.AddMethod), Method(e.RemoveMethod), Method(e.InvokeMethod), Join(e.OtherMethods, Method)));
                Attributes(owner, e);
            }
            foreach (var m in t.Methods)
            {
                var owner = Method(m);
                metadata.Add(Row(owner, (int)m.Attributes, (int)m.ImplAttributes,
                    m.HasPInvokeInfo ? Row("pinvoke", (int)m.PInvokeInfo.Attributes, m.PInvokeInfo.EntryPoint, m.PInvokeInfo.Module.Name) : "none"));
                Attributes(owner, m); Generics(owner, m); Security(owner, m);
                var r = m.MethodReturnType;
                metadata.Add(Row("parameter", owner + ":return", r.Name, (int)r.Attributes, Constant(r.HasConstant, r.Constant)));
                Attributes(owner + ":return", r);
                foreach (var p in m.Parameters) Parameter(owner + ":param:" + p.Index, p);
                foreach (var o in m.Overrides) metadata.Add(Row("override", owner, Method(o)));
                if (!m.HasBody) { bodies.Add(Row("no-body", owner)); continue; }
                var b = m.Body; var offsets = new Dictionary<Instruction, int>();
                for (int j = 0; j < b.Instructions.Count; j++) offsets.Add(b.Instructions[j], j);
                Func<Instruction, int> target = i => i == null ? b.Instructions.Count : offsets[i];
                // Different protected regions may move within the EH table;
                // preserve catch/filter precedence for the SAME try region.
                var handlers = new List<ExceptionHandler>(b.ExceptionHandlers);
                handlers.Sort((x, y) => {
                    int order = target(x.TryStart).CompareTo(target(y.TryStart));
                    if (order == 0) order = target(x.TryEnd).CompareTo(target(y.TryEnd));
                    return order != 0 ? order : b.ExceptionHandlers.IndexOf(x).CompareTo(b.ExceptionHandlers.IndexOf(y));
                });
                string Operand(object operand)
                {
                    if (operand == null) return "none";
                    if (operand is Instruction i) return Row("branch", target(i));
                    if (operand is Instruction[] a) return Row("switch", Join(a, i => target(i).ToString(CultureInfo.InvariantCulture)));
                    if (operand is TypeReference type) return Ty(type);
                    if (operand is MethodReference method) return Method(method);
                    if (operand is FieldReference field) return Row("field", Ty(field.DeclaringType), field.Name, Ty(field.FieldType));
                    if (operand is CallSite site) return Row("callsite", Sig(site));
                    if (operand is VariableDefinition variable) return Row("local", variable.Index);
                    if (operand is ParameterDefinition parameter) return Row("argument", parameter.Index);
                    if (operand is float f) return Row("f32", BitConverter.SingleToInt32Bits(f).ToString("x8"));
                    if (operand is double d) return Row("f64", BitConverter.DoubleToInt64Bits(d).ToString("x16"));
                    if (operand is string || operand is sbyte || operand is byte || operand is int || operand is long)
                        return Row(operand.GetType().Name, operand);
                    throw new Exception("unsupported semantic operand: " + operand.GetType());
                }
                bodies.Add(Row("body", owner, b.InitLocals, Join(b.Variables, v => Ty(v.VariableType)),
                    Join(b.Instructions, i => Row(i.OpCode.Name, Operand(i.Operand))),
                    Join(handlers, h => Row("handler", (int)h.HandlerType, target(h.TryStart), target(h.TryEnd),
                        target(h.HandlerStart), target(h.HandlerEnd), h.HandlerType == ExceptionHandlerType.Filter ? target(h.FilterStart) : -1, Ty(h.CatchType)))));
            }
            foreach (var nested in t.NestedTypes) Type(nested);
        }

        public static Semantics Read(AssemblyDefinition asm)
        {
            var s = new Semantics(); var m = asm.MainModule; var a = asm.Name;
            s.metadata.Add(Row("assembly", a.Name, a.Version, a.Culture, Convert.ToHexString(a.PublicKey), (int)a.Attributes));
            s.metadata.Add(Row("module", m.Name, (int)m.Kind, (int)m.Architecture, m.RuntimeVersion));
            s.Attributes("assembly", asm); s.Security("assembly", asm); s.Attributes("module", m);
            if (m.EntryPoint != null) s.metadata.Add(Row("entry", Method(m.EntryPoint)));
            foreach (var reference in m.AssemblyReferences) s.metadata.Add(Row("assembly-ref", reference.FullName, (int)reference.Attributes));
            foreach (var reference in m.ModuleReferences) s.metadata.Add(Row("module-ref", reference.Name));
            foreach (var resource in m.Resources)
            {
                if (resource is EmbeddedResource embedded) s.metadata.Add(Row("embedded", resource.Name, (int)resource.Attributes, Convert.ToHexString(embedded.GetResourceData())));
                else if (resource is LinkedResource linked) s.metadata.Add(Row("linked", resource.Name, (int)resource.Attributes, linked.File));
                else if (resource is AssemblyLinkedResource assembly) s.metadata.Add(Row("assembly-linked", resource.Name, (int)resource.Attributes, assembly.Assembly.FullName));
                else throw new Exception("unknown resource: " + resource);
            }
            foreach (var t in m.Types) s.Type(t);
            s.metadata.Sort(StringComparer.Ordinal); s.bodies.Sort(StringComparer.Ordinal);
            return s;
        }

        static string Hash(List<string> records) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", records)))).ToLowerInvariant();
        public string Json() => "{\"scheme\":\"cecil-model-v1-sha256\",\"metadata\":\"" + Hash(metadata) + "\",\"bodies\":\"" + Hash(bodies) + "\",\"metadata_records\":" + metadata.Count + ",\"body_records\":" + bodies.Count + "}";
        public void Dump(string path) => File.WriteAllText(path, string.Join("\n", metadata) + "\n" + string.Join("\n", bodies), new UTF8Encoding(false));
        public void AssertSame(Semantics after)
        {
            void Compare(string label, List<string> before, List<string> result)
            {
                int i = 0; while (i < before.Count && i < result.Count && before[i] == result[i]) i++;
                if (i != before.Count || i != result.Count)
                {
                    var old = i < before.Count ? before[i] : "<end>"; var updated = i < result.Count ? result[i] : "<end>";
                    int at = 0; while (at < old.Length && at < updated.Length && old[at] == updated[at]) at++;
                    string Context(string value) { int start = Math.Min(value.Length, Math.Max(0, at - 120)); return value.Substring(start, Math.Min(value.Length - start, at + 200 - start)); }
                    throw new Exception("semantic " + label + " changed at record " + i + ", character " + at + ": before " + Context(old) + "; after " + Context(updated));
                }
            }
            Compare("metadata", metadata, after.metadata); Compare("bodies", bodies, after.bodies);
        }
    }

    static AssemblyDefinition Read(byte[] bytes, DefaultAssemblyResolver resolver)
        => AssemblyDefinition.ReadAssembly(new MemoryStream(bytes, false), new ReaderParameters
        { ReadingMode = ReadingMode.Deferred, ReadSymbols = false, AssemblyResolver = resolver });

    [MethodImpl(MethodImplOptions.NoInlining)]
    static void Operation(string mode, byte[] bytes, AssemblyDefinition loaded, DefaultAssemblyResolver resolver)
    {
        if (mode == "write")
        {
            using (var output = new MemoryStream()) { loaded.Write(output); GC.KeepAlive(output.Length); }
        }
        else
        {
            using (var asm = Read(bytes, resolver))
            {
                GC.KeepAlive(Load(asm));
                if (mode == "roundtrip")
                    using (var output = new MemoryStream()) { asm.Write(output); GC.KeepAlive(output.Length); }
                else if (mode != "read") throw new ArgumentException("unknown mode: " + mode);
            }
        }
    }

    static int Main(string[] args)
    {
        try
        {
            var mode = args[0]; var bytes = File.ReadAllBytes(args[1]);
            using (var resolver = new DefaultAssemblyResolver())
            {
                resolver.AddSearchDirectory(Path.GetDirectoryName(typeof(object).Assembly.Location));
                resolver.AddSearchDirectory(Path.GetDirectoryName(Path.GetFullPath(args[1])));
                resolver.AddSearchDirectory(Path.Combine(AppContext.BaseDirectory, "roslyn", "tasks", "netcore", "bincore"));
                resolver.AddSearchDirectory(Path.Combine(AppContext.BaseDirectory, "..", "..", "roslyn", "tasks", "netcore", "bincore"));
                using (var loaded = Read(bytes, resolver))
                {
                    var counts = Load(loaded);
                    if (mode == "validate" || mode == "inspect")
                    {
                        var semantics = Semantics.Read(loaded);
                        if (args.Length > 6) semantics.Dump(args[6]);
                        if (mode == "inspect")
                        {
                            Console.WriteLine("{\"implementation\":\"Mono.Cecil\",\"version\":\"0.11.6\",\"mode\":\"inspect\",\"input_bytes\":" + bytes.Length + ",\"counts\":" + counts.Json() + ",\"semantics\":" + semantics.Json() + "}");
                            return 0;
                        }
                        using (var output = new MemoryStream())
                        {
                            loaded.Write(output); var encoded = output.ToArray();
                            if (args.Length > 5) File.WriteAllBytes(args[5], encoded);
                            using (var after = Read(encoded, resolver))
                            {
                                if (Load(after).Json() != counts.Json()) throw new Exception("counts changed on roundtrip");
                                semantics.AssertSame(Semantics.Read(after));
                            }
                            Console.WriteLine("{\"implementation\":\"Mono.Cecil\",\"version\":\"0.11.6\",\"mode\":\"validate\",\"input_bytes\":" + bytes.Length + ",\"output_bytes\":" + encoded.Length + ",\"counts\":" + counts.Json() + ",\"semantics\":" + semantics.Json() + "}");
                        }
                        return 0;
                    }
                    int samples = args.Length > 2 ? int.Parse(args[2]) : 11;
                    double sampleMs = args.Length > 3 ? double.Parse(args[3], CultureInfo.InvariantCulture) : 120;
                    double warmupMs = args.Length > 4 ? double.Parse(args[4], CultureInfo.InvariantCulture) : 800;
                    if (samples < 1 || sampleMs <= 0 || warmupMs <= 0) throw new ArgumentException("invalid durations");
                    GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
                    var clock = Stopwatch.StartNew(); int warmupOps = 0;
                    while (clock.Elapsed.TotalMilliseconds < warmupMs) { Operation(mode, bytes, loaded, resolver); warmupOps++; }
                    double estimate = clock.Elapsed.TotalMilliseconds / warmupOps;
                    int iterations = Math.Max(1, Math.Min(1000000, (int)Math.Ceiling(sampleMs / estimate)));
                    var values = new List<string>();
                    for (int s = 0; s < samples; s++)
                    {
                        clock.Restart();
                        for (int i = 0; i < iterations; i++) Operation(mode, bytes, loaded, resolver);
                        values.Add((clock.Elapsed.TotalMilliseconds * 1000 / iterations).ToString("F6", CultureInfo.InvariantCulture));
                    }
                    Console.WriteLine("{\"implementation\":\"Mono.Cecil\",\"version\":\"0.11.6\",\"mode\":\"" + mode + "\",\"input_bytes\":" + bytes.Length + ",\"iterations_per_sample\":" + iterations + ",\"warmup_ops\":" + warmupOps + ",\"counts\":" + counts.Json() + ",\"samples_us\":[" + string.Join(",", values) + "]}");
                }
            }
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine(e); return 1; }
    }
}
