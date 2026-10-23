using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using dnlib.DotNet;

static class DnlibBench
{
    const string Version = "4.5.0";
    const string Coverage = "{\"metadata\":\"definitions/signatures/generics/constraints/interfaces/constants/marshal/layout/pinvoke/overrides/resources\",\"utf8_names\":\"String decoded, including names/namespaces/cultures/nested resolution scopes\",\"signature_traversal\":\"force lazy getters once per object identity per Load\",\"il\":\"all instructions/resolved operand references/locals/handlers\",\"custom_attributes\":\"all raw rows, copied blob payloads, resolved constructor signatures; no argument decoding in Load\",\"security\":\"raw permission-set blobs\",\"writer\":\"default managed writer; its native implementation may decode custom attributes\",\"symbols\":false,\"external_resolution_requested\":false}";

    static HashSet<object> visited;
    static void Name(UTF8String value) => GC.KeepAlive(value?.String);

    static void Signature(CallingConventionSig signature)
    {
        if (signature == null || !visited.Add(signature)) return;
        if (signature is MethodBaseSig method)
        {
            TypeSignature(method.RetType);
            foreach (var p in method.Params) TypeSignature(p);
            if (method.ParamsAfterSentinel != null) foreach (var p in method.ParamsAfterSentinel) TypeSignature(p);
        }
        else if (signature is FieldSig field) TypeSignature(field.Type);
        else if (signature is GenericInstMethodSig generic) foreach (var a in generic.GenericArguments) TypeSignature(a);
        GC.KeepAlive(signature);
    }

    static void TypeSignature(TypeSig type)
    {
        if (type == null || !visited.Add(type)) return;
        if (type is GenericInstSig generic)
        {
            TypeSignature(generic.GenericType);
            foreach (var a in generic.GenericArguments) TypeSignature(a);
        }
        else if (type is FnPtrSig function) Signature(function.Signature);
        else if (type is ModifierSig modifier) Reference(modifier.Modifier);
        else if (type is TypeDefOrRefSig named) Reference(named.TypeDefOrRef);
        if (type.Next != null) TypeSignature(type.Next);
    }

    static void Reference(object reference)
    {
        if (reference == null) return;
        if (reference is CallingConventionSig signature) { Signature(signature); return; }
        if (!(reference is TypeSpec || reference is TypeRef || reference is MethodSpec || reference is MemberRef || reference is AssemblyRef || reference is ModuleRef))
        {
            GC.KeepAlive(reference);
            return;
        }
        if (!visited.Add(reference)) return;
        if (reference is TypeSpec spec) TypeSignature(spec.TypeSig);
        else if (reference is TypeRef type)
        {
            Name(type.Name); Name(type.Namespace); Reference(type.ResolutionScope);
        }
        else if (reference is MethodSpec generic)
        {
            Reference(generic.Method); Signature(generic.GenericInstMethodSig);
        }
        else if (reference is MemberRef member)
        {
            Name(member.Name); Reference(member.Class); Signature(member.Signature);
        }
        else if (reference is AssemblyRef assembly) { Name(assembly.Name); Name(assembly.Culture); GC.KeepAlive(assembly.PublicKeyOrToken); }
        else if (reference is ModuleRef module) Name(module.Name);
        GC.KeepAlive(reference);
    }

    static void Generics(IList<GenericParam> parameters)
    {
        foreach (var g in parameters)
        {
            Name(g.Name);
            foreach (var constraint in g.GenericParamConstraints) Reference(constraint.Constraint);
        }
    }

    static void Type(TypeDef t, Counts c)
    {
        c.Types++; Name(t.Name); Name(t.Namespace); Reference(t.BaseType);
        GC.KeepAlive(t.ClassLayout); Generics(t.GenericParameters);
        foreach (var i in t.Interfaces) Reference(i.Interface);
        foreach (var f in t.Fields)
        {
            c.Fields++; Name(f.Name); Signature(f.FieldSig); GC.KeepAlive(f.Constant?.Value);
            GC.KeepAlive(f.MarshalType); GC.KeepAlive(f.FieldOffset); GC.KeepAlive(f.InitialValue); GC.KeepAlive(f.ImplMap);
        }
        foreach (var p in t.Properties)
        {
            c.Properties++; Name(p.Name); Signature(p.PropertySig); GC.KeepAlive(p.Constant?.Value);
            GC.KeepAlive(p.GetMethods); GC.KeepAlive(p.SetMethods); GC.KeepAlive(p.OtherMethods);
        }
        foreach (var e in t.Events)
        {
            c.Events++; Name(e.Name); Reference(e.EventType); GC.KeepAlive(e.AddMethod);
            GC.KeepAlive(e.RemoveMethod); GC.KeepAlive(e.InvokeMethod); GC.KeepAlive(e.OtherMethods);
        }
        foreach (var m in t.Methods)
        {
            c.Methods++; Name(m.Name); Signature(m.MethodSig); Generics(m.GenericParameters); GC.KeepAlive(m.ImplMap);
            foreach (var p in m.ParamDefs)
            {
                Name(p.Name); GC.KeepAlive(p.Constant?.Value); GC.KeepAlive(p.MarshalType);
            }
            foreach (var o in m.Overrides) { Reference(o.MethodBody); Reference(o.MethodDeclaration); }
            if (m.Body is { } b)
            {
                c.Bodies++; c.Instructions += b.Instructions.Count; c.Locals += b.Variables.Count; c.Handlers += b.ExceptionHandlers.Count;
                foreach (var i in b.Instructions) Reference(i.Operand);
                foreach (var v in b.Variables) TypeSignature(v.Type);
                foreach (var h in b.ExceptionHandlers) Reference(h.CatchType);
            }
        }
        foreach (var nested in t.NestedTypes) Type(nested, c);
    }

    static Counts Load(ModuleDefMD module)
    {
        visited = new HashSet<object>(ReferenceEqualityComparer.Instance);
        var c = new Counts(); Name(module.Name); Name(module.Assembly?.Name); Name(module.Assembly?.Culture);
        foreach (var reference in module.GetAssemblyRefs()) Reference(reference);
        foreach (var reference in module.GetModuleRefs()) Reference(reference);
        foreach (var exported in module.ExportedTypes) { Name(exported.TypeName); Name(exported.TypeNamespace); GC.KeepAlive(exported.Implementation); }
        foreach (var resource in module.Resources)
        {
            Name(resource.Name);
            if (resource is EmbeddedResource embedded) GC.KeepAlive(embedded.CreateReader().ToArray());
        }
        foreach (var t in module.Types) Type(t, c);
        // Enumerating dnlib.CustomAttributes decodes arguments eagerly. Read its
        // public raw metadata interface instead, matching Cecil.GetBlob() and
        // Rust's constructor + opaque bytes model, without external enum lookup.
        for (uint rid = 1; rid <= module.TablesStream.CustomAttributeTable.Rows; rid++)
        {
            if (!module.TablesStream.TryReadCustomAttributeRow(rid, out var row)) throw new BadImageFormatException("custom attribute row");
            c.Attributes++; Reference(module.ResolveCustomAttributeType(row.Type)); GC.KeepAlive(module.BlobStream.Read(row.Value));
        }
        for (uint rid = 1; rid <= module.TablesStream.DeclSecurityTable.Rows; rid++)
        {
            if (!module.TablesStream.TryReadDeclSecurityRow(rid, out var row)) throw new BadImageFormatException("security row");
            GC.KeepAlive(module.BlobStream.Read(row.PermissionSet));
        }
        visited = null;
        return c;
    }

    static ModuleDefMD Read(byte[] bytes, ModuleContext context)
        => ModuleDefMD.Load(bytes, new ModuleCreationOptions(context) { TryToLoadPdbFromDisk = false });

    [MethodImpl(MethodImplOptions.NoInlining)]
    static void Operation(string mode, byte[] bytes, ModuleDefMD loaded, ModuleContext context)
    {
        if (mode == "write")
        {
            using (var output = new MemoryStream()) { loaded.Write(output); GC.KeepAlive(output.Length); }
        }
        else
        {
            using (var module = Read(bytes, context))
            {
                GC.KeepAlive(Load(module));
                if (mode == "roundtrip") using (var output = new MemoryStream()) { module.Write(output); GC.KeepAlive(output.Length); }
                else if (mode != "read") throw new ArgumentException("unknown mode: " + mode);
            }
        }
    }

    static int Main(string[] args)
    {
        try
        {
            var mode = args[0]; var bytes = File.ReadAllBytes(args[1]);
            var context = ModuleDef.CreateModuleContext();
            var resolver = (AssemblyResolver)context.AssemblyResolver;
            resolver.PreSearchPaths.Add(Path.GetDirectoryName(Path.GetFullPath(args[1])));
            resolver.PreSearchPaths.Add(Path.GetDirectoryName(typeof(object).Assembly.Location));
            resolver.PreSearchPaths.Add(Path.Combine(AppContext.BaseDirectory, "..", "..", "roslyn", "tasks", "netcore", "bincore"));
            using (var loaded = Read(bytes, context))
            {
                var counts = Load(loaded);
                if (mode == "validate")
                {
                    using (var output = new MemoryStream())
                    {
                        loaded.Write(output); var encoded = output.ToArray();
                        if (args.Length > 5) File.WriteAllBytes(args[5], encoded);
                        using (var after = Read(encoded, context))
                            if (Load(after).Json() != counts.Json()) throw new Exception("counts changed on roundtrip");
                        BenchProtocol.Validation("dnlib", Version, bytes.Length, encoded.Length, counts, Coverage);
                    }
                }
                else BenchProtocol.Measure("dnlib", Version, mode, bytes.Length, counts, Coverage, args, () => Operation(mode, bytes, loaded, context));
            }
            resolver.Clear();
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine(e); return 1; }
    }
}
