using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Serialized;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Metadata.Tables;

static class AsmResolverBench
{
    const string Version = "6.0.1";
    const string Coverage = "{\"metadata\":\"definitions/signatures/generics/constraints/interfaces/constants/marshal/layout/pinvoke/overrides/resources\",\"utf8_names\":\"ToString decoded, including names/namespaces/cultures/nested resolution scopes\",\"signature_traversal\":\"force lazy getters once per object identity per Load\",\"il\":\"all instructions/resolved operand references/locals/handlers\",\"custom_attributes\":\"all raw rows, copied blob payloads, constructor signatures and uninitialized serialized signature wrappers; no argument decoding\",\"security\":\"raw permission-set blobs\",\"writer\":\"default managed writer, preserving serialized attribute blobs\",\"symbols\":false,\"external_resolution_requested\":false}";

    static HashSet<object> visited;
    static void Name(AsmResolver.Utf8String value) => GC.KeepAlive(value?.ToString());

    static void Signature(CallingConventionSignature signature)
    {
        if (signature == null || !visited.Add(signature)) return;
        if (signature is MethodSignatureBase method)
        {
            TypeSignature(method.ReturnType);
            foreach (var p in method.ParameterTypes) TypeSignature(p);
            if (method is MethodSignature m) foreach (var p in m.SentinelParameterTypes) TypeSignature(p);
        }
        else if (signature is FieldSignature field) TypeSignature(field.FieldType);
        else if (signature is GenericInstanceMethodSignature generic) foreach (var a in generic.TypeArguments) TypeSignature(a);
        else if (signature is LocalVariablesSignature locals) foreach (var v in locals.VariableTypes) TypeSignature(v);
        GC.KeepAlive(signature);
    }

    static void TypeSignature(TypeSignature type)
    {
        if (type == null || !visited.Add(type)) return;
        if (type is GenericInstanceTypeSignature generic)
        {
            Reference(generic.GenericType);
            foreach (var a in generic.TypeArguments) TypeSignature(a);
        }
        else if (type is FunctionPointerTypeSignature function) Signature(function.Signature);
        else if (type is CustomModifierTypeSignature modifier) Reference(modifier.ModifierType);
        else if (type is TypeDefOrRefSignature named) Reference(named.Type);
        if (type is TypeSpecificationSignature spec) TypeSignature(spec.BaseType);
    }

    static void Reference(object reference)
    {
        if (reference == null) return;
        if (reference is CallingConventionSignature signature) { Signature(signature); return; }
        if (!(reference is TypeSpecification || reference is TypeReference || reference is MethodSpecification || reference is MemberReference || reference is StandAloneSignature || reference is AssemblyReference || reference is ModuleReference))
        {
            GC.KeepAlive(reference);
            return;
        }
        if (!visited.Add(reference)) return;
        if (reference is TypeSpecification spec) TypeSignature(spec.Signature);
        else if (reference is TypeReference type)
        {
            Name(type.Name); Name(type.Namespace); Reference(type.Scope);
        }
        else if (reference is MethodSpecification generic)
        {
            Reference(generic.Method); Signature(generic.Signature);
        }
        else if (reference is MemberReference member)
        {
            Name(member.Name); Reference(member.Parent); Signature(member.Signature);
        }
        else if (reference is StandAloneSignature standalone) Reference(standalone.Signature);
        else if (reference is AssemblyReference assembly) { Name(assembly.Name); Name(assembly.Culture); GC.KeepAlive(assembly.PublicKeyOrToken); }
        else if (reference is ModuleReference module) Name(module.Name);
        GC.KeepAlive(reference);
    }

    static void Generics(IHasGenericParameters owner)
    {
        foreach (var g in owner.GenericParameters)
        {
            Name(g.Name);
            foreach (var constraint in g.Constraints) Reference(constraint.Constraint);
        }
    }

    static void Type(TypeDefinition t, Counts c)
    {
        c.Types++; Name(t.Name); Name(t.Namespace); Reference(t.BaseType);
        GC.KeepAlive(t.ClassLayout); Generics(t);
        foreach (var i in t.Interfaces) Reference(i.Interface);
        foreach (var f in t.Fields)
        {
            c.Fields++; Name(f.Name); Signature(f.Signature); GC.KeepAlive(f.Constant?.Value);
            GC.KeepAlive(f.MarshalDescriptor); GC.KeepAlive(f.FieldOffset); GC.KeepAlive(f.FieldRva); GC.KeepAlive(f.ImplementationMap);
        }
        foreach (var p in t.Properties)
        {
            c.Properties++; Name(p.Name); Signature(p.Signature); GC.KeepAlive(p.Constant?.Value);
            GC.KeepAlive(p.Semantics); GC.KeepAlive(p.GetMethod); GC.KeepAlive(p.SetMethod);
        }
        foreach (var e in t.Events)
        {
            c.Events++; Name(e.Name); Reference(e.EventType); GC.KeepAlive(e.Semantics);
            GC.KeepAlive(e.AddMethod); GC.KeepAlive(e.RemoveMethod); GC.KeepAlive(e.FireMethod);
        }
        foreach (var o in t.MethodImplementations) { Reference(o.Body); Reference(o.Declaration); }
        foreach (var m in t.Methods)
        {
            c.Methods++; Name(m.Name); Signature(m.Signature); Generics(m); GC.KeepAlive(m.ImplementationMap);
            foreach (var p in m.ParameterDefinitions)
            {
                Name(p.Name); GC.KeepAlive(p.Constant?.Value); GC.KeepAlive(p.MarshalDescriptor);
            }
            if (m.CilMethodBody is { } b)
            {
                c.Bodies++; c.Instructions += b.Instructions.Count; c.Locals += b.LocalVariables.Count; c.Handlers += b.ExceptionHandlers.Count;
                foreach (var i in b.Instructions) Reference(i.Operand);
                foreach (var v in b.LocalVariables) TypeSignature(v.VariableType);
                foreach (var h in b.ExceptionHandlers) Reference(h.ExceptionType);
            }
        }
        foreach (var nested in t.NestedTypes) Type(nested, c);
    }

    static Counts Load(ModuleDefinition module)
    {
        visited = new HashSet<object>(ReferenceEqualityComparer.Instance);
        var c = new Counts(); Name(module.Name); Name(module.Assembly?.Name); Name(module.Assembly?.Culture);
        foreach (var reference in module.AssemblyReferences) Reference(reference);
        foreach (var reference in module.ModuleReferences) Reference(reference);
        foreach (var exported in module.ExportedTypes) { Name(exported.Name); Name(exported.Namespace); GC.KeepAlive(exported.Implementation); }
        foreach (var resource in module.Resources)
        {
            Name(resource.Name);
            if (resource.Implementation == null) GC.KeepAlive(resource.GetData());
        }
        foreach (var t in module.TopLevelTypes) Type(t, c);
        var serialized = (SerializedModuleDefinition)module;
        var streams = serialized.ReaderContext.Streams;
        var attributes = streams.TablesStream.GetTable<CustomAttributeRow>();
        for (int i = 0; i < attributes.Count; i++)
        {
            var row = attributes[i]; c.Attributes++;
            var attribute = (CustomAttribute)module.LookupMember(new MetadataToken(TableIndex.CustomAttribute, (uint)i + 1));
            Reference(attribute.Constructor); GC.KeepAlive(attribute.Signature);
            GC.KeepAlive(streams.BlobStream.GetBlobByIndex(row.Value));
        }
        foreach (var row in streams.TablesStream.GetTable<SecurityDeclarationRow>())
            GC.KeepAlive(streams.BlobStream.GetBlobByIndex(row.PermissionSet));
        visited = null;
        return c;
    }

    static ModuleDefinition Read(byte[] bytes) => ModuleDefinition.FromBytes(bytes);

    [MethodImpl(MethodImplOptions.NoInlining)]
    static void Operation(string mode, byte[] bytes, ModuleDefinition loaded)
    {
        if (mode == "write")
        {
            using (var output = new MemoryStream()) { loaded.Write(output); GC.KeepAlive(output.Length); }
        }
        else
        {
            var module = Read(bytes); GC.KeepAlive(Load(module));
            if (mode == "roundtrip") using (var output = new MemoryStream()) { module.Write(output); GC.KeepAlive(output.Length); }
            else if (mode != "read") throw new ArgumentException("unknown mode: " + mode);
            GC.KeepAlive(module);
        }
    }

    static int Main(string[] args)
    {
        try
        {
            var mode = args[0]; var bytes = File.ReadAllBytes(args[1]); var loaded = Read(bytes); var counts = Load(loaded);
            if (mode == "validate")
            {
                using (var output = new MemoryStream())
                {
                    loaded.Write(output); var encoded = output.ToArray();
                    if (args.Length > 5) File.WriteAllBytes(args[5], encoded);
                    if (Load(Read(encoded)).Json() != counts.Json()) throw new Exception("counts changed on roundtrip");
                    BenchProtocol.Validation("AsmResolver", Version, bytes.Length, encoded.Length, counts, Coverage);
                }
            }
            else BenchProtocol.Measure("AsmResolver", Version, mode, bytes.Length, counts, Coverage, args, () => Operation(mode, bytes, loaded));
            GC.KeepAlive(loaded);
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine(e); return 1; }
    }
}
