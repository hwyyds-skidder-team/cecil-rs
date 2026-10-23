using System;
using System.Collections.Generic;
using System.IO;
using dnlib.DotNet;

// Eager reference/signature materialization, with an iterative identity-bounded
// traversal. CA/security remain raw bytes like cecil's read model. No external
// assembly resolution, symbols or writing occurs.
static class DnlibProbe {
    sealed class ProbeLimitException : Exception {
        public ProbeLimitException(string message) : base(message) { }
    }
    sealed class Walker {
        readonly HashSet<object> visited = new HashSet<object>(ReferenceEqualityComparer.Instance);
        readonly Queue<object> pending = new Queue<object>();
        long workLeft;
        public int Methods;

        public Walker(int bytes) { workLeft = Math.Max(4096L, (long)bytes * 32); }
        void Charge() { if (--workLeft < 0) throw new ProbeLimitException("traversal limit exceeded"); }
        public void Add(object value) {
            if (value == null) return;
            Charge();
            if (visited.Add(value)) pending.Enqueue(value);
        }
        static void Name(UTF8String value) { GC.KeepAlive(value?.String); }
        public void Drain() {
            while (pending.Count != 0) {
                var value = pending.Dequeue(); Charge();
                if (value is TypeDef type) {
                    Name(type.Name); Name(type.Namespace); Add(type.BaseType); Add(type.DeclaringType);
                    GC.KeepAlive(type.ClassLayout);
                    foreach (var item in type.Interfaces) Add(item);
                    foreach (var item in type.GenericParameters) Add(item);
                    foreach (var item in type.Fields) Add(item);
                    foreach (var item in type.Properties) Add(item);
                    foreach (var item in type.Events) Add(item);
                    foreach (var item in type.Methods) Add(item);
                    foreach (var item in type.NestedTypes) Add(item);
                } else if (value is FieldDef field) {
                    Name(field.Name); Add(field.FieldSig); Add(field.Constant); Add(field.MarshalType); Add(field.ImplMap);
                    GC.KeepAlive(field.FieldOffset); GC.KeepAlive(field.InitialValue);
                } else if (value is PropertyDef property) {
                    Name(property.Name); Add(property.PropertySig); Add(property.Constant);
                    foreach (var item in property.GetMethods) Add(item);
                    foreach (var item in property.SetMethods) Add(item);
                    foreach (var item in property.OtherMethods) Add(item);
                } else if (value is EventDef evt) {
                    Name(evt.Name); Add(evt.EventType); Add(evt.AddMethod); Add(evt.RemoveMethod); Add(evt.InvokeMethod);
                    foreach (var item in evt.OtherMethods) Add(item);
                } else if (value is MethodDef method) {
                    Methods++; Name(method.Name); Add(method.MethodSig); Add(method.ImplMap);
                    foreach (var item in method.GenericParameters) Add(item);
                    foreach (var item in method.ParamDefs) Add(item);
                    foreach (var item in method.Overrides) { Add(item.MethodBody); Add(item.MethodDeclaration); }
                    var body = method.Body;
                    if (body != null) {
                        foreach (var ins in body.Instructions) Add(ins.Operand);
                        foreach (var local in body.Variables) Add(local.Type);
                        foreach (var handler in body.ExceptionHandlers) Add(handler.CatchType);
                    }
                } else if (value is ParamDef param) {
                    Name(param.Name); Add(param.Constant); Add(param.MarshalType);
                } else if (value is GenericParam generic) {
                    Name(generic.Name); GC.KeepAlive(generic.Flags); GC.KeepAlive(generic.Number);
                    foreach (var item in generic.GenericParamConstraints) Add(item);
                } else if (value is GenericParamConstraint constraint) Add(constraint.Constraint);
                else if (value is InterfaceImpl implementation) Add(implementation.Interface);
                else if (value is TypeSpec spec) Add(spec.TypeSig);
                else if (value is TypeRef reference) {
                    Name(reference.Name); Name(reference.Namespace); Add(reference.ResolutionScope);
                } else if (value is MethodSpec specMethod) { Add(specMethod.Method); Add(specMethod.GenericInstMethodSig); }
                else if (value is MemberRef member) { Name(member.Name); Add(member.Class); Add(member.Signature); }
                else if (value is StandAloneSig standalone) Add(standalone.Signature);
                else if (value is CallingConventionSig signature) {
                    if (signature is MethodBaseSig methodSig) {
                        Add(methodSig.RetType);
                        foreach (var item in methodSig.Params) Add(item);
                        if (methodSig.ParamsAfterSentinel != null) foreach (var item in methodSig.ParamsAfterSentinel) Add(item);
                    } else if (signature is FieldSig fieldSig) Add(fieldSig.Type);
                    else if (signature is LocalSig locals) foreach (var item in locals.Locals) Add(item);
                    else if (signature is GenericInstMethodSig inst) foreach (var item in inst.GenericArguments) Add(item);
                } else if (value is TypeSig signatureType) {
                    if (signatureType is GenericInstSig inst) {
                        Add(inst.GenericType); foreach (var item in inst.GenericArguments) Add(item);
                    } else if (signatureType is FnPtrSig function) Add(function.Signature);
                    else if (signatureType is ModifierSig modifier) Add(modifier.Modifier);
                    else if (signatureType is TypeDefOrRefSig named) Add(named.TypeDefOrRef);
                    Add(signatureType.Next);
                } else if (value is AssemblyRef assembly) {
                    Name(assembly.Name); Name(assembly.Culture); GC.KeepAlive(assembly.PublicKeyOrToken);
                } else if (value is ModuleRef module) Name(module.Name);
                else if (value is Constant constant) GC.KeepAlive(constant.Value);
                else if (value is ImplMap map) { Name(map.Name); Add(map.Module); GC.KeepAlive(map.Attributes); }
                GC.KeepAlive(value);
            }
        }
    }

    static uint Rows(uint count, int bytes) {
        if (count > (long)bytes * 2) throw new ProbeLimitException("table-row limit exceeded");
        return count;
    }
    static void Name(UTF8String value) { GC.KeepAlive(value?.String); }
    static int Read(ModuleDefMD module, int bytes) {
        var walker = new Walker(bytes);
        Name(module.Name); Name(module.Assembly?.Name); Name(module.Assembly?.Culture);
        foreach (var type in module.Types) walker.Add(type);
        // Independent row enumeration includes unused references/signatures,
        // not only records reachable from TypeDef or method bodies.
        for (uint rid = 1; rid <= Rows(module.TablesStream.TypeDefTable.Rows, bytes); rid++) walker.Add(module.ResolveTypeDef(rid));
        for (uint rid = 1; rid <= Rows(module.TablesStream.FieldTable.Rows, bytes); rid++) walker.Add(module.ResolveField(rid));
        for (uint rid = 1; rid <= Rows(module.TablesStream.MethodTable.Rows, bytes); rid++) walker.Add(module.ResolveMethod(rid));
        for (uint rid = 1; rid <= Rows(module.TablesStream.ParamTable.Rows, bytes); rid++) walker.Add(module.ResolveParam(rid));
        for (uint rid = 1; rid <= Rows(module.TablesStream.PropertyTable.Rows, bytes); rid++) walker.Add(module.ResolveProperty(rid));
        for (uint rid = 1; rid <= Rows(module.TablesStream.EventTable.Rows, bytes); rid++) walker.Add(module.ResolveEvent(rid));
        for (uint rid = 1; rid <= Rows(module.TablesStream.TypeRefTable.Rows, bytes); rid++) walker.Add(module.ResolveTypeRef(rid));
        for (uint rid = 1; rid <= Rows(module.TablesStream.TypeSpecTable.Rows, bytes); rid++) walker.Add(module.ResolveTypeSpec(rid));
        for (uint rid = 1; rid <= Rows(module.TablesStream.MemberRefTable.Rows, bytes); rid++) walker.Add(module.ResolveMemberRef(rid));
        for (uint rid = 1; rid <= Rows(module.TablesStream.MethodSpecTable.Rows, bytes); rid++) walker.Add(module.ResolveMethodSpec(rid));
        for (uint rid = 1; rid <= Rows(module.TablesStream.StandAloneSigTable.Rows, bytes); rid++) walker.Add(module.ResolveStandAloneSig(rid));
        for (uint rid = 1; rid <= Rows(module.TablesStream.GenericParamTable.Rows, bytes); rid++) walker.Add(module.ResolveGenericParam(rid));
        for (uint rid = 1; rid <= Rows(module.TablesStream.GenericParamConstraintTable.Rows, bytes); rid++) walker.Add(module.ResolveGenericParamConstraint(rid));
        for (uint rid = 1; rid <= Rows(module.TablesStream.InterfaceImplTable.Rows, bytes); rid++) walker.Add(module.ResolveInterfaceImpl(rid));
        for (uint rid = 1; rid <= Rows(module.TablesStream.ConstantTable.Rows, bytes); rid++) walker.Add(module.ResolveConstant(rid));
        for (uint rid = 1; rid <= Rows(module.TablesStream.ImplMapTable.Rows, bytes); rid++) walker.Add(module.ResolveImplMap(rid));
        foreach (var reference in module.GetAssemblyRefs()) walker.Add(reference);
        foreach (var reference in module.GetModuleRefs()) walker.Add(reference);
        foreach (var exported in module.ExportedTypes) { Name(exported.TypeName); Name(exported.TypeNamespace); walker.Add(exported.Implementation); }
        foreach (var resource in module.Resources) {
            Name(resource.Name);
            if (resource is EmbeddedResource embedded) GC.KeepAlive(embedded.CreateReader().ToArray());
        }
        for (uint rid = 1; rid <= Rows(module.TablesStream.FieldMarshalTable.Rows, bytes); rid++) {
            if (!module.TablesStream.TryReadFieldMarshalRow(rid, out var row)) throw new BadImageFormatException("marshal row");
            var owner = module.ResolveHasFieldMarshal(row.Parent);
            walker.Add(owner); walker.Add(owner?.MarshalType); GC.KeepAlive(module.BlobStream.Read(row.NativeType));
        }
        // CA argument decoding can resolve external enum types. Read all raw
        // rows/blobs and constructor signatures, as cecil retains opaque data.
        for (uint rid = 1; rid <= Rows(module.TablesStream.CustomAttributeTable.Rows, bytes); rid++) {
            if (!module.TablesStream.TryReadCustomAttributeRow(rid, out var row)) throw new BadImageFormatException("custom attribute row");
            walker.Add(module.ResolveCustomAttributeType(row.Type)); GC.KeepAlive(module.BlobStream.Read(row.Value));
        }
        for (uint rid = 1; rid <= Rows(module.TablesStream.DeclSecurityTable.Rows, bytes); rid++) {
            if (!module.TablesStream.TryReadDeclSecurityRow(rid, out var row)) throw new BadImageFormatException("security row");
            GC.KeepAlive(row.Action); GC.KeepAlive(module.BlobStream.Read(row.PermissionSet));
        }
        walker.Drain();
        return walker.Methods;
    }
    static void Main() {
        string path;
        while ((path = Console.ReadLine()) != null) {
            try {
                var bytes = File.ReadAllBytes(path);
                using (var module = ModuleDefMD.Load(bytes, new ModuleCreationOptions { TryToLoadPdbFromDisk = false })) {
                    Console.WriteLine("ok\t" + Read(module, bytes.Length));
                }
            } catch (ProbeLimitException error) {
                // Harness resource cutoffs are not dnlib parse rejections.
                Console.WriteLine("limit\t" + error.Message);
            } catch (Exception error) {
                Console.WriteLine("error\t" + error.GetType().Name + ": " + error.Message.Replace('\n', ' ').Replace('\r', ' ').Replace('\t', ' '));
            }
        }
    }
}
