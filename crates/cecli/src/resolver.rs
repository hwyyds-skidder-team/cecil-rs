//! Assembly name resolution: locates the backing image file for an
//! `AssemblyRef` row.
//!
//! Port of Mono.Cecil `BaseAssemblyResolver` / `DefaultAssemblyResolver`
//! (`Mono.Cecil/BaseAssemblyResolver.cs`, `Mono.Cecil/DefaultAssemblyResolver.cs`).
//!
//! # Deviations from Mono.Cecil (documented v1 limitations)
//!
//! * **No framework / GAC probing.** Cecil falls back to the running
//!   framework directory, a hardcoded `mscorlib` version ladder, and the
//!   GAC (`GetAssemblyInGac`). This port replaces all of that with
//!   *explicit search directories* supplied by the caller
//!   ([`DefaultAssemblyResolver::add_search_directory`]). A fresh resolver
//!   still seeds `"."` and `"bin"` like Cecil's constructor.
//! * **First directory wins.** When several search directories contain a
//!   same-named candidate, Cecil reads each image and picks the highest
//!   assembly `Version`. Reading PE images here would require the PE layer
//!   inside the resolver; v1 instead resolves against the *first* search
//!   directory that contains any matching candidate file, without comparing
//!   versions. Callers control precedence by directory insertion order.
//! * **Extension set.** Cecil probes `.dll` + `.exe` for managed references
//!   and `.winmd` + `.dll` for Windows Runtime references. This port always
//!   probes `.dll`, `.exe`, `.netmodule`, `.winmd` in that fixed order,
//!   covering every module kind the facade can read.
//! * No resolution cache: Cecil caches resolved `AssemblyDefinition`s keyed
//!   by full name. Cache ownership belongs to the future facade reader, so
//!   this resolver stays stateless apart from its directory list.

use std::path::{Path, PathBuf};

use crate::model::types::AssemblyNameReference;
use cecli_core::{Error, Result};

/// Candidate file extensions probed per directory, in priority order.
/// Covers managed DLLs/exes, netmodules, and Windows Runtime metadata.
const CANDIDATE_EXTENSIONS: [&str; 4] = [".dll", ".exe", ".netmodule", ".winmd"];

/// Resolves an [`AssemblyNameReference`] to the path of its backing image.
///
/// Port of Mono.Cecil `IAssemblyResolver`; returns the located file instead
/// of opening it, so the facade reader stays in charge of parsing.
pub trait AssemblyResolver {
    /// Locates the image file for `reference`.
    ///
    /// Returns [`Error::Unsupported`] with a message naming the assembly
    /// when it cannot be found (Cecil's `AssemblyResolutionException`).
    fn resolve(&mut self, reference: &AssemblyNameReference) -> Result<PathBuf>;
}

/// Search-directory based resolver.
///
/// Port of Mono.Cecil `DefaultAssemblyResolver` minus the definition cache
/// and framework/GAC fallbacks (see [module docs](self)).
#[derive(Debug, Clone, Default)]
pub struct DefaultAssemblyResolver {
    directories: Vec<PathBuf>,
}

impl DefaultAssemblyResolver {
    /// Creates a resolver seeded with Cecil's default search paths
    /// (`"."` and `"bin"`).
    pub fn new() -> Self {
        DefaultAssemblyResolver {
            directories: vec![PathBuf::from("."), PathBuf::from("bin")],
        }
    }

    /// Appends `directory` to the search list (Cecil `AddSearchDirectory`).
    /// Earlier directories take precedence during resolution.
    pub fn add_search_directory<P: AsRef<Path>>(&mut self, p: P) {
        self.directories.push(p.as_ref().to_path_buf());
    }

    /// Splits an environment variable into search directories.
    ///
    /// Mirrors Cecil's `MONO_GAC_PREFIX` handling: entries are separated by the
    /// platform search-path delimiter (`';'` on Windows, `':'` elsewhere) so
    /// drive letters like `C:\` survive; empty entries are skipped.
    /// A missing variable is silently ignored.
    pub fn add_search_directory_from_env_var(&mut self, var: &str) {
        let Some(value) = std::env::var_os(var) else {
            return;
        };
        const SEP: char = if cfg!(windows) { ';' } else { ':' };
        for part in value.to_string_lossy().split(SEP) {
            if part.is_empty() {
                continue;
            }
            self.directories.push(PathBuf::from(part));
        }
    }

    /// Removes `directory` from the search list if present
    /// (Cecil `RemoveSearchDirectory`).
    pub fn remove_search_directory<P: AsRef<Path>>(&mut self, p: P) {
        self.directories.retain(|d| d != p.as_ref());
    }

    /// Current search directories in probe order (Cecil
    /// `GetSearchDirectories`).
    pub fn get_search_directories(&self) -> &[PathBuf] {
        &self.directories
    }
}

impl AssemblyResolver for DefaultAssemblyResolver {
    fn resolve(&mut self, reference: &AssemblyNameReference) -> Result<PathBuf> {
        resolve_in_dirs(reference, &self.directories)
    }
}

/// Resolves `reference` against an explicit directory list.
///
/// Directories are probed in order; within a directory the extension order
/// is `.dll`, `.exe`, `.netmodule`, `.winmd`. The first existing candidate
/// file wins. On error, names the missing assembly.
pub fn resolve_in_dirs(reference: &AssemblyNameReference, dirs: &[PathBuf]) -> Result<PathBuf> {
    // Cecil `Mixin.CheckName`: an empty reference name cannot be resolved.
    if reference.name.is_empty() {
        return Err(Error::Argument(
            "assembly name reference has an empty name".to_string(),
        ));
    }

    for dir in dirs {
        if let Some(path) = probe_directory(dir, &reference.name) {
            return Ok(path);
        }
    }

    Err(Error::Unsupported(format!(
        "assembly '{}' not found",
        reference.name
    )))
}

/// Searches one directory for `<name><ext>` candidates in extension-priority
/// order. Falls back to a case-insensitive directory scan when no
/// exact-spelling file exists, mirroring Windows' case-insensitive file
/// system semantics (a `foo.DLL` satisfies a request for `foo.dll`).
fn probe_directory(dir: &Path, stem: &str) -> Option<PathBuf> {
    // Fast path: exact-spelling candidates in priority order.
    for ext in CANDIDATE_EXTENSIONS {
        let candidate = dir.join(format!("{stem}{ext}"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    // Slow path: case-insensitive match against actual directory entries.
    let wanted: Vec<String> = CANDIDATE_EXTENSIONS
        .iter()
        .map(|ext| format!("{}{ext}", stem.to_ascii_lowercase()))
        .collect();

    let mut best: Option<(usize, PathBuf)> = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let lower = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if let Some(priority) = wanted.iter().position(|w| *w == lower) {
            let takes_slot = match &best {
                Some((best_priority, _)) => priority < *best_priority,
                None => true,
            };
            if takes_slot {
                best = Some((priority, path));
            }
        }
    }
    best.map(|(_, path)| path)
}

/// Minimal reader configuration carrier, later consumed by the facade's
/// `AssemblyDefinition::read*` entry points. Port of the fields Mono.Cecil's
/// `ReaderParameters` carries that matter to this phase.
#[derive(Default)]
pub struct ReaderParameters {
    /// Resolver used for nested `AssemblyRef` lookups while reading; when
    /// `None` the facade installs its own [`DefaultAssemblyResolver`]
    /// (Cecil: `BaseAssemblyResolver.GetAssembly` defaults it to `this`).
    pub assembly_resolver: Option<Box<dyn AssemblyResolver>>,
    /// Whether to load debug symbols alongside the assembly
    /// (Cecil `ReaderParameters.ReadSymbols`).
    pub read_symbols: bool,
}

impl ReaderParameters {
    /// Creates parameters with no custom resolver and symbol loading off.
    pub fn new() -> Self {
        ReaderParameters::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::AssemblyNameReference;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// Serializes tests that mutate the process environment.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn next_unique_tag() -> String {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        format!("cecli_resolver_test_{nanos}_{n}")
    }

    /// Creates a unique empty temp directory and returns its path.
    fn make_temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(tag);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn cleanup_dir(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    fn reference(name: &str) -> AssemblyNameReference {
        AssemblyNameReference::new(name)
    }

    #[test]
    fn finds_assembly_in_temp_dir() {
        let dir = make_temp_dir(&next_unique_tag());
        std::fs::write(dir.join("foo.dll"), b"MZ fake").expect("write foo.dll");

        let mut resolver = DefaultAssemblyResolver::new();
        resolver.add_search_directory(&dir);

        let path = resolver.resolve(&reference("foo")).expect("resolved");
        assert_eq!(path, dir.join("foo.dll"));
        assert!(path.is_file());

        cleanup_dir(&dir);
    }

    #[test]
    fn first_directory_with_candidate_wins() {
        let first = make_temp_dir(&next_unique_tag());
        let second = make_temp_dir(&next_unique_tag());
        std::fs::write(first.join("bar.dll"), b"first").expect("write first");
        std::fs::write(second.join("bar.dll"), b"second").expect("write second");

        let mut resolver = DefaultAssemblyResolver::new();
        // Deliberately add the second dir first: insertion order rules.
        resolver.add_search_directory(&second);
        resolver.add_search_directory(&first);

        let path = resolver.resolve(&reference("bar")).expect("resolved");
        assert_eq!(path, second.join("bar.dll"));

        cleanup_dir(&first);
        cleanup_dir(&second);
    }

    #[test]
    fn probes_every_extension_in_priority_order() {
        for (name, ext) in [("baz", ".exe"), ("qux", ".netmodule"), ("cor", ".winmd")] {
            let dir = make_temp_dir(&next_unique_tag());
            std::fs::write(dir.join(format!("{name}{ext}")), b"MZ fake").expect("write");

            let mut resolver = DefaultAssemblyResolver::new();
            resolver.add_search_directory(&dir);
            let path = resolver.resolve(&reference(name)).expect("resolved");
            assert_eq!(path, dir.join(format!("{name}{ext}")));

            cleanup_dir(&dir);
        }
    }

    #[test]
    fn case_insensitive_fallback_matches_windows_semantics() {
        let dir = make_temp_dir(&next_unique_tag());
        std::fs::write(dir.join("MixedCase.EXE"), b"MZ fake").expect("write");

        let mut resolver = DefaultAssemblyResolver::new();
        resolver.add_search_directory(&dir);
        let path = resolver.resolve(&reference("mixedcase")).expect("resolved");
        assert_eq!(
            path.file_name().unwrap().to_string_lossy().to_lowercase(),
            "mixedcase.exe"
        );

        cleanup_dir(&dir);
    }

    #[test]
    fn env_var_splits_on_platform_delimiter() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Semicolon-separated absolute paths (plus empty entries to skip).
        let var = format!("CECLI_TEST_DIRS_{}", next_unique_tag());
        let d1 = make_temp_dir(&next_unique_tag());
        let d2 = make_temp_dir(&next_unique_tag());
        std::fs::write(d1.join("split.dll"), b"d1").expect("write d1");
        std::fs::write(d2.join("split.dll"), b"d2").expect("write d2");
        std::env::set_var(&var, format!("{};;{}", d1.display(), d2.display()));

        let mut resolver = DefaultAssemblyResolver::new();
        resolver.add_search_directory_from_env_var(&var);

        let dirs = resolver.get_search_directories();
        assert_eq!(
            &dirs[dirs.len() - 2..],
            &[d1.clone(), d2.clone()],
            "env entries appended in order, empties dropped"
        );
        let path = resolver.resolve(&reference("split")).expect("resolved");
        assert_eq!(path, d1.join("split.dll"));

        std::env::remove_var(&var);
        cleanup_dir(&d1);
        cleanup_dir(&d2);

        // Relative entries separated by the platform delimiter; on Windows the
        // separator is ';' (drive letters must survive), elsewhere ':'.
        let colon_var = format!("CECLI_TEST_COLON_DIRS_{}", next_unique_tag());
        if cfg!(windows) {
            std::env::set_var(&colon_var, ";relative_docs;;bin2");
        } else {
            std::env::set_var(&colon_var, ":relative_docs::bin2");
        }
        let mut colon_resolver = DefaultAssemblyResolver::new();
        colon_resolver.add_search_directory_from_env_var(&colon_var);
        assert_eq!(
            colon_resolver.get_search_directories(),
            &[
                PathBuf::from("."),
                PathBuf::from("bin"),
                PathBuf::from("relative_docs"),
                PathBuf::from("bin2")
            ]
        );
        std::env::remove_var(&colon_var);
    }

    #[test]
    fn missing_env_var_is_a_no_op() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let before = DefaultAssemblyResolver::new();
        let mut resolver = DefaultAssemblyResolver::new();
        resolver.add_search_directory_from_env_var("CECLI_TEST_DEFINITELY_UNSET_VAR_42");
        assert_eq!(resolver.get_search_directories(), before.get_search_directories());
    }

    #[test]
    fn missing_assembly_yields_err_naming_it() {
        let dir = make_temp_dir(&next_unique_tag());

        let mut resolver = DefaultAssemblyResolver::new();
        resolver.add_search_directory(&dir);

        let err = resolver
            .resolve(&reference("no_such_asm"))
            .expect_err("must fail");
        let msg = err.to_string();
        assert!(msg.contains("no_such_asm"), "message names assembly: {msg}");

        cleanup_dir(&dir);
    }

    #[test]
    fn resolve_in_dirs_reports_missing_reference() {
        let err = resolve_in_dirs(&reference("ghost"), &[]).expect_err("must fail");
        let msg = err.to_string();
        assert!(msg.contains("ghost"), "message names assembly: {msg}");
    }

    #[test]
    fn empty_reference_name_is_rejected() {
        let err = resolve_in_dirs(&reference(""), &[]).expect_err("must fail");
        assert!(matches!(err, Error::Argument(_)));
    }

    #[test]
    fn remove_search_directory_drops_entry() {
        let dir = make_temp_dir(&next_unique_tag());
        std::fs::write(dir.join("gone.dll"), b"x").expect("write");

        let mut resolver = DefaultAssemblyResolver::new();
        resolver.add_search_directory(&dir);
        resolver.remove_search_directory(&dir);
        assert!(!resolver.get_search_directories().contains(&dir));
        assert!(resolver.resolve(&reference("gone")).is_err());

        cleanup_dir(&dir);
    }

    #[test]
    fn reader_parameters_default_and_trait_object_use() {
        let params = ReaderParameters::default();
        assert!(!params.read_symbols);
        assert!(params.assembly_resolver.is_none());

        // Trait object round-trip through ReaderParameters.
        let mut boxed: Box<dyn AssemblyResolver> =
            Box::new(<DefaultAssemblyResolver as Default>::default());
        boxed
            .resolve(&reference("anything"))
            .expect_err("no search dirs configured");
        let mut params = ReaderParameters::new();
        params.read_symbols = true;
        params.assembly_resolver = Some(boxed);
        assert!(params.read_symbols && params.assembly_resolver.is_some());
    }
}
