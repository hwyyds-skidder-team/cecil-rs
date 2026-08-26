//! Assembly name resolution: locates the backing image file for an
//! `AssemblyRef` row.
//!
//! Port of Mono.Cecil `BaseAssemblyResolver` / `DefaultAssemblyResolver`
//! (`Mono.Cecil/BaseAssemblyResolver.cs`, `Mono.Cecil/DefaultAssemblyResolver.cs`).
//!
//! # Candidate selection (Cecil parity)
//!
//! Every search directory is scanned for `<stem><ext>` candidates first.
//! Each candidate is then probed by parsing its PE/CLI image and reading the
//! version of its metadata `Assembly` row ([`probe_version`]). Selection:
//!
//! 1. Among candidates whose probed version is `>=` the requested
//!    `(major, minor)` (build and revision of the reference are ignored,
//!    mirroring .NET's major.minor binding floor), the highest full
//!    four-part version wins.
//! 2. When no candidate reaches that floor, the highest overall version
//!    wins ("best effort", like Cecil's retargetable fallback).
//! 3. Ties keep the earlier candidate (directory insertion order, then the
//!    `.dll` > `.exe` > `.netmodule` > `.winmd` extension priority inside a
//!    directory). Version comparison is field-wise lexicographic on
//!    `(major, minor, build, revision)`, identical to Cecil's
//!    `AssemblyNameReference` version ordering. A zero requested version
//!    (e.g. a freshly built [`AssemblyNameReference::new`]) accepts every
//!    candidate, so rule 1 degenerates to "highest overall".
//!
//! Candidates whose version cannot be probed (netmodules have no `Assembly`
//! row; native or corrupt images fail to parse) rank below every probed
//! candidate and serve as last-resort fallbacks so plain module references
//! keep resolving like Cecil's `SearchDirectory` loop.
//!
//! # Deviations from Mono.Cecil (documented v1 limitations)
//!
//! * **No framework / GAC probing.** Cecil falls back to the running
//!   framework directory, a hardcoded `mscorlib` version ladder, and the
//!   GAC (`GetAssemblyInGac`). This port resolves strictly via the explicit
//!   search directories supplied to
//!   [`DefaultAssemblyResolver::add_search_directory`]. The
//!   [`DefaultAssemblyResolver::add_framework_directory`] hook exists only
//!   to mirror Cecil's API shape; registered framework directories are
//!   recorded but never consulted during resolution. A fresh resolver still
//!   seeds `"."` and `"bin"` like Cecil's constructor.
//! * **No resolution cache:** Cecil caches resolved `AssemblyDefinition`s
//!   keyed by full name. Cache ownership belongs to the facade reader, so
//!   this resolver stays stateless apart from its directory lists.
//! * **Extension set.** Cecil probes `.dll` + `.exe` for managed references
//!   and `.winmd` + `.dll` for Windows Runtime references. This port always
//!   probes `.dll`, `.exe`, `.netmodule`, `.winmd` in that fixed order,
//!   covering every module kind the facade can read.

use std::path::{Path, PathBuf};

use crate::model::types::{AssemblyNameReference, Version};
use cecli_core::token::TableIndex;
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
    fn resolve(&self, reference: &AssemblyNameReference) -> Result<PathBuf>;
}

/// Search-directory based resolver.
///
/// Port of Mono.Cecil `DefaultAssemblyResolver` minus the definition cache
/// and framework/GAC probing (see [module docs](self)).
#[derive(Debug, Clone, Default)]
pub struct DefaultAssemblyResolver {
    directories: Vec<PathBuf>,
    /// Mirrors the implicit framework directory list Cecil builds from the
    /// running runtime (`framework_dirs` in `BaseAssemblyResolver.Resolve`).
    /// Carried for API parity only; resolution never consults it because the
    /// Rust port has no host framework to discover.
    framework_directories: Vec<PathBuf>,
}

impl DefaultAssemblyResolver {
    /// Creates a resolver seeded with Cecil's default search paths
    /// (`"."` and `"bin"`).
    pub fn new() -> Self {
        DefaultAssemblyResolver {
            directories: vec![PathBuf::from("."), PathBuf::from("bin")],
            framework_directories: Vec::new(),
        }
    }

    /// Appends `directory` to the search list (Cecil `AddSearchDirectory`).
    /// Earlier directories take precedence when versions tie during
    /// resolution.
    pub fn add_search_directory<P: AsRef<Path>>(&mut self, p: P) {
        self.directories.push(p.as_ref().to_path_buf());
    }

    /// Registers `directory` as a framework directory (Cecil
    /// `AddFrameworkDirectory`-shaped hook).
    ///
    /// **No-op at resolution time:** the Rust port resolves strictly via the
    /// explicit search directories; framework directories are recorded (and
    /// visible through [`Self::get_framework_directories`]) purely to keep
    /// Cecil's API surface available to callers.
    pub fn add_framework_directory<P: AsRef<Path>>(&mut self, p: P) {
        self.framework_directories.push(p.as_ref().to_path_buf());
    }

    /// Registered framework directories, in registration order. These are
    /// never searched; see [`Self::add_framework_directory`].
    pub fn get_framework_directories(&self) -> &[PathBuf] {
        &self.framework_directories
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
    fn resolve(&self, reference: &AssemblyNameReference) -> Result<PathBuf> {
        resolve_in_dirs(reference, &self.directories)
    }
}

/// Resolves `reference` against an explicit directory list.
///
/// All stem-matching candidates across all directories are gathered, then
/// ranked by their probed `Assembly` row version as described in the
/// [module docs](self). On failure the error message names the missing
/// assembly (Cecil `AssemblyResolutionException` wording).
pub fn resolve_in_dirs(reference: &AssemblyNameReference, dirs: &[PathBuf]) -> Result<PathBuf> {
    // Cecil `Mixin.CheckName`: an empty reference name cannot be resolved.
    if reference.name.is_empty() {
        return Err(Error::Argument("assembly name reference has an empty name".to_string()));
    }

    // Gather every candidate across all directories before ranking, so a
    // higher-versioned image in a later directory beats an earlier one.
    let mut versioned: Vec<(PathBuf, Version)> = Vec::new();
    let mut opaque: Vec<PathBuf> = Vec::new();
    for dir in dirs {
        if let Some(path) = probe_directory(dir, &reference.name) {
            match probe_version(&path) {
                Ok(version) => versioned.push((path, version)),
                Err(_) => opaque.push(path),
            }
        }
    }

    if let Some(path) = pick_highest(&versioned, &reference.version) {
        return Ok(path);
    }
    // No probed candidate: fall back to the first unprobed one (extension
    // priority order), keeping netmodule-style references resolvable.
    if let Some((path, _)) = opaque.split_first() {
        return Ok(path.clone());
    }

    Err(Error::Unsupported(format!("Failed to resolve assembly: '{}'", reference.full_name())))
}

/// Picks the winning candidate among `(path, version)` pairs.
///
/// Eligible candidates are those with `version >= (major, minor)` of the
/// request; the highest four-part version wins among them. When nothing is
/// eligible, the highest overall version wins. The earliest candidate wins
/// ties, preserving directory/extension priority.
fn pick_highest(candidates: &[(PathBuf, Version)], requested: &Version) -> Option<PathBuf> {
    let floor = Version::new(requested.major, requested.minor, 0, 0);

    // (eligible?, path, version) of the current winner; `None` while empty.
    let mut best: Option<(bool, &PathBuf, &Version)> = None;
    for (path, version) in candidates {
        let eligible = *version >= floor;
        let takes_over = match best {
            None => true,
            Some((best_eligible, _, best_version)) => match (eligible, best_eligible) {
                // Eligible beats ineligible outright; within a class the
                // strictly higher version wins and ties keep the earlier
                // candidate (directory/extension priority).
                (true, false) => true,
                (false, true) => false,
                _ => *version > *best_version,
            },
        };
        if takes_over {
            best = Some((eligible, path, version));
        }
    }

    best.map(|(_, path, _)| path.clone())
}

/// Reads `path` as a managed PE/CLI image and returns the version of its
/// single `Assembly` metadata row.
///
/// Errors mirror the underlying layers: [`Error::Io`] when the file cannot
/// be read, [`Error::BadImage`] when it is not a managed image or carries no
/// `Assembly` row (netmodules), and metadata-layer errors for malformed
/// roots. Callers treat any error as "candidate without a known version".
pub fn probe_version(path: &Path) -> Result<Version> {
    let data = std::fs::read(path)?;
    let image = cecli_pe::Image::parse(&data)?;

    let (md_rva, md_size) = image.metadata_rva()?;
    let mapped = image.rva(md_rva)?;
    let root = &mapped[..md_size.min(mapped.len())];
    let md = cecli_metadata::MetadataReader::parse(root)?;

    // The Assembly table holds at most one row (ECMA-335 II 22.2); rid 1.
    if md.row_count(TableIndex::Assembly) == 0 {
        return Err(Error::bad_image("image has no Assembly table"));
    }
    let major = md.column(TableIndex::Assembly, 1, 1)? as u16;
    let minor = md.column(TableIndex::Assembly, 1, 2)? as u16;
    let build = md.column(TableIndex::Assembly, 1, 3)? as u16;
    let revision = md.column(TableIndex::Assembly, 1, 4)? as u16;
    Ok(Version::new(major, minor, build, revision))
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

/// Port of Mono.Cecil `ReadingMode`.
///
/// Carried for API parity with Cecil's `ReaderParameters.ReadingMode`.
/// This port always materializes the module eagerly, so [`ReadingMode::Lazy`]
/// and [`ReadingMode::Deferred`] behave exactly like [`ReadingMode::Immediate`];
/// the value is documented as advisory-only until lazy reading lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadingMode {
    /// Parse everything up front (the only behavior this port implements).
    #[default]
    Immediate,
    /// Advisory: defer member bodies. Currently treated as [`ReadingMode::Immediate`].
    Lazy,
    /// Advisory: defer whole-module parsing. Currently treated as [`ReadingMode::Immediate`].
    Deferred,
}

/// Hook mirroring Mono.Cecil `ISymbolReaderProvider`: given the resolved
/// assembly image path, produce the raw bytes of its symbol store (portable
/// or native `.pdb`, Mono `.mdb`) or `None` when none should be loaded.
pub trait SymbolReaderProvider {
    /// Locates the symbol data accompanying the image at `image_path`.
    fn get_symbol_reader(&self, image_path: &Path) -> Result<Option<Vec<u8>>>;
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
    /// Cecil `ReaderParameters.ReadingMode`. Advisory only: this port reads
    /// eagerly regardless of the value (see [`ReadingMode`]).
    pub reading_mode: ReadingMode,
    /// Symbol-store source used when [`Self::read_symbols`] is set
    /// (Cecil `ReaderParameters.SymbolReaderProvider`). When `None`, the
    /// facade falls back to its default same-stem lookup.
    pub symbol_reader_provider: Option<Box<dyn SymbolReaderProvider>>,
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

    /// Copies a fixture assembly into `dir` under `stem.dll` and returns the
    /// destination path. Used to obtain genuinely parseable candidates with
    /// distinct probed versions.
    fn copy_fixture_as(dir: &Path, fixture: &str, stem: &str) -> PathBuf {
        let dest = dir.join(format!("{stem}.dll"));
        std::fs::copy(cecli_core::fixtures_dir().join(fixture), &dest).expect("copy fixture");
        dest
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
    fn first_directory_with_candidate_wins_for_unprobed_candidates() {
        let first = make_temp_dir(&next_unique_tag());
        let second = make_temp_dir(&next_unique_tag());
        std::fs::write(first.join("bar.dll"), b"first").expect("write first");
        std::fs::write(second.join("bar.dll"), b"second").expect("write second");

        let mut resolver = DefaultAssemblyResolver::new();
        // Neither file parses as a managed image, so both stay unprobed and
        // insertion order decides.
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
        assert_eq!(path.file_name().unwrap().to_string_lossy().to_lowercase(), "mixedcase.exe");

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

        let err = resolver.resolve(&reference("no_such_asm")).expect_err("must fail");
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
        assert_eq!(params.reading_mode, ReadingMode::Immediate);
        assert!(params.symbol_reader_provider.is_none());

        // Trait object round-trip through ReaderParameters.
        let boxed: Box<dyn AssemblyResolver> =
            Box::new(<DefaultAssemblyResolver as Default>::default());
        boxed.resolve(&reference("anything")).expect_err("no search dirs configured");
        let mut params = ReaderParameters::new();
        params.read_symbols = true;
        params.assembly_resolver = Some(boxed);
        params.reading_mode = ReadingMode::Deferred;
        assert!(params.read_symbols && params.assembly_resolver.is_some());
        assert_eq!(params.reading_mode, ReadingMode::Deferred);
    }

    #[test]
    fn probe_version_reads_fixture_assembly_row() {
        // hello.exe ships with an all-zero assembly version (ilasm default).
        let v = probe_version(&cecli_core::fixtures_dir().join("hello.exe")).expect("probe");
        assert_eq!((v.major, v.minor, v.build), (0, 0, 0));

        // cecil.dll ships as v2.0.24.* — a genuinely different version.
        let v = probe_version(&cecli_core::fixtures_dir().join("cecil.dll")).expect("probe");
        assert_eq!((v.major, v.minor, v.build), (0, 9, 6));
    }

    #[test]
    fn probe_version_rejects_images_without_an_assembly_row() {
        // Netmodules carry no Assembly table.
        assert!(probe_version(&cecli_core::fixtures_dir().join("moda.netmodule")).is_err());

        let dir = make_temp_dir(&next_unique_tag());
        let garbage = dir.join("garbage.dll");
        std::fs::write(&garbage, b"MZ fake").expect("write garbage");
        assert!(probe_version(&garbage).is_err());
        cleanup_dir(&dir);
    }

    #[test]
    fn higher_version_wins_even_in_later_directory() {
        let early = make_temp_dir(&next_unique_tag());
        let late = make_temp_dir(&next_unique_tag());
        // foo.dll probes as 1.0.0.*, cecil.dll as 2.0.24.*.
        copy_fixture_as(&early, "foo.dll", "same");
        copy_fixture_as(&late, "cecil.dll", "same");

        let mut resolver = DefaultAssemblyResolver::new();
        resolver.add_search_directory(&early);
        resolver.add_search_directory(&late);

        // A zero requested version accepts everything: highest overall wins,
        // even though the winner lives in the later directory.
        let path = resolver.resolve(&reference("same")).expect("resolved");
        assert_eq!(path, late.join("same.dll"));

        cleanup_dir(&early);
        cleanup_dir(&late);
    }

    #[test]
    fn requested_major_minor_floor_filters_candidates() {
        let early = make_temp_dir(&next_unique_tag());
        let late = make_temp_dir(&next_unique_tag());
        copy_fixture_as(&early, "foo.dll", "same"); // v1.0.0.*
        copy_fixture_as(&late, "cecil.dll", "same"); // v2.0.24.*

        let mut resolver = DefaultAssemblyResolver::new();
        resolver.add_search_directory(&early);
        resolver.add_search_directory(&late);

        // Requesting >= 2.0 excludes the earlier v1 candidate outright.
        let mut want_two = reference("same");
        want_two.version = Version::new(2, 0, 0, 0);
        let path = resolver.resolve(&want_two).expect("resolved");
        assert_eq!(path, late.join("same.dll"));

        // Major mismatch: nothing satisfies 9.x, so the highest overall
        // (still v2 over v1) wins as the best-effort fallback.
        let mut unreachable = reference("same");
        unreachable.version = Version::new(9, 9, 9, 9);
        let path = resolver.resolve(&unreachable).expect("resolved");
        assert_eq!(path, late.join("same.dll"));

        cleanup_dir(&early);
        cleanup_dir(&late);
    }

    #[test]
    fn equal_versions_keep_earlier_directory() {
        let early = make_temp_dir(&next_unique_tag());
        let late = make_temp_dir(&next_unique_tag());
        copy_fixture_as(&early, "hello.exe", "tied");
        copy_fixture_as(&late, "hello.exe", "tied");

        let mut resolver = DefaultAssemblyResolver::new();
        resolver.add_search_directory(&early);
        resolver.add_search_directory(&late);

        let path = resolver.resolve(&reference("tied")).expect("resolved");
        assert_eq!(path, early.join("tied.dll"));

        cleanup_dir(&early);
        cleanup_dir(&late);
    }

    #[test]
    fn probed_candidate_beats_unprobed_one() {
        let early = make_temp_dir(&next_unique_tag());
        let late = make_temp_dir(&next_unique_tag());
        std::fs::write(early.join("mix.dll"), b"not an image").expect("write opaque");
        copy_fixture_as(&late, "hello.exe", "mix");

        let mut resolver = DefaultAssemblyResolver::new();
        resolver.add_search_directory(&early);
        resolver.add_search_directory(&late);

        let path = resolver.resolve(&reference("mix")).expect("resolved");
        assert_eq!(path, late.join("mix.dll"));

        cleanup_dir(&early);
        cleanup_dir(&late);
    }

    #[test]
    fn all_candidates_unprobed_still_resolves_first() {
        let early = make_temp_dir(&next_unique_tag());
        let late = make_temp_dir(&next_unique_tag());
        std::fs::write(early.join("opaque.dll"), b"a").expect("write a");
        std::fs::write(late.join("opaque.exe"), b"b").expect("write b");

        let mut resolver = DefaultAssemblyResolver::new();
        resolver.add_search_directory(&early);
        resolver.add_search_directory(&late);

        // Neither candidate parses; the first in probe order (.dll before
        // .exe) is returned instead of failing.
        let path = resolver.resolve(&reference("opaque")).expect("resolved");
        assert_eq!(path, early.join("opaque.dll"));

        cleanup_dir(&early);
        cleanup_dir(&late);
    }

    #[test]
    fn framework_directory_is_recorded_but_never_searched() {
        let fw = make_temp_dir(&next_unique_tag());
        let target = copy_fixture_as(&fw, "hello.exe", "fwonly");

        let mut resolver = DefaultAssemblyResolver::new();
        resolver.add_framework_directory(&fw);
        assert_eq!(resolver.get_framework_directories(), std::slice::from_ref(&fw));

        // Framework directories are not consulted during resolution...
        assert!(resolver.resolve(&reference("fwonly")).is_err());

        // ...but registering the same location as a search directory works.
        assert_eq!(
            probe_version(&target).expect("probed").major,
            0, // hello.exe carries an all-zero assembly version
            "fixture sanity"
        );
        resolver.add_search_directory(&fw);
        assert!(resolver.resolve(&reference("fwonly")).is_ok());

        cleanup_dir(&fw);
    }

    #[test]
    fn symbol_reader_provider_hook_accepts_custom_implementations() {
        struct NullProvider;
        impl SymbolReaderProvider for NullProvider {
            fn get_symbol_reader(&self, _image_path: &Path) -> Result<Option<Vec<u8>>> {
                Ok(None)
            }
        }

        let mut params = ReaderParameters::new();
        params.read_symbols = true;
        params.symbol_reader_provider = Some(Box::new(NullProvider));
        assert!(params.read_symbols && params.symbol_reader_provider.is_some());
    }
}
