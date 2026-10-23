param(
    [int]$Rounds = 3,
    [int]$Samples = 11,
    [int]$SampleMs = 120,
    [int]$WarmupMs = 800,
    [string]$InputFilter = '.',
    [string]$ModeFilter = '.',
    [string]$CargoTargetDir = 'target',
    [string]$CargoProfile = 'release',
    [string]$CargoFeatures = 'fast-allocator',
    [switch]$RequireAllCells,
    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Rounds -lt 1 -or $Samples -lt 1 -or $SampleMs -lt 1 -or $WarmupMs -lt 1) { throw 'Parameters must be positive.' }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$work = Join-Path $repo 'target\compare-cecil'
$results = Join-Path $repo 'benchmarks'
New-Item -ItemType Directory -Path $work, $results -Force | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$prefix = Join-Path $results "$stamp-cecil-comparison"
$runWork = Join-Path $work "runs\$stamp"
New-Item -ItemType Directory -Path $runWork | Out-Null

function Run-Native([string]$Executable, [string[]]$Arguments) {
    $output = & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Executable exited with code $LASTEXITCODE`n$($output -join "`n")" }
    return $output
}

function Package([string]$Id, [string]$Version, [string]$Folder, [string]$Archive) {
    $destination = Join-Path $work $Folder
    if (-not (Test-Path -LiteralPath $destination)) {
        $zip = Join-Path $work $Archive
        if (-not (Test-Path -LiteralPath $zip)) {
            Run-Native 'curl.exe' @('-sS', '-L', '--fail', '--max-time', '180', "https://api.nuget.org/v3-flatcontainer/$Id/$Version/$Id.$Version.nupkg", '-o', $zip) | Out-Null
        }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $destination)
    }
    return $destination
}

function Source-Manifest {
    $paths = @(Run-Native 'git' @('ls-files', '--cached', '--others', '--exclude-standard', '--', 'Cargo.toml', 'Cargo.lock', 'crates', '.cargo', 'scripts/compare-cecil')) | Where-Object { $_ -notmatch '(^|/)__pycache__/|\.pyc$' } | Sort-Object -Unique
    return @($paths | ForEach-Object {
        $path = Join-Path $repo $_
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            [ordered]@{ path = $_; bytes = (Get-Item -LiteralPath $path).Length; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
        }
    })
}

function Save-SourceArchive($Manifest, [string]$Path) {
    Add-Type -AssemblyName System.IO.Compression
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            foreach ($entry in $Manifest) {
                $item = $zip.CreateEntry($entry.path.Replace('\', '/'), [System.IO.Compression.CompressionLevel]::Optimal)
                $destination = $item.Open()
                $source = [System.IO.File]::OpenRead((Join-Path $repo $entry.path))
                try { $source.CopyTo($destination) } finally { $source.Dispose(); $destination.Dispose() }
            }
        } finally { $zip.Dispose() }
    } finally { $stream.Dispose() }
}

function Assert-SameValidation($Original, $Cross, [string]$Label) {
    foreach ($field in @('counts', 'semantics')) {
        if (($Original.$field | ConvertTo-Json -Compress) -ne ($Cross.$field | ConvertTo-Json -Compress)) {
            throw "$Label $field mismatch: original $($Original.$field | ConvertTo-Json -Compress); output $($Cross.$field | ConvertTo-Json -Compress). Canonical dumps are in $runWork."
        }
    }
}

Push-Location $repo
try {
    $cecil = Package 'mono.cecil' '0.11.6' 'cecil' 'mono.cecil.nupkg'
    $roslyn = Package 'microsoft.net.compilers.toolset' '4.14.0' 'roslyn' 'roslyn.nupkg'
    $runtimeLine = (& dotnet --list-runtimes | Where-Object { $_ -match '^Microsoft.NETCore.App ' } | Select-Object -Last 1)
    if (-not $runtimeLine) { throw 'Microsoft.NETCore.App runtime is required.' }
    $match = [regex]::Match($runtimeLine, '^Microsoft.NETCore.App (\S+) \[(.+)\]$')
    $runtimeVersion = $match.Groups[1].Value
    $runtimePath = Join-Path $match.Groups[2].Value $runtimeVersion
    $manifest = Source-Manifest
    $manifestJson = $manifest | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText("$prefix.source.json", $manifestJson, $utf8)
    Save-SourceArchive $manifest "$prefix.source.zip"
    $gitStatusBefore = @(Run-Native 'git' @('status', '--porcelain=v1', '--untracked-files=all'))
    $output = Join-Path $runWork 'CecilBench.dll'
    Copy-Item -LiteralPath (Join-Path $cecil 'lib\netstandard2.0\Mono.Cecil.dll') -Destination (Join-Path $work 'Mono.Cecil.dll') -Force
    Copy-Item -LiteralPath (Join-Path $work 'Mono.Cecil.dll') -Destination (Join-Path $runWork 'Mono.Cecil.dll')
    $config = @{ runtimeOptions = @{ tfm = "net$($runtimeVersion.Split('.')[0]).0"; framework = @{ name = 'Microsoft.NETCore.App'; version = $runtimeVersion }; configProperties = @{ 'System.Runtime.TieredCompilation' = $false; 'System.GC.Server' = $false } } }
    [System.IO.File]::WriteAllText((Join-Path $runWork 'CecilBench.runtimeconfig.json'), ($config | ConvertTo-Json -Depth 6), $utf8)
    $compilerArgs = @('-nologo', '-noconfig', '-nostdlib+', '-target:exe', '-optimize+', "-out:$output", "-r:$(Join-Path $work 'Mono.Cecil.dll')")
    $compilerArgs += @('System.Private.CoreLib.dll', 'System.Runtime.dll', 'netstandard.dll', 'System.Console.dll', 'System.Collections.dll', 'System.Diagnostics.Process.dll', 'System.Runtime.Extensions.dll', 'System.Security.Cryptography.dll') | ForEach-Object { "-r:$(Join-Path $runtimePath $_)" }
    $compilerArgs += Join-Path $PSScriptRoot 'CecilBench.cs'
    $compiler = Join-Path $roslyn 'tasks\netcore\bincore\csc.dll'
    Run-Native 'dotnet' (@('--roll-forward', 'Major', $compiler) + $compilerArgs) | Out-Null
    $targetPath = if ([System.IO.Path]::IsPathRooted($CargoTargetDir)) { $CargoTargetDir } else { Join-Path $repo $CargoTargetDir }
    $cargoArgs = @('build', '--locked', '--profile', $CargoProfile, '--target-dir', $targetPath, '-p', 'cecil-rs', '--example', 'compare_cecil')
    if ($CargoFeatures) { $cargoArgs += @('--features', $CargoFeatures) }
    Run-Native 'cargo' $cargoArgs | Out-Null
    $profileDirectory = if ($CargoProfile -eq 'dev') { 'debug' } else { $CargoProfile }
    $rust = Join-Path $targetPath "$profileDirectory\examples\compare_cecil.exe"
    if (((Source-Manifest) | ConvertTo-Json -Depth 6) -ne $manifestJson) { throw 'Build inputs changed during compilation; source archive is preserved, run again from a stable source state.' }
    $inputs = @(
        @{ name = 'hello.exe'; path = Join-Path $repo 'fixtures\hello.exe' },
        @{ name = 'System.Runtime.dll (fixture)'; path = Join-Path $repo 'fixtures\System.Runtime.dll' },
        @{ name = 'SQLite-net.dll'; path = Join-Path $repo 'fixtures\SQLite-net.dll' },
        @{ name = 'cecil.dll (fixture)'; path = Join-Path $repo 'fixtures\cecil.dll' },
        @{ name = 'Mono.Cecil.dll (0.11.6)'; path = Join-Path $work 'Mono.Cecil.dll' },
        @{ name = 'Microsoft.CodeAnalysis.dll'; path = Join-Path $roslyn 'tasks\netcore\bincore\Microsoft.CodeAnalysis.dll' },
        @{ name = 'Microsoft.CodeAnalysis.CSharp.dll'; path = Join-Path $roslyn 'tasks\netcore\bincore\Microsoft.CodeAnalysis.CSharp.dll' }
    )
    $inputs = @($inputs | Where-Object { $_.name -match $InputFilter })
    $modes = @(@('read', 'write', 'roundtrip') | Where-Object { $_ -match $ModeFilter })
    if ($inputs.Count -eq 0 -or $modes.Count -eq 0) { throw 'Filters selected no inputs or modes.' }
    $validation = @()
    foreach ($input in $inputs) {
        Write-Host "Validate $($input.name)"
        $safe = [regex]::Replace($input.name, '[^A-Za-z0-9_.-]', '_')
        $rustOut = Join-Path $runWork "$safe.rust.dll"
        $cecilOut = Join-Path $runWork "$safe.cecil.dll"
        $r = (Run-Native $rust @('validate', $input.path, '1', '1', '1', $rustOut, (Join-Path $runWork "$safe.original.rust.txt"))) | ConvertFrom-Json
        $c = (Run-Native 'dotnet' @($output, 'validate', $input.path, '1', '1', '1', $cecilOut, (Join-Path $runWork "$safe.original.cecil.txt"))) | ConvertFrom-Json
        if (($r.counts | ConvertTo-Json -Compress) -ne ($c.counts | ConvertTo-Json -Compress)) {
            throw "Input count mismatch for $($input.name): Rust $($r.counts | ConvertTo-Json -Compress); Cecil $($c.counts | ConvertTo-Json -Compress)"
        }
        $crossC = (Run-Native 'dotnet' @($output, 'inspect', $rustOut, '1', '1', '1', '-', (Join-Path $runWork "$safe.rust-output.cecil.txt"))) | ConvertFrom-Json
        $crossR = (Run-Native $rust @('inspect', $cecilOut, '1', '1', '1', '-', (Join-Path $runWork "$safe.cecil-output.rust.txt"))) | ConvertFrom-Json
        Assert-SameValidation $c $crossC "Cecil reads Rust output: $($input.name)"
        Assert-SameValidation $r $crossR "Rust reads Cecil output: $($input.name)"
        $input['bytes'] = (Get-Item -LiteralPath $input.path).Length
        $input['sha256'] = (Get-FileHash -LiteralPath $input.path -Algorithm SHA256).Hash.ToLowerInvariant()
        $validation += @{ name = $input.name; counts = $r.counts; rust_output_bytes = $r.output_bytes; cecil_output_bytes = $c.output_bytes; cross_read = 'passed'; semantic_validation = 'passed'; rust_semantics = $r.semantics; cecil_semantics = $c.semantics }
    }
    $buildEnv = @{}
    Get-ChildItem Env: | Where-Object { $_.Name -match '^(RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|RUSTUP_TOOLCHAIN|CARGO_BUILD_(TARGET|RUSTFLAGS)|CARGO_PROFILE_.+|CARGO_TARGET_.+_RUSTFLAGS)$' } | ForEach-Object { $buildEnv[$_.Name] = $_.Value }
    $cargoConfigs = @()
    $configPaths = @((Join-Path $repo '.cargo\config'), (Join-Path $repo '.cargo\config.toml'), (Join-Path $env:USERPROFILE '.cargo\config'), (Join-Path $env:USERPROFILE '.cargo\config.toml'))
    if ($env:CARGO_HOME) { $configPaths += @((Join-Path $env:CARGO_HOME 'config'), (Join-Path $env:CARGO_HOME 'config.toml')) }
    foreach ($path in ($configPaths | Sort-Object -Unique)) {
        if (Test-Path -LiteralPath $path) { $cargoConfigs += @{ path = $path; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() } }
    }
    $environment = @{
        recorded_at = (Get-Date -Format o); commit = (Run-Native 'git' @('rev-parse', 'HEAD'));
        rust = (Run-Native 'rustc' @('-Vv')) -join "`n"; dotnet = $runtimeVersion;
        mono_cecil = '0.11.6'; roslyn = '4.14.0'; cpu = (Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors);
        ram_bytes = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory;
        os = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version);
        rounds = $Rounds; samples_per_round = $Samples; sample_ms = $SampleMs; warmup_ms = $WarmupMs;
        modes = $modes;
        suite = 'cecil-7x3-v1'; required_cells = 21;
        tiered_compilation = $false; server_gc = $false; inputs = $inputs; validation = $validation;
        source_snapshot = @{ manifest = "$prefix.source.json"; archive = "$prefix.source.zip"; manifest_sha256 = (Get-FileHash -LiteralPath "$prefix.source.json" -Algorithm SHA256).Hash.ToLowerInvariant(); archive_sha256 = (Get-FileHash -LiteralPath "$prefix.source.zip" -Algorithm SHA256).Hash.ToLowerInvariant(); git_status = $gitStatusBefore; dirty = ($gitStatusBefore.Count -gt 0) };
        build = @{ cargo = (Run-Native 'cargo' @('-Vv')) -join "`n"; profile = $CargoProfile; features = $CargoFeatures; allocator = $(if ($CargoFeatures.Split(',') -contains 'fast-allocator') { 'mimalloc' } else { 'application/system default' }); target_dir = $targetPath; cargo_arguments = $cargoArgs; csharp_arguments = $compilerArgs; environment = $buildEnv; cargo_configs = $cargoConfigs; runtime_config = $config; artifact_dir = $runWork };
        mono_cecil_package_sha256 = (Get-FileHash (Join-Path $work 'mono.cecil.nupkg')).Hash.ToLowerInvariant();
        roslyn_package_sha256 = (Get-FileHash (Join-Path $work 'roslyn.nupkg')).Hash.ToLowerInvariant();
        driver_sha256 = @{
            rust_source = (Get-FileHash (Join-Path $repo 'crates\cecil-rs\examples\compare_cecil.rs')).Hash.ToLowerInvariant();
            csharp_source = (Get-FileHash (Join-Path $PSScriptRoot 'CecilBench.cs')).Hash.ToLowerInvariant();
            rust_binary = (Get-FileHash $rust).Hash.ToLowerInvariant();
            csharp_binary = (Get-FileHash $output).Hash.ToLowerInvariant()
        }
    }
    if (((Source-Manifest) | ConvertTo-Json -Depth 6) -ne $manifestJson) { throw 'Build inputs changed during validation; refusing to attribute these results to the archived sources.' }
    [System.IO.File]::WriteAllText("$prefix.environment.json", ($environment | ConvertTo-Json -Depth 10), $utf8)
    if ($ValidateOnly) { Write-Host "Validation passed: $prefix.environment.json"; return }
    $rawPath = "$prefix.raw.jsonl"
    [System.IO.File]::WriteAllText($rawPath, '', $utf8)
    for ($round = 1; $round -le $Rounds; $round++) {
        $cell = 0
        foreach ($input in $inputs) {
            foreach ($mode in $modes) {
                $order = if (($round + $cell) % 2 -eq 0) { @('rust', 'cecil') } else { @('cecil', 'rust') }
                foreach ($implementation in $order) {
                    Write-Host "Round $round/$Rounds $($input.name) $mode $implementation"
                    $arguments = @($mode, $input.path, "$Samples", "$SampleMs", "$WarmupMs")
                    $data = if ($implementation -eq 'rust') { (Run-Native $rust $arguments) | ConvertFrom-Json } else { (Run-Native 'dotnet' (@($output) + $arguments)) | ConvertFrom-Json }
                    $data | Add-Member -NotePropertyName input -NotePropertyValue $input.name
                    $data | Add-Member -NotePropertyName round -NotePropertyValue $round
                    [System.IO.File]::AppendAllText($rawPath, ($data | ConvertTo-Json -Depth 6 -Compress) + "`n", $utf8)
                }
                $cell++
            }
        }
    }
    if (((Source-Manifest) | ConvertTo-Json -Depth 6) -ne $manifestJson) { throw 'Build inputs changed during measurement; raw data is preserved but cannot pass acceptance.' }
    $reportArgs = @('-X', 'utf8', (Join-Path $PSScriptRoot 'report.py'), "$prefix.environment.json", $rawPath)
    if ($RequireAllCells) { $reportArgs += '--require-all-cells' }
    Run-Native 'python' $reportArgs | Write-Host
}
finally { Pop-Location }
