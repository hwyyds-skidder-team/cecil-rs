param(
    [int]$Rounds = 3,
    [int]$Samples = 11,
    [int]$SampleMs = 120,
    [int]$WarmupMs = 800,
    [string]$InputFilter = '.',
    [string]$ModeFilter = '.',
    [string]$CargoTargetDir = 'target/perf-managed',
    [string]$CargoProfile = 'release',
    [string]$CargoFeatures = 'fast-allocator',
    [switch]$ValidateOnly,
    [switch]$RequireAllCells
)
$arguments = @('-X','utf8',(Join-Path $PSScriptRoot 'run.py'),'--rounds',"$Rounds",'--samples',"$Samples",'--sample-ms',"$SampleMs",'--warmup-ms',"$WarmupMs",'--input-filter',$InputFilter,'--mode-filter',$ModeFilter,'--cargo-target-dir',$CargoTargetDir,'--cargo-profile',$CargoProfile,'--cargo-features',$CargoFeatures)
if ($ValidateOnly) { $arguments += '--validate-only' }
if ($RequireAllCells) { $arguments += '--require-all-cells' }
& python @arguments
exit $LASTEXITCODE
