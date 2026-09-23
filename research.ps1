param(
    [Parameter(Position = 0)]
    [ValidateSet("setup", "test", "pilot", "protocol", "requirements", "cxp-requirements", "webauthn", "cxp", "campaign-c1", "campaign-c2", "campaign-c3", "phase6", "phase7-calibration", "phase7", "phase8", "phase9", "phase10", "phase11", "phase12", "phase13", "verify-release", "status")]
    [string]$Action = "status"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$ProtocolPath = Join-Path $ProjectRoot "experiments\protocol_v1.4.json"
$PublicationStem = "PasskeyTransit_v0.6"

function Require-Venv {
    if (-not (Test-Path -LiteralPath $VenvPython)) {
        throw "Virtual environment missing. Run ./research.ps1 setup first."
    }
}

function Resolve-CargoPath {
    if ($env:PASSKEYTRANSIT_CARGO -and (Test-Path -LiteralPath $env:PASSKEYTRANSIT_CARGO)) {
        return (Resolve-Path -LiteralPath $env:PASSKEYTRANSIT_CARGO).Path
    }
    $CargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
    if ($CargoCommand) { return $CargoCommand.Source }
    if ($env:CARGO_HOME) {
        $CargoHomeCandidate = Join-Path $env:CARGO_HOME "bin\cargo.exe"
        if (Test-Path -LiteralPath $CargoHomeCandidate) { return $CargoHomeCandidate }
    }
    throw "Cargo was not found. Set PASSKEYTRANSIT_CARGO to the cargo executable."
}

switch ($Action) {
    "setup" {
        if (-not (Test-Path -LiteralPath $VenvPython)) {
            python -m venv (Join-Path $ProjectRoot ".venv")
        }
        & $VenvPython -m pip install --upgrade pip
        & $VenvPython -m pip install -r (Join-Path $ProjectRoot "requirements.lock")
        & $VenvPython -m pip install --no-deps -e $ProjectRoot
    }
    "test" {
        Require-Venv
        & $VenvPython -m pytest
    }
    "pilot" {
        Require-Venv
        & $VenvPython -m passkeytransit pilot `
            --config (Join-Path $ProjectRoot "experiments\pilot_v0.1.json") `
            --output (Join-Path $ProjectRoot "datasets\generated")
    }
    "protocol" {
        Require-Venv
        & $VenvPython -m passkeytransit protocol `
            --config $ProtocolPath
    }
    "requirements" {
        Require-Venv
        & $VenvPython -m passkeytransit requirements `
            --matrix (Join-Path $ProjectRoot "spec\cxf_passkey_requirements_v1.0.json")
    }
    "cxp-requirements" {
        Require-Venv
        & $VenvPython -m passkeytransit requirements `
            --matrix (Join-Path $ProjectRoot "spec\cxp_requirements_wd_20241003.json")
    }
    "webauthn" {
        Require-Venv
        $BrowserPath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        if (-not (Test-Path -LiteralPath $BrowserPath)) {
            $BrowserPath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
        }
        if (-not (Test-Path -LiteralPath $BrowserPath)) {
            throw "No supported local Chromium executable was found."
        }
        & $VenvPython -m passkeytransit webauthn `
            --browser $BrowserPath `
            --output (Join-Path $ProjectRoot "datasets\generated\webauthn_phase3_result.json")
    }
    "cxp" {
        Require-Venv
        & $VenvPython -m passkeytransit cxp `
            --output (Join-Path $ProjectRoot "datasets\generated\cxp_phase4_result.json")
    }
    "campaign-c1" {
        Require-Venv
        $RunStamp = Get-Date -Format "yyyyMMddTHHmmssfff"
        & $VenvPython -m passkeytransit campaign-c1 `
            --protocol $ProtocolPath `
            --output (Join-Path $ProjectRoot "datasets\generated\phase5_c1\$RunStamp")
    }
    "campaign-c2" {
        Require-Venv
        $RunStamp = Get-Date -Format "yyyyMMddTHHmmssfff"
        & $VenvPython -m passkeytransit campaign-c2 `
            --protocol $ProtocolPath `
            --output (Join-Path $ProjectRoot "datasets\generated\phase6\$RunStamp\c2")
    }
    "campaign-c3" {
        Require-Venv
        $RunStamp = Get-Date -Format "yyyyMMddTHHmmssfff"
        & $VenvPython -m passkeytransit campaign-c3 `
            --protocol $ProtocolPath `
            --output (Join-Path $ProjectRoot "datasets\generated\phase6\$RunStamp\c3")
    }
    "phase6" {
        Require-Venv
        $RunStamp = Get-Date -Format "yyyyMMddTHHmmssfff"
        $RunRoot = Join-Path $ProjectRoot "datasets\generated\phase6\$RunStamp"
        & $VenvPython -m passkeytransit campaign-c2 `
            --protocol $ProtocolPath `
            --output (Join-Path $RunRoot "c2")
        & $VenvPython -m passkeytransit campaign-c3 `
            --protocol $ProtocolPath `
            --output (Join-Path $RunRoot "c3")
    }
    "phase7-calibration" {
        Require-Venv
        $RunStamp = Get-Date -Format "yyyyMMddTHHmmssfff"
        & $VenvPython -m passkeytransit browser-c1 `
            --protocol $ProtocolPath `
            --mode calibration `
            --output (Join-Path $ProjectRoot "datasets\generated\phase7\$RunStamp\calibration")
    }
    "phase7" {
        Require-Venv
        $RunStamp = Get-Date -Format "yyyyMMddTHHmmssfff"
        $RunRoot = Join-Path $ProjectRoot "datasets\generated\phase7\$RunStamp"
        & $VenvPython -m passkeytransit browser-c1 `
            --protocol $ProtocolPath `
            --mode calibration `
            --output (Join-Path $RunRoot "calibration")
        if ($LASTEXITCODE -ne 0) { throw "Phase 7 calibration failed; full campaign was not started." }
        & $VenvPython -m passkeytransit browser-c1 `
            --protocol $ProtocolPath `
            --mode full `
            --output (Join-Path $RunRoot "full")
    }
    "phase8" {
        Require-Venv
        $RunStamp = Get-Date -Format "yyyyMMddTHHmmssfff"
        $NodePath = (Get-Command node -ErrorAction Stop).Source
        & $VenvPython -m passkeytransit interop `
            --node $NodePath `
            --node-verifier (Join-Path $ProjectRoot "interop\node_cxf_verifier.mjs") `
            --output (Join-Path $ProjectRoot "datasets\generated\phase8\$RunStamp\interop_result.json")
    }
    "phase9" {
        Require-Venv
        $RunStamp = Get-Date -Format "yyyyMMddTHHmmssfff"
        $Phase7Run = Get-ChildItem (Join-Path $ProjectRoot "datasets\generated\phase7") -Directory | Sort-Object Name | Select-Object -Last 1
        $Phase6Run = Get-ChildItem (Join-Path $ProjectRoot "datasets\generated\phase6") -Directory | Sort-Object Name | Select-Object -Last 1
        $Phase8Run = Get-ChildItem (Join-Path $ProjectRoot "datasets\generated\phase8") -Directory | Sort-Object Name | Select-Object -Last 1
        $AnalysisArgs = @(
            "-m", "passkeytransit", "analyze",
            "--phase7-summary", (Join-Path $Phase7Run.FullName "full\c1_phase7_full_summary.json"),
            "--phase7-manifest", (Join-Path $Phase7Run.FullName "full\c1_phase7_full_manifest.json"),
            "--c2-summary", (Join-Path $Phase6Run.FullName "c2\c2_phase6_summary.json"),
            "--c2-manifest", (Join-Path $Phase6Run.FullName "c2\c2_phase6_manifest.json"),
            "--c3-summary", (Join-Path $Phase6Run.FullName "c3\c3_phase6_summary.json"),
            "--c3-manifest", (Join-Path $Phase6Run.FullName "c3\c3_phase6_manifest.json"),
            "--interop", (Join-Path $Phase8Run.FullName "interop_result.json"),
            "--output", (Join-Path $ProjectRoot "datasets\generated\analysis\$RunStamp")
        )
        $ExternalRun = Get-ChildItem (Join-Path $ProjectRoot "datasets\generated\phase11") -Directory -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
        $OracleRun = Get-ChildItem (Join-Path $ProjectRoot "datasets\generated\phase12") -Directory -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
        if ($ExternalRun) { $AnalysisArgs += @("--external", (Join-Path $ExternalRun.FullName "bitwarden_cxf_interop.json")) }
        if ($OracleRun) { $AnalysisArgs += @("--oracle-report", (Join-Path $OracleRun.FullName "oracle_capabilities.json")) }
        & $VenvPython @AnalysisArgs
    }
    "phase11" {
        Require-Venv
        $RunStamp = Get-Date -Format "yyyyMMddTHHmmssfff"
        $CargoPath = Resolve-CargoPath
        $NodePath = (Get-Command node -ErrorAction Stop).Source
        $CargoToolchain = if ($env:PASSKEYTRANSIT_CARGO_TOOLCHAIN) { $env:PASSKEYTRANSIT_CARGO_TOOLCHAIN } elseif ($IsWindows) { "stable-x86_64-pc-windows-gnu" } else { "stable" }
        & $VenvPython -m passkeytransit bitwarden-interop `
            --protocol $ProtocolPath `
            --cargo $CargoPath `
            --manifest (Join-Path $ProjectRoot "interop\bitwarden-cxf-adapter\Cargo.toml") `
            --node $NodePath `
            --wasi-runner (Join-Path $ProjectRoot "interop\wasi_runner.mjs") `
            --cargo-toolchain $CargoToolchain `
            --output (Join-Path $ProjectRoot "datasets\generated\phase11\$RunStamp\bitwarden_cxf_interop.json")
    }
    "phase12" {
        Require-Venv
        $RunStamp = Get-Date -Format "yyyyMMddTHHmmssfff"
        & $VenvPython -m passkeytransit oracle-audit `
            --output (Join-Path $ProjectRoot "datasets\generated\phase12\$RunStamp\oracle_capabilities.json")
    }
    "phase13" {
        Require-Venv
        $AnalysisRun = Get-ChildItem (Join-Path $ProjectRoot "datasets\generated\analysis") -Directory | Sort-Object Name | Select-Object -Last 1
        & $VenvPython (Join-Path $ProjectRoot "tools\build_publication.py") `
            --source (Join-Path $AnalysisRun.FullName "MANUSCRIPT.md") `
            --docx (Join-Path $AnalysisRun.FullName "$PublicationStem.docx") `
            --pdf (Join-Path $AnalysisRun.FullName "$PublicationStem.pdf")
    }
    "phase10" {
        Require-Venv
        $RunStamp = Get-Date -Format "yyyyMMddTHHmmssfff"
        $Phase7Run = Get-ChildItem (Join-Path $ProjectRoot "datasets\generated\phase7") -Directory | Sort-Object Name | Select-Object -Last 1
        $Phase6Run = Get-ChildItem (Join-Path $ProjectRoot "datasets\generated\phase6") -Directory | Sort-Object Name | Select-Object -Last 1
        $Phase8Run = Get-ChildItem (Join-Path $ProjectRoot "datasets\generated\phase8") -Directory | Sort-Object Name | Select-Object -Last 1
        $Phase11Run = Get-ChildItem (Join-Path $ProjectRoot "datasets\generated\phase11") -Directory | Sort-Object Name | Select-Object -Last 1
        $Phase12Run = Get-ChildItem (Join-Path $ProjectRoot "datasets\generated\phase12") -Directory | Sort-Object Name | Select-Object -Last 1
        $AnalysisRun = Get-ChildItem (Join-Path $ProjectRoot "datasets\generated\analysis") -Directory | Sort-Object Name | Select-Object -Last 1
        & $VenvPython -m passkeytransit release `
            --project-root $ProjectRoot `
            --evidence-root $Phase6Run.FullName `
            --evidence-root $Phase7Run.FullName `
            --evidence-root $Phase8Run.FullName `
            --evidence-root $AnalysisRun.FullName `
            --external-result (Join-Path $Phase11Run.FullName "bitwarden_cxf_interop.json") `
            --oracle-report (Join-Path $Phase12Run.FullName "oracle_capabilities.json") `
            --output (Join-Path $ProjectRoot "datasets\generated\releases\$RunStamp")
    }
    "verify-release" {
        Require-Venv
        $ReleaseRun = Get-ChildItem (Join-Path $ProjectRoot "datasets\generated\releases") -Directory | Sort-Object Name | Select-Object -Last 1
        $ManifestPath = Join-Path $ReleaseRun.FullName "release_manifest.json"
        $Manifest = Get-Content -Raw $ManifestPath | ConvertFrom-Json
        & $VenvPython -m passkeytransit verify-release `
            --archive (Join-Path $ReleaseRun.FullName $Manifest.archive) `
            --manifest $ManifestPath
    }
    "status" {
        if (Test-Path -LiteralPath $VenvPython) {
            & $VenvPython -m passkeytransit status
        } else {
            Write-Output "PasskeyTransit repository initialized; environment not installed."
        }
    }
}
