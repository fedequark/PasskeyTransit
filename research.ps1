param(
    [Parameter(Position = 0)]
    [ValidateSet("setup", "test", "pilot", "protocol", "requirements", "status")]
    [string]$Action = "status"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

function Require-Venv {
    if (-not (Test-Path -LiteralPath $VenvPython)) {
        throw "Virtual environment missing. Run ./research.ps1 setup first."
    }
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
            --config (Join-Path $ProjectRoot "experiments\protocol_v1.0.json")
    }
    "requirements" {
        Require-Venv
        & $VenvPython -m passkeytransit requirements `
            --matrix (Join-Path $ProjectRoot "spec\cxf_passkey_requirements_v1.0.json")
    }
    "status" {
        if (Test-Path -LiteralPath $VenvPython) {
            & $VenvPython -m passkeytransit status
        } else {
            Write-Output "PasskeyTransit repository initialized; environment not installed."
        }
    }
}
