param(
    [int]$Port = 8090,
    [string]$DbName = "vulnbank_ci",
    [string]$ReportDir = "dast-reports\zap",
    [string]$JarPath = "target\vulnbank-1.0.0.jar"
)

# Starts a throwaway instance of the already-built jar on a dedicated
# port/database (never the manually-run app on 8080, or any other
# instance), runs an OWASP ZAP active scan against it via Docker, then
# always stops the instance - even if the scan fails or times out.

$ErrorActionPreference = "Stop"
$mysqlExe = "C:\Program Files\MySQL\MySQL Server 8.4\bin\mysql.exe"
$workDir = (Get-Location).Path
$fullReportDir = Join-Path $workDir $ReportDir
if (-not (Test-Path $fullReportDir)) { New-Item -ItemType Directory -Path $fullReportDir -Force | Out-Null }

Write-Output "Ensuring CI database '$DbName' exists..."
& $mysqlExe -u root -proot -e "CREATE DATABASE IF NOT EXISTS $DbName;"

$dbUrl = "jdbc:mysql://localhost:3306/$DbName`?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"
$logFile = Join-Path $fullReportDir "dast-app.log"
$errFile = Join-Path $fullReportDir "dast-app-err.log"

Write-Output "Starting throwaway app instance on port $Port against '$DbName'..."
$proc = $null
$exitCode = 1
try {
    # stdout/stderr must be different files - Start-Process throws
    # "RedirectStandardOutput and RedirectStandardError are same" otherwise.
    $proc = Start-Process -FilePath "java" `
        -ArgumentList "-jar", $JarPath, "--server.port=$Port", "--spring.datasource.url=$dbUrl" `
        -RedirectStandardOutput $logFile -RedirectStandardError $errFile `
        -PassThru -WindowStyle Hidden
    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $resp = Invoke-WebRequest -Uri "http://localhost:$Port/login" -UseBasicParsing -TimeoutSec 2
            if ($resp.StatusCode -eq 200) { $ready = $true; break }
        } catch {}
        Start-Sleep -Seconds 2
    }

    if (-not $ready) {
        Write-Output "DAST target app did not become ready on port $Port within 60s - see dast-app.log"
        $exitCode = 2
    } else {
        Write-Output "DAST target app ready on port $Port (PID $($proc.Id)). Running ZAP active scan..."

        $planPath = Join-Path $fullReportDir "zap-ci-plan.yaml"
        $endpoints = @(
            "/login", "/dashboard?user=alice", "/dashboard?user=bob", "/dashboard?user=admin",
            "/dashboard?user=chiefadmin", "/account/1", "/account/2", "/account/3", "/account/4",
            "/accounts", "/messages", "/search?q=test", "/currency/rate?source=http://example.com",
            "/statements/download?filename=january.txt", "/admin/users?key=Sup3rAdmin!2023",
            "/admin/debug/all-data", "/admin/users/1/edit"
        )
        $base = "http://host.docker.internal:$Port"
        $urlLines = ($endpoints | ForEach-Object { "        - $base$_" }) -join "`n"

        $plan = @"
env:
  contexts:
    - name: vulnbank
      urls:
$urlLines
      includePaths:
        - "$base.*"
      excludePaths:
        - ".*\/admin\/users\/[0-9]+`$"
  parameters:
    failOnError: false
    progressToStdout: true
jobs:
  - type: spider
    parameters:
      context: vulnbank
      url: $base/login
      maxDuration: 3
  - type: passiveScan-wait
    parameters:
      maxDuration: 3
  - type: activeScan
    parameters:
      context: vulnbank
      maxRuleDurationInMins: 2
      maxScanDurationInMins: 15
  - type: report
    parameters:
      template: traditional-html
      reportDir: /zap/wrk
      reportFile: zap-full-report
      reportTitle: VulnBank DAST Full Scan (Jenkins CI, isolated DB)
  - type: report
    parameters:
      template: traditional-json
      reportDir: /zap/wrk
      reportFile: zap-full-report
  - type: report
    parameters:
      template: traditional-md
      reportDir: /zap/wrk
      reportFile: zap-full-report
"@
        Set-Content -Path $planPath -Value $plan -Encoding ascii

        docker run --rm -v "${fullReportDir}:/zap/wrk/:rw" zaproxy/zap-stable zap.sh -cmd -autorun /zap/wrk/zap-ci-plan.yaml
        $exitCode = $LASTEXITCODE
    }
} finally {
    if ($proc) {
        Write-Output "Stopping DAST target app (PID $($proc.Id))..."
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
}

exit $exitCode
