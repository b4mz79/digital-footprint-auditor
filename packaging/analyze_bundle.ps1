param(
    [string]$DistRoot = ".\dist\PrivacyAuditor"
)

if (-not (Test-Path $DistRoot)) {
    Write-Error "Dist folder tidak ditemukan: $DistRoot"
    exit 1
}

$resolved = Resolve-Path $DistRoot
$files = Get-ChildItem -Path $resolved -Recurse -File |
    Select-Object FullName, Length, Extension |
    Sort-Object Length -Descending

$total = ($files | Measure-Object Length -Sum).Sum

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " Privacy Auditor - Bundle Size Report" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host ("Total size : {0:N2} MB" -f ($total / 1MB)) -ForegroundColor Green
Write-Host ("File count : {0:N0}" -f $files.Count)
Write-Host ""

Write-Host "Top 30 largest files:" -ForegroundColor Yellow
Write-Host ""

$files | Select-Object -First 30 |
    ForEach-Object {
        "{0,10:N2} MB  {1}" -f ($_.Length / 1MB), $_.FullName
    }

Write-Host ""
Write-Host "Largest extensions:" -ForegroundColor Yellow
Write-Host ""

$files |
    Group-Object Extension |
    ForEach-Object {
        $sum = ($_.Group | Measure-Object Length -Sum).Sum

        [PSCustomObject]@{
            Extension = if ($_.Name) { $_.Name } else { "<none>" }
            SizeMB = [math]::Round($sum / 1MB, 2)
            Files = $_.Count
        }
    } |
    Sort-Object SizeMB -Descending |
    Select-Object -First 15 |
    Format-Table -AutoSize