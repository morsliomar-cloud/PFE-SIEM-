# === CONFIGURE THESE ===
$evtxDump   = "C:\Users\ss\Downloads\EVTX\evtx_dump.exe"      # path to evtx_dump.exe
$inputFolder  = "C:\Users\ss\Downloads\EVTX"              # folder containing your .evtx files
$outputFolder = "C:\Users\ss\Downloads\EVTX\json"              # where JSON files will be saved
# =======================

# Create output folder if it doesn't exist
New-Item -ItemType Directory -Force -Path $outputFolder | Out-Null

# Loop through every .evtx file (recursively)
Get-ChildItem -Path $inputFolder -Filter "*.evtx" -Recurse | ForEach-Object {
    $inputFile  = $_.FullName
    $outputFile = Join-Path $outputFolder ($_.BaseName + ".json")

    Write-Host "Converting: $($_.Name) -> $outputFile"

    & $evtxDump -o json -f $outputFile $inputFile
}

Write-Host "`nDone! JSON files saved to: $outputFolder"