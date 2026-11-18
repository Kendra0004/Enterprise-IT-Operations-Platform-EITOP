# TestHelpers.ps1 — shared helpers for *.Tests.ps1 (not a Pester test file).

function Get-CodeOnlyText {
    <#
        .SYNOPSIS
            Source text with comments and block-docs removed.
            Hygiene assertions must inspect CODE, not documentation:
            modules legitimately mention "Win32_Product"/"Invoke-Expression"
            in header comments explaining why they are forbidden.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $raw = Get-Content -LiteralPath $Path -Raw
    $raw = [regex]::Replace($raw, '(?s)<#.*?#>', '')       # block comments/doc headers
    $lines = $raw -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }   # line comments
    $lines -join "`n"
}
