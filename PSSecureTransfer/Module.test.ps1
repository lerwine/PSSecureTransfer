if ((Get-Module -Name:'PSSecureTransfer') -ne $null) { Remove-Module -Name:'PSSecureTransfer' }
Import-Module -Name:'PSSecureTransfer';

$TempKeyName = [Guid]::NewGuid().ToString('N');
$KeyExportPath = [System.IO.Path]::GetTempPath() | Join-Path -ChildPath:$TempKeyName;

Export-PublicKey -Path:$KeyExportPath;
Import-PublicKey -Path:$KeyExportPath;

$EncryptedPath = [System.IO.Path]::GetTempFileName();

$OriginalPath = $PSScriptRoot | Join-Path -ChildPath:'Install.ps1';
ConvertTo-EncryptedFile -Key:$TempKeyName -Path:$OriginalPath -Destination:$EncryptedPath -Force;

$DecryptedPath = [System.IO.Path]::GetTempFileName();

ConvertFrom-EncryptedFile -Path:$EncryptedPath -Destination:$DecryptedPath -Force;

if ([System.IO.File]::ReadAllText($OriginalPath) -ceq [System.IO.File]::ReadAllText($DecryptedPath)) {
    'Decryption successful.' | Write-Output;
} else {
    'Decryption failed.' | Write-Warning;
}

Remove-PublicKey -Name:$TempKeyName;