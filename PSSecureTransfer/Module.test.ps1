if ((Get-Module -Name:'PSSecureTransfer') -ne $null) { Remove-Module -Name:'PSSecureTransfer' }
Import-Module -Name:'PSSecureTransfer';

$TempKeyName = [Guid]::NewGuid().ToString('N');
$KeyExportPath = [System.IO.Path]::GetTempPath() | Join-Path -ChildPath:$TempKeyName;

Export-PublicKey -Path:$KeyExportPath;
Import-PublicKey -Path:$KeyExportPath;

$SourcePath = [System.IO.Path]::GetTempFileName();
$EncryptedPath = [System.IO.Path]::GetTempFileName();

$Random = New-Object -TypeName:'System.Random';
$StringBuilder = New-Object -TypeName:'System.Text.StringBuilder';
for ($i= 0; $i -lt 4096; $i++) {
	[char]$c = $Random.Next(255);
	$StringBuilder.Append($c) | Out-Null;
}
[System.IO.File]::WriteAllText($SourcePath, $StringBuilder.ToString());
ConvertTo-EncryptedFile -Key:$TempKeyName -Path:$SourcePath -Destination:$EncryptedPath -Force;

$DecryptedPath = [System.IO.Path]::GetTempFileName();

ConvertFrom-EncryptedFile -Path:$EncryptedPath -Destination:$DecryptedPath -Force;

if ([System.IO.File]::ReadAllText($SourcePath) -ceq [System.IO.File]::ReadAllText($DecryptedPath)) {
    'Decryption successful.' | Write-Output;
} else {
    'Decryption failed.' | Write-Warning;
}

Remove-PublicKey -Name:$TempKeyName;