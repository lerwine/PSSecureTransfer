Param(
    [Parameter(Mandatory=$false, Position=0)]
    [String]$PrivateKeyFile = '',
    
    [Parameter(Mandatory=$false, Position=1)]
    [String]$PublicKeyFile = ''
)

$PrivateKeyFile = $PrivateKeyFile.Trim();
$PublicKeyFile = $PublicKeyFile.Trim();

if ($PrivateKeyFile -eq "" -or $PublicKeyFile -eq "")
{
    Write-Error "Syntax: GenerateRSAKey [PrivateKeyFile] [PublicKeyFile]";
    Return;
}

try
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Cryptography");
}
catch 
{
    Write-Error "Could not load required assembly.";
    Return
}

$RSA = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048);
[IO.File]::WriteAlltext($PrivateKeyFile, ($RSA.ToXMLString($true) | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString));
[IO.File]::WriteAlltext($PublicKeyFile, $RSA.ToXMLString($false));
$RSA.Dispose;

Write-Host "Public and private keys generated.";
Write-Host "Warning: Never share the private key file with anyone and never transfer it over the network!";