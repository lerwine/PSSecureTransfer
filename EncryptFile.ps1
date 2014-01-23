Param(
    [Parameter(Mandatory=$false, Position=0)]
    [String]$PublicKeyFile = 'C:\Users\Leonard\Documents\WindowsPowerShell\Apps\SecureTransfer0-1\LTEUDIFkey.txt',
    
    [Parameter(Mandatory=$false, Position=1)]
    [String]$SourceFile = 'C:\Users\Leonard\Documents\WindowsPowerShell\Apps\SecureTransfer0-1\Source.bin',
    
    [Parameter(Mandatory=$false, Position=2)]
    [String]$OutputFile = 'C:\Users\Leonard\Documents\WindowsPowerShell\Apps\SecureTransfer0-1\EncryptedOutput.txt'
)

$error.clear();

if ($PublicKeyFile -eq "" -or $SourceFile -eq "" -or $OutputFile -eq "")
{
   Write-Error "Syntax: EncryptFile [PublicKeyFile] [SourceFile] [OutputFile]";
   Return;
}

try
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Cryptography");
}
catch 
{
    Write-Error "Could not load required assembly.";
    Return;
}

$RSA = $null;
try
{
    $RSA = New-Object -TypeName:System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList:2048;
}
catch
{
    Write-Error "Error creating RSA service provider";
    Return;
}

try
{
    $xmlData = [IO.File]::ReadAllText($PublicKeyFile).Trim();
}
catch
{
    Write-Error "Error reading public key";
    Return;
}

try
{
    $RSA.FromXMLString($xmlData);
}
catch
{
    Write-Error "Error initializing from public key";
    Return;
}

$rjndl = New-Object -TypeName:System.Security.Cryptography.RijndaelManaged;
$rjndl.KeySize = 256;
$rjndl.BlockSize = 256;
$rjndl.Mode = [System.Security.Cryptography.CipherMode]::CBC;
$transform = $rjndl.CreateEncryptor();
$EncryptedKeyData = $rsa.Encrypt($rjndl.Key, $false);
$KeyLengthData = New-Object -TypeName:Byte[] -ArgumentList:4;
$IVLengthData = New-Object -TypeName:Byte[] -ArgumentList:4;
$KeyLengthValue = $EncryptedKeyData.Length;
$KeyLengthData = [System.BitConverter]::GetBytes($KeyLengthValue);
$IVLengthValue = $rjndl.IV.Length;
$IVLengthData = [System.BitConverter]::GetBytes($IVLengthValue);
$SourceFS = $null;
try
{
    $SourceFS = New-Object -TypeName:System.IO.FileStream -ArgumentList:$SourceFile, ([IO.FileMode]::Open);
}
catch
{
    Write-Error "Error reading source file";
    $error;
    Return;
}
$EncryptedFS = $null;
try
{
    $EncryptedFS = New-Object -TypeName:System.IO.MemoryStream;
}
catch
{
    Write-Error "Error creating output file";
    $SourceFS.Close();
    $SourceFS.Dispose();
    $error;
    Return;
}

try
{
    $EncryptedFS.Write($KeyLengthData, 0, 4);
    $EncryptedFS.Write($IVLengthData, 0, 4);
    $EncryptedFS.Write($EncryptedKeyData, 0, $KeyLengthValue);
    $EncryptedFS.Write($rjndl.IV, 0, $IVLengthValue);
}
catch
{
    Write-Error "Error writing encrypted heading";
    $SourceFS.Close();
    $SourceFS.Dispose();
    $EncryptedFS.Close();
    $EncryptedFS.Dispose();
    $error;
    Return;
}

$EncryptionStream = $null;
try
{
    $EncryptionStream = New-Object -TypeName:System.Security.Cryptography.CryptoStream -ArgumentList:$EncryptedFS, $transform, ([System.Security.Cryptography.CryptoStreamMode]::Write);
}
catch
{
    Write-Error "Error creating encryption output stream";
    $SourceFS.Close();
    $SourceFS.Dispose();
    $EncryptedFS.Close();
    $EncryptedFS.Dispose();
    $error;
    Return;
}

try
{
    $blockSizeBytes = $rjndl.BlockSize / 8;
    $data = New-Object -TypeName:Byte[] $blockSizeBytes;
    $count = 0;
    $offset = 0;
    $bytesRead = 0;
    
    do
    {
        $count = $SourceFS.Read($data, 0, $blockSizeBytes);
        $offset += $count;
        $EncryptionStream.Write($data, 0, $count);
        $bytesRead += $blockSizeBytes;
    } While ($count -gt 0);
}
catch
{
    Write-Error "Error writing encrypted data";
    $error;
}
$SourceFS.Close();
$SourceFS.Dispose();
$EncryptionStream.FlushFinalBlock();
$EncryptionStream.Close();
$EncryptionStream.Dispose();
[IO.File]::WriteAllText($OutputFile, [Convert]::ToBase64String($EncryptedFS.ToArray(), ([Base64FormattingOptions]::InsertLineBreaks)));
$EncryptedFS.Close();
$EncryptedFS.Dispose();