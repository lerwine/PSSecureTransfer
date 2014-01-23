Param(
    [Parameter(Mandatory=$false, Position=0)]
    [String]$PrivateKeyFile = 'C:\Users\Leonard\Documents\WindowsPowerShell\Apps\SecureTransfer0-1\MyPrivateKey.txt',
    
    [Parameter(Mandatory=$false, Position=1)]
    [String]$SourceFile = 'C:\Users\Leonard\Documents\WindowsPowerShell\Apps\SecureTransfer0-1\EncryptedSource.txt',
    
    [Parameter(Mandatory=$false, Position=2)]
    [String]$OutputFile = 'C:\Users\Leonard\Documents\WindowsPowerShell\Apps\SecureTransfer0-1\DecryptedOutput.bin'
)

$error.clear();

if ($PrivateKeyFile -eq "" -or $SourceFile -eq "" -or $OutputFile -eq "")
{
    Write-Error "Syntax: DecryptFile [PrivateKeyFile] [SourceFile] [OutputFile]";
    Return;
}


try
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Cryptography");
}
catch 
{
    Write-Error "Could not load required assembly.";
    $error;
    Return;
}

$RSA = &{
    try
    {
        New-Object -TypeName:System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList:2048;
    }
    catch
    {
        Write-Error "Error creating RSA service provider";
        throw;
    }
};
if ($RSA -eq $null) { return }

$encryptedPrivateKey = &{
    try
    {
        [IO.File]::ReadAllText($PrivateKeyFile) | Write-Output;
    }
    catch
    {
        Write-Error "Error reading private key";
        throw;
    }
};
if ($encryptedPrivateKey -eq $null) { return }
Write-Host "Got $encryptedPrivateKey $($encryptedPrivateKey.GetType().FullName)";

$securePrivateKey = &{
    try
    {
        $encryptedPrivateKey.Trim() | ConvertTo-SecureString | Write-Output;
    }
    catch
    {
        Write-Error "Error decrypting private key";
        throw;
    }
};
if ($securePrivateKey -eq $null) { return }

try
{
    $RSA.FromXMLString([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePrivateKey)));
}
catch
{
    Write-Error "Error initializing from private key";
    $securePrivateKey = $null;
    throw;
}
if ($securePrivateKey -eq $null) { return }

$rjndl = New-Object -Typename:System.Security.Cryptography.RijndaelManaged;
$rjndl.KeySize = 256;
$rjndl.BlockSize = 256;
$rjndl.Mode = [System.Security.Cryptography.CipherMode]::CBC;
$KeyLengthData = New-Object -Typename:Byte[] -ArgumentList:4;
$IVLengthData = New-Object -Typename:Byte[] -ArgumentList:4;
#$lKey = $keyEncrypted.Length;
#$KeyLengthData = [System.BitConverter]::GetBytes($lKey);
#$lIV = $rjndl.IV.Length;
#$IVLengthData = [System.BitConverter]::GetBytes($lIV);

$encodedData = [IO.File]::ReadAllText($SourceFile);

$EncryptedFS = $null;
try
{
    $argArray = @(, [Convert]::FromBase64String($encodedData));
    $EncryptedFS = New-Object -Typename:System.IO.MemoryStream -ArgumentList:$argArray;
}
catch
{
    Write-Error "Error reading source file";
    $error;
    Return;
}

$count = 0;

try
{
    $count = $EncryptedFS.Read($KeyLengthData, 0, 4);
}
catch
{
    Write-Error "Error reading from source file";
    $error;
    Return;
}

if ($count -eq 0)
{
    Write-Error "Source data length error";
    Return;
}

try
{
    $count = $EncryptedFS.Read($IVLengthData, 0, 4);
}
catch
{
    Write-Error "Error reading from source file";
    $error;
    Return;
}

if ($count -eq 0)
{
    Write-Error "Source data length error";
    Return;
}

$transform = $null;
try
{
    $KeyLengthValue = [System.BitConverter]::ToInt32($KeyLengthData, 0);
    $IVLengthValue = [System.BitConverter]::ToInt32($IVLengthData, 0);

    # $startC = $KeyLengthValue + $IVLengthValue + 8;
    # $lenC = $EncryptedFS.Length - $startC;

    $KeyEncrypted = New-Object -Typename:Byte[] -ArgumentList:$KeyLengthValue;
    $IV = New-Object -Typename:Byte[] -ArgumentList:$IVLengthValue;
    $EncryptedFS.Read($KeyEncrypted, 0, $KeyLengthValue);
    $EncryptedFS.Read($IV, 0, $IVLengthValue);
    $KeyDecrypted = $RSA.Decrypt($KeyEncrypted, $false);
    $transform = $rjndl.CreateDecryptor($KeyDecrypted, $IV);
}
catch
{
}

$DestinationFS = $null;
try
{
    $DestinationFS = New-Object -Typename:System.IO.FileStream -ArgumentList:$OutputFile, ([System.IO.FileMode]::Create);
}
catch
{
    Write-Error "Error creating output file";
    $EncryptedFS.Close();
    $EncryptedFS.Dispose();
    $error;
    Return;
}

$DecryptionStream = $null;
try
{
    $DecryptionStream = New-Object -Typename:System.Security.Cryptography.CryptoStream -ArgumentList:$DestinationFS, $transform, ([System.Security.Cryptography.CryptoStreamMode]::Write);
}
catch
{
    Write-Error "Error creating decryption output stream";
    $EncryptedFS.Close();
    $EncryptedFS.Dispose();
    $DestinationFS.Close();
    $DestinationFS.Dispose();
    $error;
    Return;
}

try
{
    $blockSizeBytes = $rjndl.BlockSize / 8;
    $data = New-Object Byte[] $blockSizeBytes;
    $count = 0;
    $offset = 0;
    $bytesRead = 0;
    
    do
    {
        $count = $EncryptedFS.Read($data, 0, $blockSizeBytes);
        $offset += $count;
        $DecryptionStream.Write($data, 0, $count);
        $bytesRead += $blockSizeBytes;
    } While ($count -gt 0);
}
catch
{
    Write-Error "Error writing decrypted data";
}
$EncryptedFS.Close();
$EncryptedFS.Dispose();
$DecryptionStream.FlushFinalBlock();
$DecryptionStream.Close();
$DecryptionStream.Dispose();
$DestinationFS.Close();
$DestinationFS.Dispose();