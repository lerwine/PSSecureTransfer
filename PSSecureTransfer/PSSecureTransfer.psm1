try
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Cryptography");
}
catch 
{
    Write-Error "Could not load required assembly.";
    Return;
}

$Script:LastLocalBackup = $null;

Function Get-AppDataPath {
    Param(
        [switch]$Local
    )
    $SpecialFolder = &{ if ($Local) { [System.Environment+SpecialFolder]::LocalApplicationData } else { [System.Environment+SpecialFolder]::ApplicationData } };
    $AppDataPath = [System.Environment]::GetFolderPath($SpecialFolder) | Join-Path -ChildPath:'Leonard T. Erwine';
    if (-not (Test-Path $AppDataPath)) { New-Item -Path:$AppDataPath -ItemType:'Directory' | Out-Null }
    $AppDataPath = $AppDataPath | Join-Path -ChildPath:'PowerShell';
    if (-not (Test-Path $AppDataPath)) { New-Item -Path:$AppDataPath -ItemType:'Directory' | Out-Null }
    $AppDataPath = $AppDataPath | Join-Path -ChildPath:'PSSecureTransfer';
    if (-not (Test-Path $AppDataPath)) { New-Item -Path:$AppDataPath -ItemType:'Directory' | Out-Null }
    $AppDataPath | Write-Output;
}

Function ConvertTo-SafeFileName {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string[]]$InputText,
        
        [switch]$AllowExtension,
        
        [switch]$IgnorePathSeparatorChars
    )
    
    Begin {
        [char[]]$InvalidFileNameChars = [System.IO.Path]::GetInvalidFileNameChars();
        if ($IgnorePathSeparatorChars) {
            [char[]]$InvalidFileNameChars = $InvalidFileNameChars | Where-Object { $char -ne [System.IO.Path]::DirectorySeparatorChar -and $char -ne [System.IO.Path]::AltDirectorySeparatorChar };
        }
        if ($InvalidFileNameChars -notcontains '_') { [char[]]$InvalidFileNameChars += [char]'_' }
        if (-not $AllowExtension) { [char[]]$InvalidFileNameChars += [char]'.' }
    }
    
    Process {
        foreach ($text in $InputText) {
            if ($text -ne $null -and $text.Length -gt 0) {
                $StringBuilder = New-Object -TypeName:'System.Text.StringBuilder';
                foreach ($char in $text.ToCharArray()) {
                    if ($InvalidFileNameChars -contains $char) {
                        $StringBuilder.AppendFormat('_0x{0:x2}_', [int]$char) | Out-Null;
                    } else {
                        $StringBuilder.Append($char) | Out-Null;
                    }
                }
                
                $StringBuilder.ToString() | Write-Output;
            }
        }
    }
}

Function ConvertFrom-SafeFileName {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string[]]$InputText
    )
    
    Begin {
        $Regex = New-Object -TypeName:'System.Text.RegularExpressions.Regex' -ArgumentList:('_0x(?<hex>[\da-f]{2})_',
            ([System.Text.RegularExpressions.RegexOptions]::Compiled -bor [System.Text.RegularExpressions.RegexOptions]::Ignorecase));
    }
    
    Process {
        foreach ($text in $InputText) {
            if ($text -ne $null -and $text.Length -gt 0) {
                $MatchCollection = $Regex.Matches($text);
                if ($MatchCollection.Count -eq 0) {
                    $text | Write-Output;
                } else {
                    $StringBuilder = New-Object -TypeName:'System.Text.StringBuilder';
                    $previousEnd = 0;
                    $MatchCollection | ForEach-Object {
                        $Match = $_;
                        if ($Match.Index -gt $previousEnd) { $StringBuilder.Append($text.SubString($previousEnd, $Match.Index - $previousEnd)) | Out-Null }
                        [char]$char = [System.Convert]::ToInt32($Match.Groups['hex'].Value, 16);
                        $StringBuilder.Append($char) | Out-Null;
                        $previousEnd = $Match.Index + $Match.Length;
                    }
                    
                    if ($previousEnd -lt $text.Length) { $StringBuilder.Append($text.SubString($previousEnd)) }
                
                    $StringBuilder.ToString() | Write-Output;
                }
            }
        }
    }
}

Function Get-PersonalKeyPaths {
    $PrivateKeyPath = Get-AppDataPath | Join-Path -ChildPath:'Private.pkey';
    $PublicKeyPath = Get-AppDataPath | Join-Path -ChildPath:'Public.pkey';
    if (-not (Test-Path $PrivateKeyPath)) {
        $RSA = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048);
        [IO.File]::WriteAlltext($PrivateKeyPath, ($RSA.ToXMLString($true) | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString));
        [IO.File]::WriteAlltext($PublicKeyPath, $RSA.ToXMLString($false));
        $RSA.Dispose;
    }

    @{
        PrivateKeyPath = $PrivateKeyPath;
        PublicKeyPath = $PublicKeyPath;
    } | Write-Output;
}

Function Get-KeyPath {
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$Name
    )

    if ($Name -eq $null -or $Name -eq '') {
        $PersonalKeyPaths = Get-PersonalKeyPaths;
        $PersonalKeyPaths.PublicKeyPath | Write-Output;
    } else {
        $Path = Get-AppDataPath | Join-Path -ChildPath:($Name | ConvertTo-SafeFileName);
        if (-not $Path.ToLower().EndsWith('.key')) {
            if ($Path.EndsWith('.')) {
                $Path += 'key';
            } else {
                $Path += '.key';
            }
        }
        $Path | Write-Output;
    }
}

Function Import-PublicKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path,

        [switch]$Force
    )

    if (-not (Test-Path -Path:$Path)) {
        throw 'File not found.';
        return;
    }

    [xml]$xml = [IO.File]::ReadAllText($Path).Trim();
    $Destination = Get-KeyPath -Name:([System.IO.Path]::GetFileNameWithoutExtension($Path));

    if ($Force) {
        Copy-Item -Path:$Path -Destination:$Destination -Force -ErrorAction:Stop;
    } else {
        Copy-Item -Path:$Path -Destination:$Destination -ErrorAction:Stop;
    }
}

Function Get-PublicKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$Name
    )

    if ($Name -eq $null -or $Name -eq '') {
        [IO.File]::ReadAllText((Get-KeyPath)).Trim() | Write-Output;
    } else {
        $Path = Get-KeyPath -Name:$Name;
        if (Test-Path -Path:$Path) {
            [IO.File]::ReadAllText($Path).Trim() | Write-Output;
        }
    }
}

Function Export-PublicKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$Name,
        [switch]$Force
    )
    
    if ((Test-Path -Path:$Path) -and (-not $Force)) {
        throw 'File already exists.';
        return;
    }

    $PublicKey = &{
        if ($Name -ne $null -and $Name -ne '') {
            Get-PublicKey -Name:$Name;
        } else {
            Get-PublicKey;
        }
    };

    if ($PublicKey -eq $null) {
        throw 'Key not found.';
        return;
    }

    [IO.File]::WriteAllText($Path, $PublicKey);
}

Function Show-PublicKeys {
    [CmdletBinding()]
    Param()

    Get-ChildItem -Path:(Get-AppDataPath) -Filter:'*.key' | ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) }
}

Function Remove-PublicKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Name
    )
    
    $Path = Get-KeyPath -Name:$Name;
    if (Test-Path -Path:$Path) {
        Remove-Item -Path:$Path;
    } else {
        throw 'File not found.';
    }
}

Function ConvertTo-EncryptedFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Key,
        
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Path,
        
        [Parameter(Mandatory = $true, Position = 2)]
        [string]$Destination,

        [switch]$Force
    )

    $PublicKey = Get-PublicKey -Name:$Key;
    if ($PublicKey -eq $null) {
        throw 'Key not found.';
        return;
    }
    
    if (-not (Test-Path -Path:$Path)) {
        throw 'File not found.';
        return;
    }

    if ((Test-Path -Path:$Destination) -and (-not $Force)) {
        throw 'File already exists.';
        return;
    }

    $RSA = New-Object -TypeName:'System.Security.Cryptography.RSACryptoServiceProvider' -ArgumentList:2048;
    try {
        $RSA.FromXMLString($PublicKey);
    } catch {
        throw 'Invalid public key';
        $RSA.Dispose();
        $RSA = $null;
    }

    if ($RSA -eq $null) { return }
    
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
        $SourceFS = New-Object -TypeName:System.IO.FileStream -ArgumentList:$Path, ([IO.FileMode]::Open);
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
    if (Test-Path $Destination) { Remove-Item -Path:$Destination -Force }
    [IO.File]::WriteAllText($Destination, [Convert]::ToBase64String($EncryptedFS.ToArray(), ([Base64FormattingOptions]::InsertLineBreaks)));
    $EncryptedFS.Close();
    $EncryptedFS.Dispose();
}

Function ConvertFrom-EncryptedFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path,
        
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Destination,

        [switch]$Force
    )
    
    if (-not (Test-Path -Path:$Path)) {
        throw 'File not found.';
        return;
    }

    if ((Test-Path -Path:$Destination) -and (-not $Force)) {
        throw 'File already exists.';
        return;
    }

    $PersonalKeyPaths = Get-PersonalKeyPaths;
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
            [IO.File]::ReadAllText($PersonalKeyPaths.PrivateKeyPath) | Write-Output;
        }
        catch
        {
            Write-Error "Error reading private key";
            throw;
        }
    };
    if ($encryptedPrivateKey -eq $null) { return }

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

    $encodedData = [IO.File]::ReadAllText($Path);

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
        $EncryptedFS.Read($KeyEncrypted, 0, $KeyLengthValue) | Out-Null;
        $EncryptedFS.Read($IV, 0, $IVLengthValue) | Out-Null;
        $KeyDecrypted = $RSA.Decrypt($KeyEncrypted, $false);
        $transform = $rjndl.CreateDecryptor($KeyDecrypted, $IV);
    }
    catch
    {
    }

    $DestinationFS = $null;
    try
    {
        $DestinationFS = New-Object -Typename:System.IO.FileStream -ArgumentList:$Destination, ([System.IO.FileMode]::Create);
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
}
