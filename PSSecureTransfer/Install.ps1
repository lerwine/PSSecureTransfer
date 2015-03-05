$Script:ModuleName = 'PSSecureTransfer';

Function Read-YesOrNo {
    Param(
        [string]$Caption,
        [string]$Message,
        [bool]$DefaultValue
    )

    $YesOrNO = $Host.UI.PromptForChoice($Caption, $Message, @(
        (New-Object -TypeName:'System.Management.Automation.Host.ChoiceDescription' -ArgumentList:'Yes'),
        (New-Object -TypeName:'System.Management.Automation.Host.ChoiceDescription' -ArgumentList:'No')
    ), (&{ if ($DefaultValue) { 0 } else { 1 } }));

    return $YesOrNO -ne $null -and $YesOrNO -eq 0;
}

# for compatibility with older version of PowerShell
if ($PSScriptRoot -eq $null -or $PSScriptRoot -eq '') {
    $PSScriptRoot = $MyInvocation.InvocationName;
}

$InstallOptions = @(
    $index = 1;
    foreach ($path in $env:PSModulePath.Split([System.IO.Path]::PathSeparator)) {
        if ($path.Length -gt 0) {
            $Item = New-Object -TypeName:'System.Management.Automation.Host.ChoiceDescription' -ArgumentList:($index.ToString(), $path);
            $Item | Add-Member -Name:'Index' -MemberType:NoteProperty -Value:$Index;
            $Item | Add-Member -Name:'ModuleFolderPath' -MemberType:NoteProperty -Value:($path | Join-Path -ChildPath:($Script:ModuleName));
            $MyInvocation.InvocationName | Write-Host;
            $Item.ModuleFolderPath | Write-Host;
            $Item | Add-Member -Name:'ManifestSource' -MemberType:NoteProperty -Value:($PSScriptRoot | Join-Path -ChildPath:($Script:ModuleName + '.psd1'));
            $Item | Add-Member -Name:'ManifestPath' -MemberType:NoteProperty -Value:($Item.ModuleFolderPath | Join-Path -ChildPath:($Script:ModuleName + '.psd1'));
            $Item | Add-Member -Name:'ModuleScriptSource' -MemberType:NoteProperty -Value:($PSScriptRoot | Join-Path -ChildPath:($Script:ModuleName + '.psm1'));
            $Item | Add-Member -Name:'ModuleScriptPath' -MemberType:NoteProperty -Value:($Item.ModuleFolderPath | Join-Path -ChildPath:($Script:ModuleName + '.psm1'));
            $index++;
            $Item | Write-Output;
        }
    }
);
Int32 PromptForChoice(System.String, System.String, System.Collections.ObjectModel.Collection`1[System.Management.Autom
ation.Host.ChoiceDescription], Int32)
System.Collections.ObjectModel.Collection`1[System.Int32] PromptForChoice(System.String, System.String, System.Collecti
ons.ObjectModel.Collection`1[System.Management.Automation.Host.ChoiceDescription], System.Collections.Generic.IEnumerab
le`1[System.Int32])
$choices = $InstallOptions + (New-Object -TypeName:'System.Management.Automation.Host.ChoiceDescription' -ArgumentList:("0", "(cancel)"));
$index = $Host.UI.PromptForChoice("Installation Location", (@(
    'Select root path for module installation';
    '';
    $choices | ForEach-Object { '{0}: {1}' -f $_.Label, $_.ModuleFolderPath }) | Out-String).Trim(), $choices, $choices.Count - 1);
if ($index -eq $null -or $index -lt 0 -or $index -ge $choices.Count -or $choices[$index].Path -eq $null) {
    return;
}

$index++;

$hasFolderToRemove = $false;

$actionMessages = @(
    'The following actions will be taken:' | Write-Output;
    '' | Write-Output;

    foreach ($Item in $InstallOptions) {
        $Item | Add-Member -Name:'IsSelected' -MemberType:NoteProperty -Value:($_.Index -eq $index);
        if (Test-Path -Path:($Item.ModuleFolderPath)) {
            $verb = &{ if ($Item.IsSelected) { 'overwrite' } else { 'remove' } };
            if ((Test-Path -Path:($Item.ManifestPath)) -or (Test-Path -Path:($Item.ModuleScriptPath))) {
                if (-not (Read-YesOrNo -Caption:'Remove Module?' -Message:(@(
                            'An existing module was found at the following location:',
                            '',
                            $Item.ModuleFolderPath,
                            '',
                            ('Do you want to {0} this module?' -f $verb)
                        ) | Out-String).Trim() -DefaultValue:$false)) {
                    'Aborted.' | Write-Warning;
                    return;
                }
            } else {
                if (-not (Read-YesOrNo -Caption:'Remove Folder?' -Message:(@(
                            'An existing folder using the same target name was found at the following location:',
                            '',
                            $Item.ModuleFolderPath,
                            '',
                            ('Do you want to {0} this folder?' -f $verb)
                        ) | Out-String).Trim() -DefaultValue:$false)) {
                    'Aborted.' | Write-Warning;
                    return;
                }
            }
        
            if ($Item.IsSelected) {
                $Item | Add-Member -Name:'RemoveFolder' -MemberType:NoteProperty -Value:$false;
            } else {
                ('Remove {0}' -f $Item.ModuleFolderPath) | Write-Output;
                $Item | Add-Member -Name:'RemoveFolder' -MemberType:NoteProperty -Value:$true;
                $hasFolderToRemove = $true;
            }
        } else {
            if ($Item.IsSelected) {
                ('Create {0}' -f $Item.ModuleFolderPath) | Write-Output;
            }
            $Item | Add-Member -Name:'RemoveFolder' -MemberType:NoteProperty -Value:$false;
        }

        if ($Item.IsSelected) {
            if (Test-Path -Path:($Item.ModuleFolderPath)) {
                Get-ChildItem -Path:$Item.ModuleFolderPath | ForEach-Object {
                    if ($_.FullName -ine $Item.ManifestPath -and $_.FullName -ine $Item.ModuleScriptPath) {
                        ('Remove {0}' -f $_.FullName) | Write-Output;
                    }
                }
            }
            if (Test-Path -Path:($Item.ManifestPath)) {
                ('Overwrite {0}' -f $Item.ManifestPath) | Write-Output;
            } else {
                ('Install {0}' -f $Item.ManifestPath) | Write-Output;
            }
            if (Test-Path -Path:($Item.ModuleScriptPath)) {
                ('Overwrite {0}' -f $Item.ModuleScriptPath) | Write-Output;
            } else {
                ('Install {0}' -f $Item.ModuleScriptPath) | Write-Output;
            }
        }
    }
    
    '' | Write-Output;

    'Do you want to proceed?' | Write-Output;
);

if (-not (Read-YesOrNo -Caption:'Confirm Actions' -Message:($actionMessages | Out-String).Trim() -DefaultValue:$false)) {
    'Aborted.' | Write-Warning;
    return;
}

$ToRemove = @($InstallOptions | Where-Object { $_.RemoveFolder });

if ($ToRemove.Count -gt 0) {
    $index = 0;
    foreach ($Item in $ToRemove) {
        Write-Progress -Activity:'Remove Folders' -Status:'In Progress' -CurrentOperation:('Remove {0}' -f $Item.ModuleFolderPath) -PercentComplete:(($index * 100) / $ToRemove.Count);
        $index++;
        Remove-Item -Path:($Item.ModuleFolderPath) -Force;
        if (Test-Path -Path:($Item.ModuleFolderPath)) {
            Write-Progress -Activity:'Remove Folders' -Status:'Failed' -CurrentOperation:('Remove {0}' -f $Item.ModuleFolderPath) -PercentComplete:100 -Completed;
            ('Failed to remove {0}' -f $Item.ModuleFolderPath) | Write-Warning;
            'Aborted.' | Write-Warning;
            return;
        }
    }

    Write-Progress -Activity:'Remove Folders' -Status:'Success' -PercentComplete:100 -Completed;
}

$Item = $InstallOptions | Where-Object { $_.IsSelected };

$actionCount = 2;
$completedCount = 1;
if (Test-Path -Path:($Item.ModuleFolderPath)) {
    $actionCount = 3;
    Write-Progress -Activity:'Install Module' -Status:'In Progress' -CurrentOperation:('Create {0}' -f $Item.ModuleFolderPath) -PercentComplete:0;
    New-Item -Path:($Item.ModuleFolderPath) -ItemType:Directory;
    if (-not (Test-Path -Path:($Item.ModuleFolderPath))) {
        Write-Progress -Activity:'Install Module' -Status:'Failed' -CurrentOperation:('Create {0}' -f $Item.ModuleFolderPath) -PercentComplete:100 -Completed;
        ('Failed to create {0}' -f $Item.ModuleFolderPath) | Write-Warning;
        'Aborted.' | Write-Warning;
        return;
    }
} else {
    Write-Progress -Activity:'Install Module' -Status:'In Progress' -CurrentOperation:('Replace contents of {0}' -f $Item.ModuleFolderPath) -PercentComplete:0;
    $ToDelete = @(Get-ChildItem -Path:($Item.ModuleFolderPath) | Where-Object { $_.FullName -ine $Item.ManifestPath -and $_.FullName -ine $Item.ModuleScriptPath });
    $actionCount += $ToDelete.Count;
    if ($ToDelete.Count -gt 0) {
        $ToDelete | ForEach-Object {
            Write-Progress -Activity:'Install Module' -Status:'In Progress' -CurrentOperation:('Delete {0}' -f $_.FullName) -PercentComplete:(($completedCount * 100) / $actionCount);
            $completedCount++;
            Remove-Item -Path:($_.FullName) -Force;
            if (Test-Path -Path:($_.FullName)) {
                Write-Progress -Activity:'Install Module' -Status:'Failed' -CurrentOperation:('Remove {0}' -f $_.FullName) -PercentComplete:100 -Completed;
                ('Failed to remove {0}' -f $_.FullName) | Write-Warning;
                'Aborted.' | Write-Warning;
                return;
            }
        }
    }
}

if (Test-Path -Path:($Item.ManifestPath)) {
    Write-Progress -Activity:'Install Module' -Status:'In Progress' -CurrentOperation:('Overwrite {0}' -f $Item.ManifestPath) -PercentComplete:(($completedCount * 100) / $actionCount);
    $completedCount++;

    Try {
        Copy-Item -Path:($Item.ManifestSource) -Destination:($Item.ManifestPath) -ErrorAction:Stop -Force;
    } Catch {
        Write-Progress -Activity:'Install Module' -Status:'Failed' -CurrentOperation:('Overwrite {0}' -f $Item.ManifestPath) -PercentComplete:100 -Completed;
        ('Failed to overwrite {0}' -f $Item.ManifestPath) | Write-Warning;
        'Aborted.' | Write-Warning;
        return;
    }
} else {
    Write-Progress -Activity:'Install Module' -Status:'In Progress' -CurrentOperation:('Install {0}' -f $Item.ManifestPath) -PercentComplete:(($completedCount * 100) / $actionCount);
    $completedCount++;

    Try {
        Copy-Item -Path:($Item.ManifestSource) -Destination:($Item.ManifestPath) -ErrorAction:Stop;
    } Catch {
        Write-Progress -Activity:'Install Module' -Status:'Failed' -CurrentOperation:('Overwrite {0}' -f $Item.ManifestPath) -PercentComplete:100 -Completed;
        ('Failed to install {0}' -f $Item.ManifestPath) | Write-Warning;
        'Aborted.' | Write-Warning;
        return;
    }
}

if (Test-Path -Path:($Item.ModuleScriptPath)) {
    Write-Progress -Activity:'Install Module' -Status:'In Progress' -CurrentOperation:('Overwrite {0}' -f $Item.ModuleScriptPath) -PercentComplete:(($completedCount * 100) / $actionCount);
    $completedCount++;

    Try {
        Copy-Item -Path:($Item.ModuleScriptSource) -Destination:($Item.ModuleScriptPath) -ErrorAction:Stop -Force;
    } Catch {
        Write-Progress -Activity:'Install Module' -Status:'Failed' -CurrentOperation:('Overwrite {0}' -f $Item.ModuleScriptPath) -PercentComplete:100 -Completed;
        ('Failed to overwrite {0}' -f $Item.ModuleScriptPath) | Write-Warning;
        'Aborted.' | Write-Warning;
        return;
    }
} else {
    Write-Progress -Activity:'Install Module' -Status:'In Progress' -CurrentOperation:('Install {0}' -f $Item.ModuleScriptPath) -PercentComplete:(($completedCount * 100) / $actionCount);
    $completedCount++;

    Try {
        Copy-Item -Path:($Item.ModuleScriptSource) -Destination:($Item.ModuleScriptPath) -ErrorAction:Stop;
    } Catch {
        Write-Progress -Activity:'Install Module' -Status:'Failed' -CurrentOperation:('Overwrite {0}' -f $Item.ModuleScriptPath) -PercentComplete:100 -Completed;
        ('Failed to install {0}' -f $Item.ModuleScriptPath) | Write-Warning;
        'Aborted.' | Write-Warning;
        return;
    }
}

Write-Progress -Activity:'Install Module' -Status:'Success' -PercentComplete:100 -Completed;
'Completed.' | Write-Host;