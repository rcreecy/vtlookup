Import-Module ".\prompt\Write-Ascii.psm1"

# Draw welcome screen
function Welcome {
    Write-Host -ForegroundColor Red "`n`                         !"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Red "                         !"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Red "                         ^"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Red "                        / \"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Red "                       /___\"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                      |=   =|"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                      |     |"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                      |     |"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                      |     |"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                      |     |"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                      |     |"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                      |     |"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                      |     |"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                      |     |"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                      |     |"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                      |     |"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                     /|##!##|\"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                    / |##!##| \"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                   /  |##!##|  \"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                  |  / ^ | ^ \  |"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                  | /  ( | )  \ |"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                  |/   ( | )   \|"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                      ((   ))"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Green "                     ((  :  ))"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Yellow "                     ((  :  ))"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Yellow "                      ((   ))"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Yellow "                       (( ))"
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Yellow "                         ."
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Yellow "                         ."
    Start-Sleep -MilliSeconds 200
    Write-Host -ForegroundColor Yellow "                         ."
    Start-Sleep -MilliSeconds 600
    Write-Ascii "VIRUSTOTAL" -ForegroundColor Blue
    Start-Sleep -Milliseconds 400
    Write-Ascii "      LOOKUP" -ForegroundColor Green
    Start-Sleep -MilliSeconds 400
    Start-Sleep -Milliseconds 300
    VTSubmissions
}

# VIRUSTOTAL API SCRIPTS
$VTApiKey = "bd3033ff119fc586a8b4fa36fac3a2dc92ec66846d207b9ec32588bbd64f25b3"
Add-Type -AssemblyName System.Security

function Set-VTApiKey {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true)][ValidateNotNull()][String] $VTApiKey,
    [String] $vtFileLocation = $(Join-Path $env:APPDATA 'virustotal.bin'))
    $inBytes = [System.Text.Encoding]::Unicode.GetBytes($VTApiKey)
    $protected = [System.Security.Cryptography.ProtectedData]::Protect($inBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllBytes($vtfileLocation, $protected)
}

function Get-VTApiKey {
    [CmdletBinding()]
    Param([String] $vtFileLocation = $(Join-Path $env:APPDATA 'virustotal.bin'))
    if (Test-Path $vtfileLocation) {
        $protected = [System.IO.File]::ReadAllBytes($vtfileLocation)
        $rawKey = [System.Security.Cryptography.ProtectedData]::Unprotect($protected, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [System.Text.Encoding]::Unicode.GetString($rawKey)
    } else {
        throw "Call Set-VTApiKey first!"
    }
}

function Get-VTReport {
    [CmdletBinding()]
    Param( 
    [String] $VTApiKey = (Get-VTApiKey),
    [Parameter(ParameterSetName="hash", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $hash,
    [Parameter(ParameterSetName="file", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][System.IO.FileInfo] $file,
    [Parameter(ParameterSetName="uri", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][Uri] $uri,
    [Parameter(ParameterSetName="ipaddress", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $ip,
    [Parameter(ParameterSetName="domain", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $domain
    )
    Begin {
        $fileUri = 'https://www.virustotal.com/vtapi/v2/file/report'
        $UriUri = 'https://www.virustotal.com/vtapi/v2/url/report'
        $IPUri = 'http://www.virustotal.com/vtapi/v2/ip-address/report'
        $DomainUri = 'http://www.virustotal.com/vtapi/v2/domain/report'
       
        function Get-Hash(
            [System.IO.FileInfo] $file = $(Throw 'Usage: Get-Hash [System.IO.FileInfo]'), 
            [String] $hashType = 'sha256')
        {
          $stream = $null;  
          [string] $result = $null;
          $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($hashType )
          $stream = $file.OpenRead();
          $hashByteArray = $hashAlgorithm.ComputeHash($stream);
          $stream.Close();

          trap
          {
            if ($stream -ne $null) { $stream.Close(); }
            break;
          }

          # Convert the hash to Hex
          $hashByteArray | foreach { $result += $_.ToString("X2") }
          return $result
        }
    }
    Process {
        [String] $h = $null
        [String] $u = $null
        [String] $method = $null
        $body = @{}

        switch ($PSCmdlet.ParameterSetName) {
        "file" { 
            $h = Get-Hash -file $file
            Write-Verbose -Message ("FileHash:" + $h)
            $u = $fileUri
            $method = 'POST'
            $body = @{ resource = $h; apikey = $VTApiKey}
            }
        "hash" {            
            $u = $fileUri
            $method = 'POST'
            $body = @{ resource = $hash; apikey = $VTApiKey}
            }
        "uri" {
            $u = $UriUri
            $method = 'POST'
            $body = @{ url = $uri; apikey = $VTApiKey}
            }
        "ipaddress" {
            $u = $IPUri
            $method = 'GET'
            $body = @{ ip = $ip; apikey = $VTApiKey}
        }
        "domain" {            
            $u = $DomainUri
            $method = 'GET'
            $body = @{ domain = $domain; apikey = $VTApiKey}}
        }        

        return Invoke-RestMethod -Method $method -Uri $u -Body $body
    }    
}

function Invoke-VTScan {
    [CmdletBinding()]
    Param( 
    [String] $VTApiKey = (Get-VTApiKey),
    [Parameter(ParameterSetName="file", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [System.IO.FileInfo] $file,
    [Parameter(ParameterSetName="uri", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Uri] $uri
    )
    Begin {
        $fileUri = 'https://www.virustotal.com/vtapi/v2/file/scan'
        $UriUri = 'https://www.virustotal.com/vtapi/v2/url/scan'
        [byte[]]$CRLF = 13, 10

        function Get-AsciiBytes([String] $str) {
            return [System.Text.Encoding]::ASCII.GetBytes($str)            
        }
    }
    Process {
        [String] $h = $null
        [String] $u = $null
        [String] $method = $null
        $body = New-Object System.IO.MemoryStream

        switch ($PSCmdlet.ParameterSetName) {
        "file" { 
            $u = $fileUri
            $method = 'POST'
            $boundary = [Guid]::NewGuid().ToString().Replace('-','')
            $ContentType = 'multipart/form-data; boundary=' + $boundary
            $b2 = Get-AsciiBytes ('--' + $boundary)
            $body.Write($b2, 0, $b2.Length)
            $body.Write($CRLF, 0, $CRLF.Length)
            
            $b = (Get-AsciiBytes ('Content-Disposition: form-data; name="apikey"'))
            $body.Write($b, 0, $b.Length)

            $body.Write($CRLF, 0, $CRLF.Length)
            $body.Write($CRLF, 0, $CRLF.Length)
            
            $b = (Get-AsciiBytes $VTApiKey)
            $body.Write($b, 0, $b.Length)

            $body.Write($CRLF, 0, $CRLF.Length)
            $body.Write($b2, 0, $b2.Length)
            $body.Write($CRLF, 0, $CRLF.Length)
            
            $b = (Get-AsciiBytes ('Content-Disposition: form-data; name="file"; filename="' + $file.Name + '";'))
            $body.Write($b, 0, $b.Length)
            $body.Write($CRLF, 0, $CRLF.Length)            
            $b = (GgetAsciiBytes 'Content-Type:application/octet-stream')
            $body.Write($b, 0, $b.Length)
            
            $body.Write($CRLF, 0, $CRLF.Length)
            $body.Write($CRLF, 0, $CRLF.Length)
            
            $b = [System.IO.File]::ReadAllBytes($file.FullName)
            $body.Write($b, 0, $b.Length)

            $body.Write($CRLF, 0, $CRLF.Length)
            $body.Write($b2, 0, $b2.Length)
            
            $b = (Get-AsciiBytes '--')
            $body.Write($b, 0, $b.Length)
            
            $body.Write($CRLF, 0, $CRLF.Length)
            
                
            Invoke-RestMethod -Method $method -Uri $u -ContentType $ContentType -Body $body.ToArray()
            }
        "uri" {
            $h = $uri
            $u = $UriUri
            $method = 'POST'
            $body = @{ url = $uri; apikey = $VTApiKey}
            Invoke-RestMethod -Method $method -Uri $u -Body $body
            }            
        }                        
    }    
}

function New-VTComment {
    [CmdletBinding()]
    Param( 
    [String] $VTApiKey = (Get-VTApiKey),
    [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $hash,
    [Parameter(Mandatory=$true)][ValidateNotNull()][String] $Comment
    )

    Process {
        $u = 'https://www.virustotal.com/vtapi/v2/comments/put'
        $method = 'POST'
        $body = @{ resource = $hash; apikey = $VTApiKey; comment = $Comment}

        return Invoke-RestMethod -Method $method -Uri $u -Body $body
    }    
}

function Invoke-VTRescan {
 [CmdletBinding()]
    Param( 
    [String] $VTApiKey = (Get-VTApiKey),
    [Parameter(Mandatory=$true, ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $hash
    )
    Process {
        $u = 'https://www.virustotal.com/vtapi/v2/file/rescan'
        $method = 'POST'
        $body = @{ resource = $hash; apikey = $VTApiKey}
        return Invoke-RestMethod -Method $method -Uri $u -Body $body
    }    
}


#########################################
# Here is out Virus Total query code
#########################################
function LoopbackAfterPost {
    Write-Ascii "VT LOOKUP" -ForegroundColor Blue
    & VTSubmissions
}

function VTSubmissions {
    $FileType = Read-Host "`n`nHow would you like to conduct the sample lookup?`n(1) HASH`n(2) FILE`n(3) URL`n`n["
    if ($FileType -eq "1" -or $FileType -eq "HASH") {
        HashSubmit
    } elseif ($FileType -eq "2" -or $FileType -eq "FILE") {
        FileSubmit
    } elseif ($FileType -eq "3" -or $FileType -eq "URL") {
        UrlSubmit
    } elseif ($FileType -eq "exit") {
        Write-Ascii "Goodbye!" -ForegroundColor Green
        Write-Host "`n`n`n"
        Start-Sleep -Milliseconds 300
        exit
    } else {
        Write-Host "`nSelection Invalid! Please try again.`n" -ForegroundColor Red
        VTSubmissions
    }
}

function HashSubmit {
    Write-Ascii "#HASH" -ForegroundColor Green
    $FileHash = Read-Host "`nWhat is the file hash you would like to lookup?`nYou can also type 'back' to return to the menu`n["
    if ($FileHash -eq "back") {
        & LoopbackAfterPost
    } else {
        Get-VTReport -VTApiKey $VTApiKey -Hash $FileHash | select scan_date, md5, sha1, sha256, positives, total, permalink, scans
        HashSubmit
    }
}

function FileSubmit {
    Write-Ascii "C:\FILE" -ForegroundColor Green
    $FilePath = Read-Host "`nWhat is the path to the file you would like to submit? (Enter 'diag' for a popout dialog box)`nYou can also type 'back' to return to the menu`n["
    if ($FilePath -eq "diag") {
        $FilePathDirect = Get-Filename
        Get-VTReport -VTApiKey $VTApiKey -file $FilePathDirect | select scan_date, md5, sha1, sha256, positives, total, permalink, scans
    } elseif ($FilePath -eq "back") {
        & LoopbackAfterPost
    } else {
        Get-VTReport -VTApiKey $VTApiKey -file $FilePath | select scan_date, md5, sha1, sha256, positives, total, permalink, scans
    }
}

function UrlSubmit {
    Write-Ascii "http://url" -ForegroundColor Green
    $UrlPath = Read-Host "`nWhat is the URL path you would like to submit?`nYou can also type 'back' to return to the menu`n["
    if ($UrlPath -eq "back") {
        & LoopbackAfterPost
    } else {
        Get-VTReport -VTApiKey $VTApiKey -uri $FilePath | select scan_date, md5, sha1, sha256, positives, total, permalink, scans
    }
}

function Get-FileName($initialDirectory)
{   
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") |
    Out-Null

    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "All files (*.*)| *.*"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}

Welcome