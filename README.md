# VirusTotal Powershell Lookup
![Interface](/readme/gui.png)
![Example Lookup](/readme/use.PNG)

This tool provides a straightforward and ASCII happy powershell GUI to interact with Virustotal, through the API created by David B Heise and improved upon by [Dave Hull](https://github.com/davehull/VirusTotalShell)

The main purpose is to learn more about working with REST apis in powershell, as well as parsing returned data and overall understanding of building a valid and functional module.

It allows hash lookup, file lookup (with a windows popup dialog so full path entry is an option, but not a must), and URL lookup. Scanning is still a work in progress.

Place your VirusTotal API key in a api.txt file next to where you execute the script, and powershell will use the $PSScriptRoot variable to find your invocation path and read the output of the file. I left it at the top of the script so it's straightforward to change should you want too.
```powershell
$VTApiKey = [IO.file]::ReadAllText("$PSScriptRoot\api.txt")
```

One of the more useful and user-friendly options of this script is the use of the Windows file prompt, called from the below function.
```powershell
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
```

The current pitfall of the scan function is that VT returns a verbose_msg stating to return later for the report. I need to figure out a way to store the hash in a variable from the JSON return and allow it to be called directly from the "Scan" page with a 'prev' keyword, or ideally, simply sleep the script for a suitable time until the report can be returned. The latter would be heavily dependent on VT server load at the time of scan however, and may prove as a poor option from a optimization "my script is stuck in a hung state and god knows when it will proceed" nightmare.
```powershell
function FileScan {
    Write-Ascii "SCAN" -ForegroundColor Magenta
    $ScanHoldFinal = 1
    $FilePath = Read-Host "`nWhat is the path to the file you would like to scan? (Enter 'diag' for a popout dialog box, or 'prev' to grab a report on a previous scan)`n'prev' is currently not holding the last MD5 value correctly, but you can use the hash search for the report`nYou can also type 'back' to return to the menu, or 'exit' to leave.`n["
    if ($FilePath -eq "diag") {
        $FilePath = Get-Filename
        $ScanReturn = Invoke-VTScan -VTApiKey $VTApiKey -file $FilePath
        $ScanHold = $ScanReturn | select md5 | Tee-Object -Variable $ScanHoldFinal
        $ScanVerbose = $ScanReturn | select md5, verbose_msg
        $ScanVerbose
        FileScan
    } elseif ($FilePath -eq "back") {
        & LoopbackAfterPost
    } elseif ($FilePath -eq "prev") {
        if ($ScanHoldFinal -eq 1) {
            Write-Host "`nNo files have been scanned this session.`n" -ForegroundColor Red
            Filescan
        } else {
            Get-VTReport -VTApiKey $VTApiKey -hash $ScanHoldFinal
            FileScan
        }
    } elseif ($FilePAth -eq "exit") {
        Goodbye
    } else {
        Invoke-VTScan -VTApiKey $VTApiKey -file $FilePath  | select md5, sha1, sha256, verbose_msg, permalink
        $ScanHold = select md5
        FileScan
    }
}
```

You can find the Write-Ascii module used for the text output through out the script at [Powershell Admin](https://www.powershelladmin.com/wiki/Ascii_art_characters_powershell_script)