[System.Environment]::SetEnvironmentVariable('SPLUNK_HOME', 'C:\Program Files\SplunkUniversalForwarder')
[System.Environment]::SetEnvironmentVariable('SPLUNK_CERTS_DIR', $env:SPLUNK_HOME+'\etc\auth')
[System.Environment]::SetEnvironmentVariable('SPLUNK_EXE', $env:SPLUNK_HOME+'\bin\splunk.exe')

function check_web_conf_serverCert () {
    # File path
    Set-Variable -Name FILEPATH -Value ((& "$env:SPLUNK_EXE" btool web list --debug | Select-String -Pattern "serverCert") -split '\s\s+')[0]

    # File name
    Set-Variable -Name FILENAME -Value ($FILEPATH -split "\\")[-1]

    # Key
    Set-Variable -Name KEY -Value ((& "$env:SPLUNK_EXE" btool web list --debug | Select-String -Pattern "serverCert") -split '\s(\s+)?')[3]

    # Value
    Set-Variable -Name VALUE -Value (((& "$env:SPLUNK_EXE" btool web list --debug | Select-String -Pattern "serverCert") -split ' = ')[-1] -replace '\$SPLUNK_HOME', $env:SPLUNK_HOME -replace '\/', '\')

    # Hash
    if ($VALUE -and (Test-Path $VALUE)) {
        Set-Variable -Name HASH -Value (& "$env:SPLUNK_EXE" cmd openssl x509 -in $VALUE -hash -noout)
    }

    if ($FILEPATH.Length -ne 0) {
        Write-Ouput (
            (Get-Date -UFormat "%b %d %H:%M:%S %Z %Y")+" - "+(hostname)+" - "+
            "filename=$FILENAME, filepath=$FILEPATH, key=$KEY, value=$VALUE, ssl_hash=$HASH"
        )
    }
}

function check_web_conf_clientCert () {
    # File path
    Set-Variable -Name FILEPATH -Value ((& "$env:SPLUNK_EXE" btool web list --debug | Select-String -Pattern "clientCert") -split '\s\s+')[0]

    # File name
    Set-Variable -Name FILENAME -Value ($FILEPATH -split "\\")[-1]

    # Key
    Set-Variable -Name KEY -Value ((& "$env:SPLUNK_EXE" btool web list --debug | Select-String -Pattern "clientCert") -split '\s(\s+)?')[3]

    # Value
    Set-Variable -Name VALUE -Value (((& "$env:SPLUNK_EXE" btool web list --debug | Select-String -Pattern "clientCert") -split ' = ')[-1] -replace '\$SPLUNK_HOME', $env:SPLUNK_HOME -replace '\/', '\')

    # Hash
    if ($VALUE -and (Test-Path $VALUE)) {
        Set-Variable -Name HASH -Value (& "$env:SPLUNK_EXE" cmd openssl x509 -in $VALUE -hash -noout)
    }

    if ($FILEPATH.Length -ne 0) {
        Write-Output (
            (Get-Date -UFormat "%b %d %H:%M:%S %Z %Y")+" - "+(hostname)+" - "+
            "filename=$FILENAME, filepath=$FILEPATH, key=$KEY, value=$VALUE, ssl_hash=$HASH"
        )
    }
}


function check_server_conf_sslRootCAPath () {
    # File path
    Set-Variable -Name FILEPATH -Value ((& "$env:SPLUNK_EXE" btool server list --debug | Select-String -Pattern "sslRootCAPath") -split '\s\s+')[0]

    # File name
    Set-Variable -Name FILENAME -Value ($FILEPATH -split "\\")[-1]

    # Key
    Set-Variable -Name KEY -Value ((& "$env:SPLUNK_EXE" btool server list --debug | Select-String -Pattern "sslRootCAPath") -split '\s(\s+)?')[3]

    # Value
    Set-Variable -Name VALUE -Value (((& "$env:SPLUNK_EXE" btool server list --debug | Select-String -Pattern "sslRootCAPath") -split ' = ')[-1] -replace '\$SPLUNK_HOME', $env:SPLUNK_HOME -replace '\/', '\')

    # Hash
    if ($VALUE -and (Test-Path $VALUE)) {
        Set-Variable -Name HASH -Value (& "$env:SPLUNK_EXE" cmd openssl x509 -in $VALUE -hash -noout)
    }

    if ($FILEPATH.Length -ne 0) {
        Write-Output (
            (Get-Date -UFormat "%b %d %H:%M:%S %Z %Y")+" - "+(hostname)+" - "+
            "filename=$FILENAME, filepath=$FILEPATH, key=$KEY, value=$VALUE, ssl_hash=$HASH"
        )
    }
}

function check_inputs_conf_serverCert () {
    # File path
    Set-Variable -Name FILEPATH -Value ((& "$env:SPLUNK_EXE" btool inputs list --debug | Select-String -Pattern "serverCert") -split '\s\s+')[0]

    # File name
    Set-Variable -Name FILENAME -Value ($FILEPATH -split "\\")[-1]

    # Key
    Set-Variable -Name KEY -Value ((& "$env:SPLUNK_EXE" btool inputs list --debug | Select-String -Pattern "serverCert") -split '\s(\s+)?')[3]

    # Value
    Set-Variable -Name VALUE -Value (((& "$env:SPLUNK_EXE" btool inputs list --debug | Select-String -Pattern "serverCert") -split ' = ')[-1] -replace '\$SPLUNK_HOME', $env:SPLUNK_HOME -replace '\/', '\')

    # Hash
    if ($VALUE -and (Test-Path $VALUE)) {
        Set-Variable -Name HASH -Value (& "$env:SPLUNK_EXE" cmd openssl x509 -in $VALUE -hash -noout)
    }

    if ($FILEPATH.Length -ne 0) {
        Write-Output (
            (Get-Date -UFormat "%b %d %H:%M:%S %Z %Y")+" - "+(hostname)+" - "+
            "filename=$FILENAME, filepath=$FILEPATH, key=$KEY, value=$VALUE, ssl_hash=$HASH"
        )
    }
}

function check_outputs_conf_clientCert () {
    # File path
    Set-Variable -Name FILEPATH -Value ((& "$env:SPLUNK_EXE" btool outputs list --debug | Select-String -Pattern "clientCert") -split '\s\s+')[0]

    # File name
    Set-Variable -Name FILENAME -Value ($FILEPATH -split "\\")[-1]

    # Key
    Set-Variable -Name KEY -Value ((& "$env:SPLUNK_EXE" btool outputs list --debug | Select-String -Pattern "clientCert") -split '\s(\s+)?')[3]

    # Value
    Set-Variable -Name VALUE -Value (((& "$env:SPLUNK_EXE" btool outputs list --debug | Select-String -Pattern "clientCert") -split ' = ')[-1] -replace '\$SPLUNK_HOME', $env:SPLUNK_HOME -replace '\/', '\')

    # Hash
    if ($VALUE -and (Test-Path $VALUE)) {
        Set-Variable -Name HASH -Value (& "$env:SPLUNK_EXE" cmd openssl x509 -in $VALUE -hash -noout)
    }

    if ($FILEPATH.Length -ne 0) {
        Write-Output (
            (Get-Date -UFormat "%b %d %H:%M:%S %Z %Y")+" - "+(hostname)+" - "+
            "filename=$FILENAME, filepath=$FILEPATH, key=$KEY, value=$VALUE, ssl_hash=$HASH"
        )
    }
}

check_web_conf_clientCert
check_web_conf_serverCert
check_server_conf_sslRootCAPath
check_inputs_conf_serverCert
check_outputs_conf_clientCert
