[System.Environment]::SetEnvironmentVariable('SPLUNK_HOME', 'C:\Program Files\SplunkUniversalForwarder')
[System.Environment]::SetEnvironmentVariable('SPLUNK_CERTS_DIR', $env:SPLUNK_HOME+'\etc\auth')
[System.Environment]::SetEnvironmentVariable('SPLUNK_EXE', $env:SPLUNK_HOME+'\bin\splunk.exe')

function main() {
    Get-ChildItem $env:SPLUNK_CERTS_DIR -Recurse -Filter *.pem | ForEach-Object {
        ### Certificate Information
        Set-Variable -Name CERT_FILE -Value ($_.FullName)

        # Filename
        Set-Variable -Name FILENAME -Value ($CERT_FILE -split "\\")[-1]

        # Filepath
        Set-Variable -Name FILEPATH -Value (Split-Path -Path $CERT_FILE)

        # Serial
        Set-Variable -Name SERIAL -Value ((& "$env:SPLUNK_EXE" cmd openssl x509 -in $CERT_FILE -serial -noout) -split "=")[-1]

        # Hash
        Set-Variable -Name HASH -Value (& "$env:SPLUNK_EXE" cmd openssl x509 -in $CERT_FILE -hash -noout)

	# Public Key Algorithms
        Set-Variable -Name PUBLIC_KEY_ALGORITHM -Value ((& "$env:SPLUNK_EXE" cmd openssl x509 -in $CERT_FILE -text -noout | Select-String -Pattern '\bPublic Key Algorithm:.*[^\n]+\b' | Select-Object -First 1) -replace '\s+', '' -split ':' | Select-Object -First 2)[1]
        
	# Signature Algorithms
        Set-Variable -Name SIGNATURE_ALGORITHM -Value ((& "$env:SPLUNK_EXE" cmd openssl x509 -in $CERT_FILE -text -noout | Select-String -Pattern '\bSignature Algorithm:.*[^\n]+\b' | Select-Object -First 1) -replace '\s+', '' -split ':' | Select-Object -First 2)[1]

        # Version
        Set-Variable -Name VERSION -Value ((((& "$env:SPLUNK_EXE" cmd openssl x509 -in $CERT_FILE -text -noout | Select-String -Pattern '\bVersion:.*[^\n]+\b') -replace '\s+', '') -split ':')[1] -split '\(')[0]

        # Start Date
        Set-Variable -Name START_DATE -Value ((& "$env:SPLUNK_EXE" cmd openssl x509 -in $CERT_FILE -startdate -noout) -split '=')[-1]

        # End Date
        Set-Variable -Name END_DATE -Value ((& "$env:SPLUNK_EXE" cmd openssl x509 -in $CERT_FILE -enddate -noout) -split '=')[-1]

        # Issuer
        Set-Variable -Name ISSUER -Value ((& "$env:SPLUNK_EXE" cmd openssl x509 -in $CERT_FILE -issuer -noout) -split '= ')[-1]

        # Issuer Common Name (CN)
        Set-Variable -Name NULL_BUCKET -Value ($ISSUER -match ".*CN=([^\\//]+).*")
        Set-Variable -Name ISSUER_CN -Value ($Matches[1])

        # Issuer Organization Unit (OU)
        Set-Variable -Name NULL_BUCKET -Value ($ISSUER -match ".*OU=([^\\//]+).*")
        Set-Variable -Name ISSUER_OU -Value ($Matches[1])

        # Issuer Organization (O)
        Set-Variable -Name NULL_BUCKET -Value ($ISSUER -match ".*O=([^\\//]+).*")
        Set-Variable -Name ISSUER_O -Value ($Matches[1])

        # Issuer Locality (L)
        Set-Variable -Name NULL_BUCKET -Value ($ISSUER -match ".*L=([^\\//]+).*")
        Set-Variable -Name ISSUER_L -Value ($Matches[1])

        # Issuer State (ST)
        Set-Variable -Name NULL_BUCKET -Value ($ISSUER -match ".*ST=([^\\//]+).*")
        Set-Variable -Name ISSUER_ST -Value ($Matches[1])

        # Issuer Country (C)
        Set-Variable -Name NULL_BUCKET -Value ($ISSUER -match ".C=([^\\//]+).*")
        Set-Variable -Name ISSUER_C -Value ($Matches[1])

        # Issuer Email
        Set-Variable -Name NULL_BUCKET -Value ($ISSUER -match ".*emailAddress=([^\\//]+).*")
        Set-Variable -Name ISSUER_EMAIL -Value ($Matches[1])

        # Issuer Email Domain
        Set-Variable -Name ISSUER_EMAIL_DOMAIN -Value ($ISSUER_EMAIL -split "@")[-1]

        # Subject
        Set-Variable -Name SUBJECT -Value ((& "$env:SPLUNK_EXE" cmd openssl x509 -in (Get-Variable CERT_FILE -Value) -subject -noout) -split '= ')[-1]

        # Subject Common Name (CN)
        Set-Variable -Name NULL_BUCKET -Value ($SUBJECT -match ".*CN=([^\\//]+).*")
        Set-Variable -Name SUBJECT_CN -Value ($Matches[1])

        # Subject Organization Unit (OU)
        Set-Variable -Name NULL_BUCKET -Value ($SUBJECT -match ".*OU=([^\\//]+).*")
        Set-Variable -Name SUBJECT_OU -Value ($Matches[1])

        # Subject Organization (O)
        Set-Variable -Name NULL_BUCKET -Value ($SUBJECT -match ".*O=([^\\//]+).*")
        Set-Variable -Name SUBJECT_O -Value ($Matches[1])

        # Subject Locality (L)
        Set-Variable -Name NULL_BUCKET -Value ($SUBJECT -match ".*L=([^\\//]+).*")
        Set-Variable -Name SUBJECT_L -Value ($Matches[1])

        # Subject State (ST)
        Set-Variable -Name NULL_BUCKET -Value ($ISSUER -match ".*ST=([^\\//]+).*")
        Set-Variable -Name SUBJECT_ST -Value ($Matches[1])

        # Subject Country (C)
        Set-Variable -Name NULL_BUCKET -Value ($ISSUER -match ".C=([^\\//]+).*")
        Set-Variable -Name SUBJECT_C -Value ($Matches[1])

        # Subject Email
        Set-Variable -Name NULL_BUCKET -Value ($ISSUER -match ".*emailAddress=([^\\//]+).*")
        Set-Variable -Name SUBJECT_EMAIL -Value ($Matches[1])

        # Subject Email Domain
        Set-Variable -Name SUBJECT_EMAIL_DOMAIN -Value ($ISSUER_EMAIL -split "@")[-1]

        # Output
        Set-Variable -Name OUTPUT -Value ((Get-Date -UFormat "%b %d %H:%M:%S %Z %Y")+" - "+(hostname)+" - "+
                                          "filename="+$FILENAME+
                                          ", filepath="+$FILEPATH+
                                          ", serial="+$SERIAL+
                                          ", hash="+$HASH+
					  ", public_key_algorithm="+$PUBLIC_KEY_ALGORITHM+
                                          ", signature_algorithm="+$SIGNATURE_ALGORITHM+
                                          ", start_date="+$START_DATE+
                                          ", end_date="+$END_Date+
                                          ", issuer="+$ISSUER+
                                          ", issuer_cn="+$ISSUER_CN+
                                          ", issuer_ou="+$ISSUER_OU+
                                          ", issuer_org="+$ISSUER_O+
                                          ", issuer_loc="+$ISSUER_L+
                                          ", issuer_st="+$ISSUER_ST+
                                          ", issuer_c="+$ISSUER_C+
                                          ", issuer_email="+$ISSUER_EMAIL+
                                          ", issuer_email_domain="+$ISSUER_EMAIL_DOMAIN+
                                          ", subject="+$SUBJECT+
                                          ", subject_cn="+$SUBJECT_CN+
                                          ", subject_ou="+$SUBJECT_OU+
                                          ", subject_org="+$SUBJECT_O+
                                          ", subject_loc="+$SUBJECT_L+
                                          ", subject_st="+$SUBJECT_ST+
                                          ", subject_c="+$SUBJECT_C+
                                          ", subject_email="+$SUBJECT_EMAIL+
                                          ", subject_email_domain="+$SUBJECT_EMAIL_DOMAIN+
                                          ", version="+$VERSION)

        Write-Output $OUTPUT
    }
}

main
