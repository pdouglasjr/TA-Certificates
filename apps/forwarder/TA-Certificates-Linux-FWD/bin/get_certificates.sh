#!/bin/bash

# set Splunk home directory
if [ -z $SPLUNK_HOME ]; then
  if [ -d /opt/splunk ]; then
    SPLUNK_HOME=/opt/splunk
  elif [ -d /opt/splunkforwarder ]; then
    SPLUNK_HOME=/opt/splunkforwarder
  elif [ -d /Applications/SplunkForwarder ]; then
    SPLUNK_HOME=/Applications/SplunkForwarder
  fi
fi

OUTPUT=''

find ${SPLUNK_HOME}/etc/auth/ -maxdepth 10 -mindepth 1 -type d | while read dir; do
    for item in $dir/*; do
        if [ "$(file $item | cut -d':' -f2 | awk '{$1=$1};1')" = "PEM certificate" ]; then         
            # Grab certificate file information
            FILENAME=$(basename $item)
            FILEPATH=$(dirname $item)            

            # Grab certificate serial number
            SERIAL=$($SPLUNK_HOME/bin/splunk cmd openssl x509 -in $item -noout -serial | cut -d'=' -f2-)
            if [[ -z ${SERIAL} ]]; then
              SERIAL=-1
            fi

            # Calculate the certificate's hash
            HASH=$($SPLUNK_HOME/bin/splunk cmd openssl x509 -in $item -hash -noout)

            # Grab signature algorithm
            SIGNATURE_ALGORITHM=$($SPLUNK_HOME/bin/splunk cmd openssl x509 -in $item -text -noout | grep -o -m1 'Signature Algorithm.*' | cut -d':' -f2- | awk '{$1=$1};1')

            # Grab version of the certification
            VERSION=$($SPLUNK_HOME/bin/splunk cmd openssl x509 -in $item -text -noout | grep -o Version.* | cut -d':' -f2- | awk '{$1=$1};1' | cut -d' ' -f1)

            # Grab information about issuer of certificate
            ### distinguished name (dn)
            ISSUER=$($SPLUNK_HOME/bin/splunk cmd openssl x509 -in $item -noout -issuer | cut -d'=' -f2- | sed -e 's/\///' | awk '{$1=$1};1')

            ### common name (cn) 
            ISSUER_CN=$(echo ${ISSUER} | grep -o 'CN=[^\/]*' | cut -d'=' -f2-)

            ### organizational unit
            ISSUER_OU=$(echo ${ISSUER} | grep -o 'OU=[^\/]*' | cut -d'=' -f2-)

            ### organization
            ISSUER_ORG=$(echo ${ISSUER} | grep -o 'O=[^\/]*' | cut -d'=' -f2-)

            ### locality
            ISSUER_L=$(echo ${ISSUER} | grep -o 'L=[^\/]*' | cut -d'=' -f2-)

            ### state
            ISSUER_ST=$(echo ${ISSUER} | grep -o 'ST=[^\/]*' | cut -d'=' -f2-)

            ### country
            ISSUER_C=$(echo ${ISSUER} | grep -o 'C=[^\/]*' | cut -d'=' -f2-)
            
            ### email
            ISSUER_EMAIL="$($SPLUNK_HOME/bin/splunk cmd openssl x509 -in $item -noout -email | cut -d'=' -f2- | sed -e 's/\///' | awk '{$1=$1};1' | sed -e's/\//, /g' | awk '{$1=$1};1')"
            [[ -z ${ISSUER_EMAIL} ]] && ISSUER_EMAIL="splunk@splunk.com"

            ### email domain
            ISSUER_EMAIL_DOMAIN=$(echo ${ISSUER_EMAIL} | cut -d'@' -f2-)

            # Grab information about subject of certificate
            ### distinguished name (dn)
            SUBJECT=$($SPLUNK_HOME/bin/splunk cmd openssl x509 -in $item -noout -subject | cut -d'=' -f2- | sed -e 's/\///' | awk '{$1=$1};1')

            ### common name (cn) 
            SUBJECT_CN=$(echo ${SUBJECT} | grep -o 'CN=[^\/]*' | cut -d'=' -f2-)

            ### organizational unit
            SUBJECT_OU=$(echo ${SUBJECT} | grep -o 'OU=[^\/]*' | cut -d'=' -f2-)

            ### organization
            SUBJECT_ORG=$(echo ${SUBJECT} | grep -o 'O=[^\/]*' | cut -d'=' -f2-)

            ### locality
            SUBJECT_L=$(echo ${SUBJECT} | grep -o 'L=[^\/]*' | cut -d'=' -f2-)

            ### state
            SUBJECT_ST=$(echo ${SUBJECT} | grep -o 'ST=[^\/]*' | cut -d'=' -f2-)

            ### country
            SUBJECT_C=$(echo ${SUBJECT} | grep -o 'C=[^\/]*' | cut -d'=' -f2-)
            
            ### email
            SUBJECT_EMAIL="$($SPLUNK_HOME/bin/splunk cmd openssl x509 -in $item -noout -email | cut -d'=' -f2- | sed -e 's/\///' | awk '{$1=$1};1' | sed -e's/\//, /g' | awk '{$1=$1};1')"

            ### email domain
            if [[ -z ${SUBJECT_EMAIL} ]]; then
              SUBJECT_EMAIL="unknown"
              SUBJECT_EMAIL_DOMAIN="unknown"
            else
              SUBJECT_EMAIL_DOMAIN=$(echo ${SUBJECT_EMAIL} | cut -d'@' -f2-)
            fi

            # Grab validity information
            START_DATE="$($SPLUNK_HOME/bin/splunk cmd openssl x509 -in $item -noout -startdate | cut -d'=' -f2-)"
            END_DATE="$($SPLUNK_HOME/bin/splunk cmd openssl x509 -in $item -noout -enddate | cut -d'=' -f2-)"

            START_DATE_S=$(date +%s --date="${START_DATE}")
            END_DATE_S=$(date +%s --date="${END_DATE}")

            VALIDITY_WINDOW=$((END_DATE_S - START_DATE_S))

            ### clean up output
            OUTPUT+="$(date) - \
                     $(hostname) - \
                     filename=${FILENAME}, \
                     filepath=${FILEPATH}, \
                     serial=${SERIAL}, \
                     hash=${HASH}, \
                     signature_algorithm=${SIGNATURE_ALGORITHM}, \
                     start_date=${START_DATE}, \
                     end_date=${END_DATE}, \
                     issuer=${ISSUER}, \
                     issuer_cn=${ISSUER_CN}, \
                     issuer_ou=${ISSUER_OU}, \
                     issuer_org=${ISSUER_ORG}, \
                     issuer_loc=${ISSUER_L}, \
                     issuer_st=${ISSUER_ST}, \
                     issuer_c=${ISSUER_C}, \
                     issuer_email=${ISSUER_EMAIL}, \
                     issuer_email_domain=${ISSUER_EMAIL_DOMAIN}, \
                     subject=${SUBJECT}, \
                     subject_cn=${SUBJECT_CN}, \
                     subject_ou=${SUBJECT_OU}, \
                     subject_org=${SUBJECT_ORG}, \
                     subject_loc=${SUBJECT_L}, \
                     subject_st=${SUBJECT_ST}, \
                     subject_c=${SUBJECT_C}, \
                     subject_email=${SUBJECT_EMAIL}, \
                     subject_email_domain=${SUBJECT_EMAIL_DOMAIN}, \
                     validity_window=${VALIDITY_WINDOW}, \
                     version=${VERSION}\r\n"

            echo -e $OUTPUT | awk '{$1=$1};1'
        fi
    done
done
