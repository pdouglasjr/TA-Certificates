#!/bin/bash

#
# DEFINITIONS
# -----------
# > Non-Splunk certificate: a certificate that is issued for use on the Splunk instance by a trusted organization
#

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

ADDON_DIR="$SPLUNK_HOME/etc/apps/TA-Certificates"

# create lookup directory if not already created
[[ ! -d "${ADDON_DIR}/lookups" ]] && mkdir -p "${ADDON_DIR}/lookups"

# prepare lookup file
LOOKUP_FILE_SPLUNK_CERT_HASHES="${ADDON_DIR}/lookups/splunk_certificate_hashes.csv"
LOOKUP_FILE_NON_SPLUNK_CERT_HASHES="${ADDON_DIR}/lookups/non_splunk_certificate_hashes.csv"

[[ -f "${LOOKUP_FILE_SPLUNK_CERT_HASHES}" ]] && rm ${LOOKUP_FILE_SPLUNK_CERT_HASHES}
[[ -f "${LOOKUP_FILE_NON_SPLUNK_CERT_HASHES}" ]] && rm ${LOOKUP_FILE_NON_SPLUNK_CERT_HASHES}

touch ${LOOKUP_FILE_SPLUNK_CERT_HASHES}
touch ${LOOKUP_FILE_NON_SPLUNK_CERT_HASHES}

echo "issuer_cn, subject_cn, hash" > ${LOOKUP_FILE_SPLUNK_CERT_HASHES}
echo "issuer_cn, subject_cn, hash" > ${LOOKUP_FILE_NON_SPLUNK_CERT_HASHES}

find $SPLUNK_HOME/etc/auth -maxdepth 10 -mindepth 1 -type d | while read dir; do
  for item in $dir/*; do
    FILE_TYPE=$(file ${item} | cut -d':' -f2- | awk '{$1=$1};1')
    if [[ ${FILE_TYPE} == "PEM certificate" ]]; then
      # certificate issuer information
      ISSUER=$($SPLUNK_HOME/bin/splunk cmd openssl x509 -in ${item} -noout -issuer | cut -d'=' -f2- | sed -e 's/\///' | sed -e 's/\//, /g')
      ISSUER_CN=$(echo ${ISSUER} | grep -o "CN=[^,]*" | cut -d'=' -f2-)
      ISSUER_EMAIL=$(echo ${ISSUER} | grep -o "emailAddress=[^,]*" | cut -d'=' -f2-)

      # certificate subject information
      SUBJECT=$($SPLUNK_HOME/bin/splunk cmd openssl x509 -in ${item} -noout -subject | cut -d'=' -f2- | sed -e 's/\///' | sed -e 's/\//, /g')
      SUBJECT_CN=$(echo ${SUBJECT} | grep -o "CN=[^,]*" | cut -d'=' -f2-)
      SUBJECT_EMAIL=$(echo ${SUBJECT} | grep -o "emailAddress=[^,]*" | cut -d'=' -f2-)

      # certificate hash
      HASH=$($SPLUNK_HOME/bin/splunk cmd openssl x509 -in ${item} -noout -hash)

      # check whether it is a Splunk certificate or a Non-Splunk certificate
      if [[ ${ISSUER_CN} == "SplunkCommonCA" || ${ISSUER_EMAIL} == "support@splunk.com" ]]; then
        # check if hash is in the lookup file already
        if [[ -z $(cat ${LOOKUP_FILE_SPLUNK_CERT_HASHES} | grep -o ${HASH}) ]]; then
          echo "${ISSUER_CN}, ${SUBJECT_CN}, ${HASH}" >> ${LOOKUP_FILE_SPLUNK_CERT_HASHES}
        fi
      else        
        # check if hash is in the lookup file already
        if [[ -z $(cat ${LOOKUP_FILE_NON_SPLUNK_CERT_HASHES} | grep -o ${HASH}) ]]; then
          echo "${ISSUER_CN}, ${SUBJECT_CN}, ${HASH}" >> ${LOOKUP_FILE_NON_SPLUNK_CERT_HASHES}
        fi
      fi
    fi
  done
done
