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

ADDON_DIR="${SPLUNK_HOME}/etc/apps/TA-Certificates"

check_web_conf_clientCert () {
  # web.conf
  WEB_CLIENT_CERT_SETTING=$($SPLUNK_HOME/bin/splunk btool client list --debug | grep clientCert)

  WEB_CLIENT_CERT_SETTING_LOC=$(echo ${WEB_CLIENT_CERT_SETTING} | cut -d' ' -f1)
  WEB_CLIENT_CERT_FILE=$(echo ${WEB_CLIENT_CERT_SETTING} | cut -d'=' -f2- | awk '{$1=$1};1')

  if [[ ! -z ${WEB_CLIENT_CERT_FILE} ]]; then
    if [[ ! -z $(echo ${WEB_CLIENT_CERT_FILE} | grep -o "\$SPLUNK_HOME") ]]; then
      WEB_CLIENT_CERT_FILE="${SPLUNK_HOME}$(echo ${WEB_CLIENT_CERT_FILE} | sed -e 's/\$SPLUNK_HOME//')"
    fi

    HASH=$(${SPLUNK_HOME}/bin/splunk cmd openssl x509 -in ${WEB_CLIENT_CERT_FILE} -noout -hash 2> /dev/null)

    echo "$(date) - $(hostname) - filename=web.conf, filepath=${WEB_CLIENT_CERT_SETTING_LOC}, key=clientCert, value=${WEB_CLIENT_CERT_FILE}"
  fi
}

check_web_conf_serverCert () {
  # web.conf
  WEB_SERVER_CERT_SETTING=$($SPLUNK_HOME/bin/splunk btool web list --debug | grep serverCert)

  WEB_SERVER_CERT_SETTING_LOC=$(echo ${WEB_SERVER_CERT_SETTING} | cut -d' ' -f1)
  WEB_SERVER_CERT_FILE=$(echo ${WEB_SERVER_CERT_SETTING} | cut -d'=' -f2- | awk '{$1=$1};1')
  
  if [[ ! -z ${WEB_SERVER_CERT_FILE} ]]; then
    if [[ ! -z $(echo ${WEB_SERVER_CERT_FILE} | grep -o "\$SPLUNK_HOME") ]]; then
      WEB_SERVER_CERT_FILE="${SPLUNK_HOME}$(echo ${WEB_SERVER_CERT_FILE} | sed -e 's/\$SPLUNK_HOME//')"
    fi

    HASH=$(${SPLUNK_HOME}/bin/splunk cmd openssl x509 -in ${WEB_SERVER_CERT_FILE} -noout -hash 2> /dev/null)
 
    echo "$(date) - $(hostname) - filename=web.conf, filepath=${WEB_SERVER_CERT_SETTING_LOC}, key=serverCert, value=${WEB_SERVER_CERT_FILE}"
  fi
}

check_server_conf () {
  # server.conf
  SERVER_SSL_ROOT_CA_PATH_SETTING=$($SPLUNK_HOME/bin/splunk btool server list --debug | grep sslRootCAPath)
  
  SERVER_SSL_ROOT_CA_PATH_SETTING_LOC=$(echo ${SERVER_SSL_ROOT_CA_PATH_SETTING} | cut -d' ' -f1)
  SERVER_SSL_ROOT_CA_PATH_FILE=$(echo ${SERVER_SSL_ROOT_CA_PATH_SETTING} | cut -d'=' -f2- | awk '{$1=$1};1')

  if [[ ! -z ${SERVER_SSL_ROOT_CA_PATH_FILE} ]]; then
    if [[ ! -z $(echo ${SERVER_SSL_ROOT_CA_PATH_FILE} | grep -o "\$SPLUNK_HOME") ]]; then
      SERVER_SSL_ROOT_CA_PATH_FILE="${SPLUNK_HOME}$(echo ${SERVER_SSL_ROOT_CA_PATH_FILE} | sed -e 's/\$SPLUNK_HOME//')"
    fi

    HASH=$(${SPLUNK_HOME}/bin/splunk cmd openssl x509 -in ${SERVER_SSL_ROOT_CA_PATH_FILE} -noout -hash 2> /dev/null)

    echo "$(date) - $(hostname) - filename=server.conf, filepath=${SERVER_SSL_ROOT_CA_PATH_SETTING_LOC}, key=sslRootCAPath, value=${SERVER_SSL_ROOT_CA_PATH_FILE}"
  fi
}

check_inputs_conf () {
  # inputs.conf
  INPUTS_SERVER_CERT_SETTING=$($SPLUNK_HOME/bin/splunk btool inputs list --debug | grep serverCert)

  INPUTS_SERVER_CERT_SETTING_LOC=$(echo ${INPUTS_SERVER_CERT_SETTING} | cut -d' ' -f1)
  INPUTS_SERVER_CERT_FILE=$(echo ${INPUTS_SERVER_CERT_SETTING} | cut -d'=' -f2- | awk '{$1=$1};1')

  if [[ ! -z ${INPUTS_SERVER_CERT_FILE} ]]; then
    if [[ ! -z $(echo ${INPUTS_SERVER_CERT_FILE} | grep -o "\$SPLUNK_HOME") ]]; then
      INPUTS_SERVER_CERT_FILE="${SPLUNK_HOME}$(echo ${INPUTS_SERVER_CERT_FILE} | sed -e 's/\$SPLUNK_HOME//')"
    fi

    HASH=$(${SPLUNK_HOME}/bin/splunk cmd openssl x509 -in ${INPUTS_SERVER_CERT_FILE} -noout -hash 2> /dev/null)

    echo "$(date) - $(hostname) - filename=inputs.conf, filepath=${INPUTS_SERVER_CERT_SETTING_LOC}, key=serverCert, value=${INPUTS_SERVER_CERT_FILE}"
  fi
}

check_outputs_conf () {
  # outputs.conf
  OUTPUTS_CLIENT_CERT_SETTING=$($SPLUNK_HOME/bin/splunk btool outputs list --debug | grep clientCert)

  OUTPUTS_CLIENT_CERT_SETTING_LOC=$(echo ${OUTPUTS_CLIENT_CERT_SETTING} | cut -d' ' -f1)
  OUTPUTS_CLIENT_CERT_PATH=$(echo ${OUTPUTS_CLIENT_CERT_SETTING} | cut -d'=' -f2- | awk '{$1=$1};1')
  
  if [[ ! -z ${OUTPUTS_CLIENT_CERT_PATH} ]]; then
    if [[ ! -z $(echo ${OUTPUTS_CLIENT_CERT_PATH} | grep -o "\$SPLUNK_HOME") ]]; then
      OUTPUTS_CLIENT_CERT_PATH="${SPLUNK_HOME}$(echo ${OUTPUTS_CLIENT_CERT_PATH} | sed -e 's/\$SPLUNK_HOME//')"
    fi

    HASH=$(${SPLUNK_HOME}/bin/splunk cmd openssl x509 -in ${OUTPUTS_CLIENT_CERT_PATH} -noout -hash)
    
    echo "$(date) - $(hostname) - filename=outputs.conf, filepath=${OUTPUTS_CLIENT_CERT_SETTING_LOC}, key=clientCert, value=${OUTPUTS_CLIENT_CERT_PATH}"
  fi
}

main () {
  check_web_conf_clientCert
  check_web_conf_serverCert
  check_inputs_conf
  check_server_conf  
  check_outputs_conf
}

main

exit 0
