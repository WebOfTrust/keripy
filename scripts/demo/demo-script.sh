# GETTING STARTED
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
echo $SCRIPT_DIR

function isSuccess() {
    ret=$?
    if [ $ret -ne 0 ]; then
       echo "Error $ret"
       exit $ret
    fi
}

# CREATE DATABASE AND KEYSTORE
kli init --name test --nopasscode
isSuccess

# NON-TRANSFERABLE
kli incept --name test --alias non-trans --file ${SCRIPT_DIR}/non-transferable-sample.json
isSuccess

kli rotate --name test --alias non-trans
ret=$?
if [ $ret -eq 0 ]; then
   echo "Rotate of non-transferable should fail $ret"
   exit $ret
fi


# TRANSFERABLE
kli incept --name test --alias trans --file ${SCRIPT_DIR}/transferable-sample.json
isSuccess

kli rotate --name test --alias trans
isSuccess

kli rotate --name test --alias trans --data @${SCRIPT_DIR}/anchor.json
isSuccess

kli interact --name test --alias trans --data @${SCRIPT_DIR}/anchor.json
isSuccess

kli rotate --name test --alias trans --next-count 3 --sith 2
isSuccess

kli rotate --name test --alias trans --next-count 3 --sith 2
isSuccess

# SIGN AND VERIFY ARBITRARY DATA
kli sign --name test --alias trans --text @${SCRIPT_DIR}/anchor.json
isSuccess

kli verify --name test --alias trans --prefix EdSWKic0jXrzhG2mfCsdwWBOxIhnufSJjMT53YmCq8Pg --text @${SCRIPT_DIR}/anchor.json --signature AAasJ-r22h9LnB7SgSvjQWDuQxAyVRpcWpYbQzw-sn_MZ4--XcEYV-rKSCJYTP5ZR1WYv1_OJ9ni3P_OPKZYspAA
isSuccess

kli verify --name test --alias trans --prefix EdSWKic0jXrzhG2mfCsdwWBOxIhnufSJjMT53YmCq8Pg --text @${SCRIPT_DIR}/anchor.json --signature AB_sDX2BZqN1I0Cr-Xwz2MaH18z-uqejNZsrPDPCre1f3ND6O4aIzRf4CGCZodct5ThTDCvc6axxlm_pK_wujsAQ
isSuccess

kli verify --name test --alias trans --prefix EdSWKic0jXrzhG2mfCsdwWBOxIhnufSJjMT53YmCq8Pg --text @${SCRIPT_DIR}/anchor.json --signature AC1sns_hyJ3pTLcu8WUmSlxFZG9viUuC4-DZYlZu_21nquPRaQ2uH9286SdA9zHT-4boUA3sV129b0dd0djHKEAg
isSuccess

kli verify --name test --alias trans --prefix EdSWKic0jXrzhG2mfCsdwWBOxIhnufSJjMT53YmCq8Pg --text @${SCRIPT_DIR}/anchor.json --signature ACSHdal6kHAAjbW_frH83sDDCoBHw_nNKFysW5Dj8PSsnwVPePCNw-kFmF6Z8H87q7D3abw_5u2i4jmzdnWFsRDz
ret=$?
if [ $ret -eq 0 ]; then
   echo "Testing invalid signature should fail $ret"
   exit $ret
fi


# ESTABLISHMENT ONLY
kli incept --name test --alias est-only --file ${SCRIPT_DIR}/estonly-sample.json

kli interact --name test --alias est-only --data @${SCRIPT_DIR}/anchor.json
ret=$?
if [ $ret -eq 0 ]; then
   echo "Interact should fail for establishment only $ret"
   exit $ret
fi

kli rotate --name test --alias est-only
isSuccess

kli rotate --name test --alias est-only --data @${SCRIPT_DIR}/anchor.json
isSuccess
