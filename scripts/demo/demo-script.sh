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

kli verify --name test --alias trans --prefix EdSWKic0jXrzhG2mfCsdwWBOxIhnufSJjMT53YmCq8Pg --text @${SCRIPT_DIR}/anchor.json --signature AA29iAmC1x_gYYI5sLv4MwAt6P0XRs0Be_JKKTb6iCVBy5amf4y5XzBL-kTRWSH0d0T3Zx1QsbgXhXW3i54EWkAQ
isSuccess

kli verify --name test --alias trans --prefix EdSWKic0jXrzhG2mfCsdwWBOxIhnufSJjMT53YmCq8Pg --text @${SCRIPT_DIR}/anchor.json --signature AB_whAvInYCuPXqfNQVDlDlyL0b4KsrQWsHA9IetyhDsD_AMToqJlmZzpN5Z9x_rlYlmL4pU2i2BC0so9aaxncDA
isSuccess

kli verify --name test --alias trans --prefix EdSWKic0jXrzhG2mfCsdwWBOxIhnufSJjMT53YmCq8Pg --text @${SCRIPT_DIR}/anchor.json --signature ACAEilCq8wGtjEEWBVODrh5o98cVnB8oZ_csTyrbgequWj5elEZERSfWFsW0SH4_B5oxtN-ta0rRZiIZNoQCFLAQ
isSuccess

kli verify --name test --alias trans --prefix EdSWKic0jXrzhG2mfCsdwWBOxIhnufSJjMT53YmCq8Pg --text @${SCRIPT_DIR}/anchor.json --signature ACSHdal6kHAAjbW_frH83sDDCoBHw_nNKFysW5Dj8PSsnwVPePCNw-kFmF6Z8H87q7D3abw_5u2i4jmzdnWFsRDz
isSuccess

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
