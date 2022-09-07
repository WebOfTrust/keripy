# GETTING STARTED
function isSuccess() {
    ret=$?
    if [ $ret -ne 0 ]; then
       echo "Error $ret"
       exit $ret
    fi
}

# CREATE DATABASE AND KEYSTORE
kli init --name test --nopasscode --salt 0AMDEyMzQ1Njc4OWxtbm9aBc
isSuccess

# NON-TRANSFERABLE
kli incept --name test --alias non-trans --file ${KERI_DEMO_SCRIPT_DIR}/data/non-transferable-sample.json
isSuccess

kli rotate --name test --alias non-trans
ret=$?
if [ $ret -eq 0 ]; then
   echo "Rotate of non-transferable should fail $ret"
   exit $ret
fi


# TRANSFERABLE
kli incept --name test --alias trans --file ${KERI_DEMO_SCRIPT_DIR}/data/transferable-sample.json
isSuccess

kli rotate --name test --alias trans
isSuccess

kli rotate --name test --alias trans --data @${KERI_DEMO_SCRIPT_DIR}/data/anchor.json
isSuccess

kli interact --name test --alias trans --data @${KERI_DEMO_SCRIPT_DIR}/data/anchor.json
isSuccess

kli rotate --name test --alias trans --next-count 3 --sith 2
isSuccess

kli rotate --name test --alias trans --next-count 3 --sith 2
isSuccess

# SIGN AND VERIFY ARBITRARY DATA
kli sign --name test --alias trans --text @${KERI_DEMO_SCRIPT_DIR}/data/anchor.json
isSuccess

kli verify --name test --alias trans --prefix EKYEW7HZtLywhFZLtbTeLn1Qk5SRrsLzLZhjaIxWXDFY --text @${KERI_DEMO_SCRIPT_DIR}/data/anchor.json --signature AACopTJG_oGKeLVAFb8YKCcMq-iOOPyjvR-j7hhMH2aRXY1GGfRAjo_-iBbMlPi8JcKhBI5gWZUssbH9tMd7jAUA
isSuccess

kli verify --name test --alias trans --prefix EKYEW7HZtLywhFZLtbTeLn1Qk5SRrsLzLZhjaIxWXDFY --text @${KERI_DEMO_SCRIPT_DIR}/data/anchor.json --signature ABBIgtKqPXbOxEiD7EyrBdhpxyar6hG1aA1qRm2S3vsJg9v3sUK2Re_Rpk1jS4geh40Zan9q_OIUql17Yv0QGFAM
isSuccess

kli verify --name test --alias trans --prefix EKYEW7HZtLywhFZLtbTeLn1Qk5SRrsLzLZhjaIxWXDFY --text @${KERI_DEMO_SCRIPT_DIR}/data/anchor.json --signature ACCtB-zkgTG-83L7y1IRywHnK8axgKGYnq-ZSpopC-cOzC0YRRyU__CuT0K5UA7iPQYgJx5bubK02Uo507q4yrAC
isSuccess

kli verify --name test --alias trans --prefix EKYEW7HZtLywhFZLtbTeLn1Qk5SRrsLzLZhjaIxWXDFY --text @${KERI_DEMO_SCRIPT_DIR}/data/anchor.json --signature ACSHdal6kHAAjbW_frH83sDDCoBHw_nNKFysW5Dj8PSsnwVPePCNw-kFmF6Z8H87q7D3abw_5u2i4jmzdnWFsRDz
ret=$?
if [ $ret -eq 0 ]; then
   echo "Testing invalid signature should fail $ret"
   exit $ret
fi


# ESTABLISHMENT ONLY
kli incept --name test --alias est-only --file ${KERI_DEMO_SCRIPT_DIR}/data/estonly-sample.json

kli interact --name test --alias est-only --data @${KERI_DEMO_SCRIPT_DIR}/data/anchor.json
ret=$?
if [ $ret -eq 0 ]; then
   echo "Interact should fail for establishment only $ret"
   exit $ret
fi

kli rotate --name test --alias est-only
isSuccess

kli rotate --name test --alias est-only --data @${KERI_DEMO_SCRIPT_DIR}/data/anchor.json
isSuccess

echo 'Test Complete'
