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

kli verify --name test --alias trans --prefix EWlz5c_UEQyZgNMhF-GMjs_53_3MOhTzzqJ7yQz1vwZI --text @${KERI_DEMO_SCRIPT_DIR}/data/anchor.json --signature AA8r1EJXI1sTuI51TXo4F1JjxIJzwPeCxa-Cfbboi7F4Y4GatPEvK629M7G_5c86_Ssvwg8POZWNMV-WreVqBECw
isSuccess

kli verify --name test --alias trans --prefix EWlz5c_UEQyZgNMhF-GMjs_53_3MOhTzzqJ7yQz1vwZI --text @${KERI_DEMO_SCRIPT_DIR}/data/anchor.json --signature AB-xBrhNnUjxGK6DRElZUBGT42gla6y-MLcpKS7L6kbRcW1cKx2WONAuSvX2hKem0ueGxdtPqmQhV1cLvTkynVCA
isSuccess

kli verify --name test --alias trans --prefix EWlz5c_UEQyZgNMhF-GMjs_53_3MOhTzzqJ7yQz1vwZI --text @${KERI_DEMO_SCRIPT_DIR}/data/anchor.json --signature ACUaMj3_YdoCsc_NIu4Y3xNEKoy1208r9hxlfc1lcKGIA2TKccnHt0agHSAqvFaaK1D3FyHl5_3S_HAEypE0kzAA
isSuccess

kli verify --name test --alias trans --prefix EWlz5c_UEQyZgNMhF-GMjs_53_3MOhTzzqJ7yQz1vwZI --text @${KERI_DEMO_SCRIPT_DIR}/data/anchor.json --signature ACSHdal6kHAAjbW_frH83sDDCoBHw_nNKFysW5Dj8PSsnwVPePCNw-kFmF6Z8H87q7D3abw_5u2i4jmzdnWFsRDz
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
