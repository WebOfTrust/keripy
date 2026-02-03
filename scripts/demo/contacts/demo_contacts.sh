#!/bin/bash
# Demo script for KLI contact management commands


KS_ALICE="contact-demo-alice"
KS_BOB="contact-demo-bob"
SALT_ALICE="0AAQmsjh-C7kAJZQEzdrzwB7"
SALT_BOB="0ABBnsjh-D8lBKZRFzesx1C8"

kli init --name ${KS_ALICE} --nopasscode --salt ${SALT_ALICE} \
    --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name ${KS_ALICE} --alias alice \
    --file "${KERI_DEMO_SCRIPT_DIR}/data/trans-wits-sample.json"

echo "Creating Bob's keystore and identifier..."
kli init --name ${KS_BOB} --nopasscode --salt ${SALT_BOB} \
    --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name ${KS_BOB} --alias bob \
    --file "${KERI_DEMO_SCRIPT_DIR}/data/trans-wits-sample.json"

ALICE_OOBI=$(kli oobi generate --name ${KS_ALICE} --alias alice --role witness | head -1)
BOB_OOBI=$(kli oobi generate --name ${KS_BOB} --alias bob --role witness | head -1)
echo "Alice OOBI: ${ALICE_OOBI}"
echo "Bob OOBI: ${BOB_OOBI}"

echo "Alice adds Bob as a contact..."
kli contacts add --name ${KS_ALICE} \
    --oobi "${BOB_OOBI}" \
    --alias bob \
    --field company=ACME \
    --field role=Engineer

echo "Bob adds Alice as a contact..."
kli contacts add --name ${KS_BOB} \
    --oobi "${ALICE_OOBI}" \
    --alias alice \
    --field company=GLEIF

echo "Alice's contacts:"
kli contacts list --name ${KS_ALICE}

echo "Alice gets Bob by alias..."
kli contacts get --name ${KS_ALICE} --alias bob

echo "Alice renames 'bob' to 'robert'..."
kli contacts rename --name ${KS_ALICE} \
    --old-alias bob \
    --alias robert
kli contacts get --name ${KS_ALICE} --alias robert

echo "Alice queries robert's latest key state..."
kli contacts query --name ${KS_ALICE} --alias alice --contact-alias robert

echo "Alice deletes contact 'robert'..."
kli contacts delete --name ${KS_ALICE} --alias robert --yes

echo "Alice's contacts after delete:"
kli contacts list --name ${KS_ALICE} || echo "(no contacts)"

echo "Done."
