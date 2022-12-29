# -*- encoding: utf-8 -*-
"""
KERI
keri.ledger.cardaning module

Registrar Backer operations on Cardano Ledger

"""

from blockfrost import BlockFrostApi, ApiError, ApiUrls
from pycardano import * 
from textwrap import wrap
from threading import Timer
import os
import time
import json

# TODO
# Error handling

QUEUE_DURATION = 60
NETWORK = Network.TESTNET

class Cardano:
    """
    Environment variables required:
        - BLOCKFROST_API_KEY = API KEY from Blockfrots  https://blockfrost.io
        - FUNDING_ADDRESS_CBORHEX = Private Key of funding address as CBOR Hex. Must be an Enterprice address (no Staking part) as PaymentSigningKeyShelley_ed25519
    
    Additional libraries required:
        pip install pycardano blockfrost-python textwrap
    See Backer designation event: https://github.com/WebOfTrust/keripy/issues/90

    Features:
        - Cardano Address is derived from the same seed (private key) used to derive the prefix of the backer
        - Anchoring KELs from multiple prefixes
        - Queue events during a period to allow several block confirmations as a safety meassure
        - Optional funding address to fund the backer address
    """

    def __init__(self, name='backer', hab=None, ks=None):
        self.name = name
        self.pendingKEL = {}
        self.timer = Timer(QUEUE_DURATION, self.flushQueue)
        
        try:
            blockfrostProjectId=os.environ['BLOCKFROST_API_KEY']
        except KeyError:
            print("Environment variable BLOCKFROST_API_KEY not set")
            exit(1)
        self.api = BlockFrostApi(
            project_id=blockfrostProjectId,
            base_url=ApiUrls.preview.value
            )
        
        self.context = BlockFrostChainContext(blockfrostProjectId,NETWORK, ApiUrls.preview.value)

        backerPrivateKey = ks.pris.get(hab.kever.prefixer.qb64).raw
        self.payment_signing_key = PaymentSigningKey(backerPrivateKey,"PaymentSigningKeyShelley_ed25519","PaymentSigningKeyShelley_ed25519")
        payment_verification_key = PaymentVerificationKey.from_signing_key(self.payment_signing_key)
        self.spending_addr = Address(payment_part=payment_verification_key.hash(),staking_part=None, network=NETWORK)
        print("Cardano Backer Address:", self.spending_addr.encode())
        balance = self.getaddressBalance()
        if balance and balance > 5000000:
            print("Address balance:",balance/1000000, "ADA")
        else:
            self.fundAddress(self.spending_addr)

    def publishEvent(self, event):
        print("Adding event to queue", event['ked']['s'],event['ked']['t'])
        seq_no = int(event['ked']['s'],16)
        prefix = event['ked']['i']
        if not prefix in self.pendingKEL: self.pendingKEL[prefix] = {}
        self.pendingKEL[prefix][seq_no] = wrap(json.dumps(event), 64)
        if not self.timer.is_alive():
            self.timer = Timer(90, self.flushQueue)
            self.timer.start()

    def flushQueue(self):
        print("Flushing Queue")
        try:
            txs = self.api.address_transactions(self.spending_addr)
            utxos = self.api.address_utxos(self.spending_addr.encode())
            for key, value in self.pendingKEL.items():
                # Check last KE in blockchain to avoid duplicates (for some reason mailbox may submit an event twice)                
                for t in txs:
                    meta = self.api.transaction_metadata(t.tx_hash, return_type='json')
                    for m in meta:
                        ke = json.loads(''.join(m['json_metadata']))
                        seq = int(m['label'])
                        if ke['ked']['i'] == key and seq in self.pendingKEL[key]: del self.pendingKEL[key][seq]
                # Build transaction
                builder = TransactionBuilder(self.context)
                # select utxos
                utxo_sum = 0
                for u in utxos:
                    utxo_sum = utxo_sum + int(u.amount[0].quantity)
                    builder.add_input(
                        UTxO(
                            TransactionInput.from_primitive([u.tx_hash, u.tx_index]),
                            TransactionOutput(address=Address.from_primitive(u.address), amount=int(u.amount[0].quantity))
                        )
                    )
                    utxos.remove(u)
                    if utxo_sum > 6000000: break
                builder.add_output(TransactionOutput(self.spending_addr,Value.from_primitive([5000000])))
                builder.auxiliary_data = AuxiliaryData(Metadata(value))
                signed_tx = builder.build_and_sign([self.payment_signing_key], change_address=self.spending_addr)
                # Submit transaction
                self.context.submit_tx(signed_tx.to_cbor())
            self.pendingKEL = {}
        except Exception as e:
            print("error", e)

    def getaddressBalance(self):
        try:
            address = self.api.address(
                address=self.spending_addr.encode())
            return int(address.amount[0].quantity)
        except ApiError as e:
            return 0

    def fundAddress(self, addr):
        try:
            funding_payment_signing_key = PaymentSigningKey.from_cbor(os.environ.get("FUNDING_ADDRESS_CBORHEX"))
            funding_payment_verification_key = PaymentVerificationKey.from_signing_key(funding_payment_signing_key)
            funding_addr = Address(funding_payment_verification_key.hash(), None, network=NETWORK)
        except KeyError:
            print("Environment variable FUNDING_ADDRESS_CBORHEX not set")
            exit(1)

        funding_balance = self.api.address(address=funding_addr.encode()).amount[0]
        print("Funding address:", funding_addr)
        print("Funding balance:", int(funding_balance.quantity)/1000000,"ADA")
        if int(funding_balance.quantity) > 50000000:
            try:
                builder = TransactionBuilder(self.context)
                builder.add_input_address(funding_addr)
                builder.add_output(TransactionOutput(addr,Value.from_primitive([10000000])))
                builder.add_output(TransactionOutput(addr,Value.from_primitive([10000000])))
                builder.add_output(TransactionOutput(addr,Value.from_primitive([10000000])))
                signed_tx = builder.build_and_sign([funding_payment_signing_key], change_address=funding_addr)
                self.context.submit_tx(signed_tx.to_cbor())
                print("Funds submitted. Wait...")
                time.sleep(50)
                balance = self.getaddressBalance()
                if balance:
                    print("Backer balance:",balance/1000000, "ADA")
            except Exception as e:
                print("error", e)
        else:
            print("Insuficient balance to fund backer")
            exit(1)
