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
from  pprint import pp
import os
import time
import json

QUEUE_DURATION = 60
NETWORK = Network.TESTNET
MINIMUN_BALANCE = 5000000
FUNDING_AMOUNT = 30000000
TRANSACTION_AMOUNT = 1000000

class Cardano:
    """
    Environment variables required:
        - BLOCKFROST_API_KEY = API KEY from Blockfrots  https://blockfrost.io
        - FUNDING_ADDRESS_CBORHEX = Optional, for testing purposes. Private Key of funding address as CBOR Hex. Must be an Enterprice address (no Staking part) as PaymentSigningKeyShelley_ed25519
    
    Additional libraries required:
        pip install pycardano blockfrost-python 
    See Backer designation event: https://github.com/WebOfTrust/keripy/issues/90

    Features:
        - Cardano Address is derived from the same Ed25519 seed (private key) used to derive the prefix of the backer
        - Anchoring KELs from multiple prefixes
        - Queue events during a period of time to allow several block confirmations as a safety meassure
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

        # retrieve backer private key and derive cardano address
        backerPrivateKey = ks.pris.get(hab.kever.prefixer.qb64).raw
        self.payment_signing_key = PaymentSigningKey(backerPrivateKey,"PaymentSigningKeyShelley_ed25519","PaymentSigningKeyShelley_ed25519")
        payment_verification_key = PaymentVerificationKey.from_signing_key(self.payment_signing_key)
        self.spending_addr = Address(payment_part=payment_verification_key.hash(),staking_part=None, network=NETWORK)
        print("Cardano Backer Address:", self.spending_addr.encode())
        
        # check address balance and try to fund if necesary
        balance = self.getaddressBalance()
        if balance and balance > MINIMUN_BALANCE:
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
            kels_to_remove = []
            for key, value in self.pendingKEL.items():
                # Check last KE in blockchain to avoid duplicates (for some reason (TBD) mailbox may submit an event twice)                
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
                utxo_to_remove = []
                for u in utxos:
                    utxo_sum = utxo_sum + int(u.amount[0].quantity)
                    builder.add_input(
                        UTxO(
                            TransactionInput.from_primitive([u.tx_hash, u.tx_index]),
                            TransactionOutput(address=Address.from_primitive(u.address), amount=int(u.amount[0].quantity))
                        )
                    )
                    utxo_to_remove.append(u)
                    if utxo_sum > (TRANSACTION_AMOUNT + 2000000): break
                for ur in utxo_to_remove: utxos.remove(ur)
                builder.add_output(TransactionOutput(self.spending_addr,Value.from_primitive([TRANSACTION_AMOUNT])))
                builder.auxiliary_data = AuxiliaryData(Metadata(value))
                signed_tx = builder.build_and_sign([self.payment_signing_key], change_address=self.spending_addr)
                # Submit transaction
                self.context.submit_tx(signed_tx.to_cbor())
                kels_to_remove.append(key)
            self.pendingKEL = {}
        except Exception as e:
            for k in kels_to_remove: del self.pendingKEL[k]
            self.timer = Timer(90, self.flushQueue)
            self.timer.start()

    def getaddressBalance(self):
        try:
            address = self.api.address(address=self.spending_addr.encode())
            return int(address.amount[0].quantity)
        except ApiError as e:
            return 0

    def fundAddress(self, addr):
        try:
            funding_payment_signing_key = PaymentSigningKey.from_cbor(os.environ["FUNDING_ADDRESS_CBORHEX"])
            funding_payment_verification_key = PaymentVerificationKey.from_signing_key(funding_payment_signing_key)
            funding_addr = Address(funding_payment_verification_key.hash(), None, network=NETWORK)
        except KeyError:
            print("Backer address could not be funded. Environment variable FUNDING_ADDRESS_CBORHEX is not set")
            return

        funding_balance = self.api.address(address=funding_addr.encode()).amount[0]
        print("Funding address:", funding_addr)
        print("Funding balance:", int(funding_balance.quantity)/1000000,"ADA")
        if int(funding_balance.quantity) > (FUNDING_AMOUNT + 1000000):
            try:
                builder = TransactionBuilder(self.context)
                builder.add_input_address(funding_addr)
                builder.add_output(TransactionOutput(addr,Value.from_primitive([int(FUNDING_AMOUNT/3)])))
                # builder.add_output(TransactionOutput(addr,Value.from_primitive([int(FUNDING_AMOUNT/3)])))
                # builder.add_output(TransactionOutput(addr,Value.from_primitive([int(FUNDING_AMOUNT/3)])))
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


def getInfo(alias, hab, ks):
    try:
        blockfrostProjectId=os.environ['BLOCKFROST_API_KEY']
    except KeyError:
        print("Environment variable BLOCKFROST_API_KEY not set")
        exit(1)
    api = BlockFrostApi(
        project_id=blockfrostProjectId,
        base_url=ApiUrls.preview.value
        )
    backerPrivateKey = ks.pris.get(hab.kever.prefixer.qb64).raw
    payment_signing_key = PaymentSigningKey(backerPrivateKey,"PaymentSigningKeyShelley_ed25519","PaymentSigningKeyShelley_ed25519")
    payment_verification_key = PaymentVerificationKey.from_signing_key(payment_signing_key)
    spending_addr = Address(payment_part=payment_verification_key.hash(),staking_part=None, network=NETWORK)
    try:
        address = api.address(address=spending_addr.encode())
        balance = int(address.amount[0].quantity)
    except ApiError as e:
        print("error", e)


    try:
        funding_payment_signing_key = PaymentSigningKey.from_cbor(os.environ.get("FUNDING_ADDRESS_CBORHEX"))
        funding_payment_verification_key = PaymentVerificationKey.from_signing_key(funding_payment_signing_key)
        funding_addr = Address(funding_payment_verification_key.hash(), None, network=NETWORK).encode()
        f_address = api.address(address=funding_addr)
        funding_balace = int(f_address.amount[0].quantity)
    except:
        funding_addr = "NA"
        funding_balace = "NA"

    print("Name:", alias)
    print("Prefix:", hab.kever.prefixer.qb64)
    print("Network:", "Cardano", NETWORK.name)
    print("Cardano address:", spending_addr.encode())
    print("Balance:", balance/1000000, "ADA")
    print("Funding address:", funding_addr)
    print("Funding balance:", funding_balace/1000000, "ADA")

def queryBlockchain(prefix, hab,ks):
    try:
        blockfrostProjectId=os.environ['BLOCKFROST_API_KEY']
    except KeyError:
        print("Environment variable BLOCKFROST_API_KEY not set")
        exit(1)
    api = BlockFrostApi(
        project_id=blockfrostProjectId,
        base_url=ApiUrls.preview.value
        )
    backerPrivateKey = ks.pris.get(hab.kever.prefixer.qb64).raw
    payment_signing_key = PaymentSigningKey(backerPrivateKey,"PaymentSigningKeyShelley_ed25519","PaymentSigningKeyShelley_ed25519")
    payment_verification_key = PaymentVerificationKey.from_signing_key(payment_signing_key)
    spending_addr = Address(payment_part=payment_verification_key.hash(),staking_part=None, network=NETWORK)

    txs = api.address_transactions(spending_addr.encode())
    for tx in txs:
        tx_detail = api.transaction(tx.tx_hash)
        meta = api.transaction_metadata(tx.tx_hash, return_type='json')
        if meta:
            # print("Fees: ",str(int(tx_detail.fees)/1000000), "ADA")
            for n in meta:
                ke = json.loads(''.join(n['json_metadata']))
                if prefix == ke['ked']['i']:
                    print("SeqNo: ",n['label'])
                    pp(ke)
                    print("\n")

    return
