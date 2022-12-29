# Cardano Registrar Backer Demos

This directory contains several scripts to test how Cardano Backer achors Key Events to Cardano BLockchain

## Getting started
Before running the scripts you need to have Cardano all dependency installed. From your `keripy` python environment execute:
```
pip install pycardano blockfrost-python
```
Cardano Backers use Blockfrost API to interact with the blockchain. In order to use the API you must get an API KEY from https://blockfrost.io/. Go to **BUILD APP NOW**, create an account, and you'll be able to add a new project on a Free Tier. Make sure you create the project in the "Cardano Preview" network, and store the generated API KEY.

Now, export your API KEY as an environment variable:
```
export BLOCKFROST_API_KEY={API KEY}
```

## Running a Cardano Backer
Open a terminal and move to the backer demo folder:
```
cd scripts/demo/backer
```
Start a backer with:
```
./start_backer.sh
```
You'll see something like:
```
KERI Keystore created at: /Users/rodo/.keri/ks/witroot
KERI Database created at: /Users/rodo/.keri/db/witroot
KERI Credential Store created at: /Users/rodo/.keri/reg/witroot
Prefix  BArKbRoGIls5U_XYrzKEB1Ap1KkbQZtiJSSUxC15Dl0k
        Public key 1:  BArKbRoGIls5U_XYrzKEB1Ap1KkbQZtiJSSUxC15Dl0k

Cardano Backer Address: addr_test1vpqj4gtpkt6u4mhrt8knneyh9twar9nyfv8tthjus5ykzwg7dt2me
Backer address could not be funded. Environment variable FUNDING_ADDRESS_CBORHEX is not set
Backer witroot ready BArKbRoGIls5U_XYrzKEB1Ap1KkbQZtiJSSUxC15Dl0k
```
From above, note the Backer Prefix and the Backer Address.

Since you don't have a funding address configured, you need to fund the backer address with some ADA to be able to submit transactions. In Cardano testent you can obtain test ADA from [Testnets faucet](https://docs.cardano.org/cardano-testnet/tools/faucet). Select `Preview Testnet` for `Receive test ADA` and add the Backer Address (leave `API Key` field empty). After a minute or so, your backer will be funded with 1000 ADA.

## Running the demo
Open a new terminal and move to the backer demo folder:
```
cd scripts/demo/backer
```
The script `backer_demo-kli.sh` requires two arguments: the backer prefix and the backer address. Execute the following command replacing the arguments with your backer prefix and address:
```
./backer_demo-kli.sh BArKbRoGIls5U_XYrzKEB1Ap1KkbQZtiJSSUxC15Dl0k addr_test1vpqj4gtpkt6u4mhrt8knneyh9twar9nyfv8tthjus5ykzwg7dt2me
```
The demo creates an agent and generates several rotation and interacion events. Note the prefix of the agent.
The demo runs for several minutes and show how the backer queues messages and anchors them in the Cardano blockchain.

## Querying the blockchain
You can query the blockchain to retrieve the anchored KEL with the following `kli` command. Pass your agent prefix in the `pre` parameter:
```
kli backer query --name witroot --alias witroot --ledger cardano --pre ELlumMCbetDfswjL-noy8IvlpxSpw1SsnvMe_4hfrerW
```
You'll receive the KEL from the blockchain as follows:
```
SeqNo:  0
{'ked': {'v': 'KERI10JSON0001a1_',
         't': 'icp',
         'd': 'ELlumMCbetDfswjL-noy8IvlpxSpw1SsnvMe_4hfrerW',
         'i': 'ELlumMCbetDfswjL-noy8IvlpxSpw1SsnvMe_4hfrerW',
         's': '0',
         'kt': '1',
         'k': ['DHeGk8gHhcfbou00yZuz3MGriVZ3Xp_i3xr3N0SCLBUN'],
         'nt': '1',
         'n': ['ELDYBhHpweStMi-7vkJ0PIzpCIMfZ-LXz7C4LCcxduLq'],
         'bt': '1',
         'b': ['BArKbRoGIls5U_XYrzKEB1Ap1KkbQZtiJSSUxC15Dl0k'],
         'c': [],
         'a': [{'ca': 'addr_test1vpqj4gtpkt6u4mhrt8knneyh9twar9nyfv8tthjus5ykzwg7dt2me'}]},
 'stored': True,
 'signatures': [{'index': 0,
                 'signature': 'AABaxURf6A0OTFqU5z4yCa8TSoxMH9guSbBT8x9g3U-aTlY4_R_zCZewJKBf7BJK0mZxC0rKqgw_4QqH1V5U1zgG'}],
 'witnesses': ['BArKbRoGIls5U_XYrzKEB1Ap1KkbQZtiJSSUxC15Dl0k'],
 'witness_signatures': [{'index': 0,
                         'signature': 'AAAowlnEAEHZVucifEi1-XmlTH67dlC7SLO7dXhgo4q_pF_K3t6WBMfKQdAriaZjaIZ78Ltqg5FBme1_jSKeg8gG'}],
 'receipts': {},
 'timestamp': '2022-12-29T21:52:43.781049+00:00'}


SeqNo:  1
{'ked': {'v': 'KERI10JSON000160_',
         't': 'rot',
         'd': 'EJYD0PhIHZx2yJDBRWdNMAjTbCohQznzt9KCPNEeH15D',
         'i': 'ELlumMCbetDfswjL-noy8IvlpxSpw1SsnvMe_4hfrerW',
         's': '1',
         'p': 'ELlumMCbetDfswjL-noy8IvlpxSpw1SsnvMe_4hfrerW',
         'kt': '1',
         'k': ['DNPqk0nVN8kAkyxcVYzKSu7Yu3DMn1KIs_sAsQaqB0C0'],
         'nt': '1',
         'n': ['EFwkUc5LB_xKDcoSTbYAGiiECzPCa9s24mxG7CLC9PwS'],
         'bt': '1',
         'br': [],
         'ba': [],
         'a': []},
 'stored': True,
 'signatures': [{'index': 0,
                 'signature': 'AABNmPCjMXn5Cui3SPxCeYDxPHO1W76rFvrvTml-YeDRBYNsYfi5RvF4TuyzVqaV9pWXkD7EiTboaxN32YMeD2QB'}],
 'witnesses': ['BArKbRoGIls5U_XYrzKEB1Ap1KkbQZtiJSSUxC15Dl0k'],
 'witness_signatures': [{'index': 0,
                         'signature': 'AAAtYwlLH-nurJFEYO44OPNffsonOmwIEJv7aiMZVLWyqRCQAMHhbZgiFQHFPD0xHFPVIGAtsLxIPqwiZWFt7TEG'}],
 'receipts': {},
 'timestamp': '2022-12-29T21:52:53.972007+00:00'}


SeqNo:  2
{'ked': {'v': 'KERI10JSON0001d0_',
         't': 'rot',
         'd': 'EAWaQ76gY4KdZ7XGXNo0ehJEz4BND99dZgOGskC2tYkK',
         'i': 'ELlumMCbetDfswjL-noy8IvlpxSpw1SsnvMe_4hfrerW',
         's': '2',
         'p': 'EJYD0PhIHZx2yJDBRWdNMAjTbCohQznzt9KCPNEeH15D',
         'kt': '1',
         'k': ['DMNLSbRwBWlDhE5RC24hJSsUggs0JUhqSrJ7A5sOXyu1'],
         'nt': '1',
         'n': ['ECxy3KqYxRsWlT6l7QxTKnZgVL-PH7ue-b9YWwRk-rSP'],
         'bt': '1',
         'br': [],
         'ba': [],
         'a': [{'ca': 'EAXJtG-Ek349v43ztpFdRXozyP7YnALdB0DdCEanlHmg',
                's': '0',
                'd': 'EAR75fE1ZmuCSfDwKPfbLowUWLqqi0ZX4502DLIo857Q'}]},
 'stored': True,
 'signatures': [{'index': 0,
                 'signature': 'AABDSRFsOe6dmot2zXL4eBYudJ6IMBZt-UtvH6R9AKiyF3vaIfLTh4m9ucavcAnMD63e7lD5-0bEOFqeedwlcAEE'}],
 'witnesses': ['BArKbRoGIls5U_XYrzKEB1Ap1KkbQZtiJSSUxC15Dl0k'],
 'witness_signatures': [{'index': 0,
                         'signature': 'AADda04B425OV5TENwZ2iOQAAAQbI-Yb7ubVljFel0I1xBrpIRk1kUqaWkRbSk0IkYbMtE649dPM2ENgnC9N-wcD'}],
 'receipts': {},
 'timestamp': '2022-12-29T21:54:44.409720+00:00'}


SeqNo:  3
{'ked': {'v': 'KERI10JSON00013b_',
         't': 'ixn',
         'd': 'EIcrgz2jPU0EwJujmNGSndQr994XEUq2IIK02v7W5sKJ',
         'i': 'ELlumMCbetDfswjL-noy8IvlpxSpw1SsnvMe_4hfrerW',
         's': '3',
         'p': 'EAWaQ76gY4KdZ7XGXNo0ehJEz4BND99dZgOGskC2tYkK',
         'a': [{'ca': 'EAXJtG-Ek349v43ztpFdRXozyP7YnALdB0DdCEanlHmg',
                's': '0',
                'd': 'EAR75fE1ZmuCSfDwKPfbLowUWLqqi0ZX4502DLIo857Q'}]},
 'stored': True,
 'signatures': [{'index': 0,
                 'signature': 'AADHVNT6SuBJH_Vmmx1hMl3L58vCX0qq4ZLM4FsJrKCH9ZzdNFtJbxTINX1ab9z-4xHbW4lpKrWfg0bAQ4rDukEG'}],
 'witnesses': [],
 'witness_signatures': [{'index': 0,
                         'signature': 'AACnKANllqJernu-0HQQFiVZwTe-XspyY55S0YCd4eDAJYL5H4huk1fKZmCpM3MHqOyVlqa7nhhxCFrMO9yiJbcF'}],
 'receipts': {},
 'timestamp': '2022-12-29T21:54:56.471611+00:00'}
 ```

You can also check information from the backer with the following `kli` command:
```
kli backer info --name witroot --alias witroot --ledger cardano 
```
You'll receive something like:
```
Name: witroot
Prefix: BArKbRoGIls5U_XYrzKEB1Ap1KkbQZtiJSSUxC15Dl0k
Network: Cardano TESTNET
Cardano address: addr_test1vpqj4gtpkt6u4mhrt8knneyh9twar9nyfv8tthjus5ykzwg7dt2me
Balance: 9999.769065 ADA
Funding address: NA
Funding balance: NA
```

