.. role:: bash(code)
   :language: bash

==================================================
Features
==================================================
Key Event Receipt Infrastructure (KERI) is the first truly fully decentralized identity system.


Truly Decentralized Identity
****************************
KERI is the first truly decentralized identity system. It is ledger-less which means it doesn’t need to use a ledger at all or ledger-portable which means that its identifiers are not locked to any given ledger and may switch as needed. In other words KERI identifiers are truly portable.

Supports GDPR Compliance
************************
KERI is inherently supportive of GDPR (global data protection rights) compliance.  KERI provides non-intertwined identifier trust bases which means that a given identifier’s data may be erased and truly forgotten.


Self-Certifying Identifiers
***************************
KERI has a decentralized secure root-of-trust based on cryptographic self-certifying identifiers. It uses hash chained data structures called Key Event Logs that enable ambient cryptographic verifiability. In other words, any log may be verified anywhere at anytime by anybody. It has separable control over shared data which means each entity is truly self-sovereign over their identifiers.

Scalability
***********
KERI is designed for high performance and scalability.  It is compatible with data intensive  event streaming and event sourcing applications.


Key Management Infrastructure
*****************************
One useful way of describing KERI is that it is a decentralized key management infrastructure based on key change events that supports both attestable key events and consensus based verification of key events.


Open Apache2
************
Best of all KERI is open Apache2. It is a project working toward IETF standardization.




Installation
************


Dependencies
------------

Binaries
++++++++

python 3.9.1+
libsodium 1.0.18+



python packages
+++++++++++++++
lmdb 0.98+
pysodium 0.7.5+
blake3 0.1.5+
msgpack 1.0.0+
simplejson 3.17.0+
cbor2 5.1.0+


.. code-block:: shell

  $ pip3 install -U lmdb pysodium blake3 msgpack simplejson cbor2


or separately

.. code-block:: shell

  $ pip3 install -U lmdb
  $ pip3 install -U pysodium
  $ pip3 install -U blake3
  $ pip3 install -U msgpack
  $ pip3 install -U simplejson
  $ pip3 install -U cbor2


Development
***********

Setup
-----
* Ensure Python 3.9 is present along with venv and dev header files;
* Setup virtual environment: :bash:`python3 -m venv keripy`
* Activate virtual environment: :bash:`source keripy/bin/activate`
* Setup dependencies: :bash:`pip install -r requirements.txt`

Testing
-------
* Install pytest: :bash:`pip install pytest`

* Run the test suites:

.. code-block:: bash

  pytest tests/ --ignore tests/demo/
  pytest tests/demo/




