# Python Implementation of the KERI Core Libraries

Project Name:  keripy


## Installation

### Dependencies
#### Binaries

python 3.9.1+
libsodium 1.0.18+



#### python packages
lmdb 0.98+
pysodium 0.7.5+
blake3 0.1.5+
msgpack 1.0.0+
simplejson 3.17.0+
cbor2 5.1.0+


```shell
$ pip3 install -U lmdb pysodium blake3 msgpack simplejson cbor2
```

or separately

```shell
$ pip3 install -U lmdb
$ pip3 install -U pysodium
$ pip3 install -U blake3
$ pip3 install -U msgpack
$ pip3 install -U simplejson
$ pip3 install -U cbor2
```


## Development

### Setup
* Ensure Python 3.9 is present along with venv and dev header files;
* Setup virtual environment: `python3 -m venv keripy`
* Activate virtual environment: `source keripy/bin/activate`
* Setup dependencies: `pip install -r requirements.txt`

### Testing
* Install pytest: `pip install pytest`

* Run the test suites:

```shell
pytest tests/ --ignore tests/demo/
pytest tests/demo/
```



