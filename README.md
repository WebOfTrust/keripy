# Python Implementation of the KERI Core Libraries

Project Name:  keripy

[![PyPi](https://img.shields.io/pypi/v/keri.svg)](https://pypi.org/project/keri/)
[![GitHub Actions](https://github.com/webOfTrust/keripy/actions/workflows/python-app-ci.yml/badge.svg)](https://github.com/WebOfTrust/keripy/actions)
[![codecov](https://codecov.io/gh/WebOfTrust/keripy/branch/main/graph/badge.svg?token=FR5CB2TPYG)](https://codecov.io/gh/WebOfTrust/keripy)
[![https://pypi.org/project/keri/](https://img.shields.io/pypi/pyversions/keri.svg)](https://pypi.org/project/keri/)
[![Documentation Status](https://readthedocs.org/projects/keripy/badge/?version=latest)](https://keripy.readthedocs.io/en/latest/?badge=latest)

## Installation

### Local installation - build from source
Once all dependencies are installed and working then run:

`$ python3 -m pip install -e ./`

Then you can run 

`$ kli version` 

to get a version string similar to the following: 

`1.0.0`

### Local installation - Docker build
Run `make build-keri` to build your docker image.

Then run `docker run --pull=never -it --entrypoint /bin/bash weboftrust/keri:1.1.19` and you can run `kli version` from within the running container to play with KERIpy.

Make sure the image tag matches the version used in the `Makefile`.
We use `--pull=never` to ensure that docker does not implicitly pull a remote image and relies on the local image tagged during `make build-keri`.

### Dependencies
#### Binaries

python 3.10.4+
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
* Ensure Python 3.10.4 is present along with venv and dev header files;
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

## Building Documentation in `/docs`
* Install sphinx: 
  * `$ pip install sphinx`
  * `$ pip install myst-parser`
* Build with Sphinx in `/docs`: 
  * `$ make html`

