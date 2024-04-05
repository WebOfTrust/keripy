# KERIpy Demo Test Scripts

This directory contains several sub-directories containing the demo shell scripts that exercise KERI's capabilities.

## Getting Started
Before running any of the scripts here, you need to source the file `demo-scripts.sh` into your current shell to set
the environment variables used to locate additional files needed during the execution of some commands.  The easiest way to
do this is with either

`source demo-scripts.sh`

or

`. demo-scripts.sh`

depending on your shell.

You also need to have `jq` installed on your machine as the scripts use it to pretty print the JSON results of many of the 
commands.

### Python Requirements
We recommend using a virtual environment manager like `venv` or `pyenv` to set up a virtual environment with the version
of python listed in `setup.py` and `pip` for that version of Python.   Once that is done, install the required dependencies with:

`pip install -r requirements.txt`


## Directory Layout
The directories each exercise different parts of the KERI core library:

* basic - Exercises the KERI key management functionality from basic identifier inception to distributed multisig and delegations
* credentials - Exercises the KERI / ACDC credential issuance capabilities from single and multi-sig identifiers
* vLEI - Launches configures agents in accordance with the requirements of the GLEIF vLEI ecosystem and credentials

Each directory contains a README.md file that details additional steps or modifications to the steps listed below for running
the scripts in that directory.

## Command Line vs ReST Scripts
In many cases, the scripts were created in pairs with one script exercising a set of functions from the `kli` command line
utility and a sister script with `-agent` appended to the name that exercises the same set of funcitons using `curl` against
a running agent.  To run the `-agent` commands, a single agent or set of agents must be run before using the script.  In addition
many scripts require a set of witnesses be running locally.  The following section details how to run agents and witnesses.

### Running Witnesses
Witnesses can be started in several ways using the `kli witness` subcommands or the shell script `demo/basic/start-witness.sh`.  The
following 2 subcommands are available for starting witnesses:

* `kli witness start` - starts a single witness (used inside the start-witness.sh script)
* `kli witness demo` - starts a collection of 3 witnesses on known ports with known AIDs.

For most of the scripts that require witnesses you will use `kli witness demo` to start the 3 known witnesses.


### Additional Software
Some scripts require addition services from other repositories.  Those requirements are listed in the README.md files 
inside individual directories.


## Deleting Database Directories
KERIpy core library manages database directories for key event log, transaction event log, credential and private key storage.  
The library will create the directories in one of 3 locations on the local file system:

* `/tmp`
* `/usr/local/var/keri`
* `$HOME/.keri`

If the core library is initialize with a setting of `temp=False` (for example in unit tests) all database directories are created in `/tmp`.  
This location is not used with the demo scripts.  If the directory `/usr/local/var/keri` exists and the current user has write access to that directory
the the core library will place all database directories there.  If either that directory does not exist or is not writable, then the core library
will create the database directories under `.keri` in the current users home directory.

Each demo script was written expecting a clean database to ensure there are no conflicts with identifiers or credentials created
by other scripts.  It is recommended that developers running these scripts clear the database location before starting the witnesses
and running the scripts.  For example, before each script running something like: 

`rm -rf /usr/local/var/keri/*;kli witness demo`

creates a clean environment and starts the demo set of 3 known witnesses.
