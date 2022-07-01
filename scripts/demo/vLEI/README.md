# vLEI Ecosystem Test Scripts

These scripts are so far disorganized and not fully tested.  They were created to facilitate the creation and testing
of the Keep software which requires interactions between many participants each with their own agents and identifiers.  More
work is need to clean these scripts up and organize them into a meaningful collection that can stand up an entire vLEI
ecosystem of agents.

They all require the following commands run in separate terminal windows prior to execution:

* `kli agent vlei`
* `kli witness demo`

and from the vLEI repo run:

* `vLEI-server -s ./schema/acdc -c ./samples/acdc/ -o ./samples/oobis/`
