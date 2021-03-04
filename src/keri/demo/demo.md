# KERI Direct Mode

When installing KERI with pip3 it installs two demo scripts:

```bash
/usr/local/bin/keri_bob
/usr/local/bin/keri_eve
```

Running both of these, each in its on shell (terminal) will run a simple demo
that exchanging KERI event messages and receipt message or (chits)
for transferable identifier prefixes.

The terminal console will print out the messages that are exchanged.
"Bob" initiates the exchange once it connects to "Eve"

To exit each script just type in cntl-c in the respective terminal window or
set a run time expiration when invoking each script.

For help run the script with -h or --help
such as.

```
% keri_bob -h
usage: keri_bob [-h] [-V] [-r REMOTE] [-l LOCAL] [-e EXPIRE] [-n NAME]

Runs KERI direct mode demo controller. Example: keri_bob -r 5621 -l 5620 --e 10.0'

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         Prints out version of script runner.
  -r REMOTE, --remote REMOTE
                        Remote port number the client connects to. Default is 5621.
  -l LOCAL, --local LOCAL
                        Local port number the server listens on. Default is 5620.
  -e EXPIRE, --expire EXPIRE
                        Expire time for demo. 0.0 means not expire. Default is 0.0.
  -n NAME, --name NAME  Name of controller. Default is bob.

```

and

```
% keri_eve -h
usage: keri_eve [-h] [-V] [-r REMOTE] [-l LOCAL] [-e EXPIRE] [-n NAME]

Runs KERI direct mode demo controller. Example: keri_eve -r 5620 -l 5621 --e 10.0

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         Prints out version of script runner.
  -r REMOTE, --remote REMOTE
                        Remote port number the client connects to. Default is 5621.
  -l LOCAL, --local LOCAL
                        Local port number the server listens on. Default is 5620.
  -e EXPIRE, --expire EXPIRE
                        Expire time for demo. 0.0 means not expire. Default is 0.0.
  -n NAME, --name NAME  Name of controller. Default is eve.

```



## To Run from Development Repo Directory

In order to run the demo commands directly from the development repository
one must setup the shell PYTHONPATH environment variable to point to
the keripy src directory that includes the keri package

.zsh

#PYTHONPATH
export PYTHONPATH="..../keripy/src:$PYTHONPATH"



Then to run use shell command

% python3 -m keri.demo.demo_bob

Works.
Where demo_bob is in
..../keripy/src/keri/demo/demo_bob.py


So to run bob and eve together. Open two shells one for each and point their
TCP ports at each other.

Bob's tcp ports default to remote 5621  local 5620
Eve's tcp ports default to remote 5620  local 5621
Sam's tcp ports default to  remote 5621  local 5620

so Bob and Eve or Sam and Eve work without changing ports

To change ports use the command line options
-r or --remote
-l or --local


## Example


### Bob's terminal window
```zsh
% python3 -m keri.demo.demo_bob
Direct Mode demo of bob as EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w on TCP port 5620 to port 5621.


EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w:
 connected to ('127.0.0.1', 5621).


EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w sent event:
b'{"v":"KERI10JSON0000e6_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAmDoPp9jDio1hznNDO-3T2KA_FUbY8f_qybT6_FqPAuf89e9AMDXP5wch6jvT4Ev4QRp8HqtTb9t2Y6_KJPYlBw'


EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w received:
bytearray(b'{"v":"KERI10JSON0000e6_","i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg","s":"0","t":"icp","kt":"1","k":["D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"],"n":"EOWDAJvex5dZzDxeHBANyaIoUG3F4-ic81G6GwtnC4f4","wt":"0","w":[],"c":[]}-AABAAll_W0_FsjUyJnYokSNPqq7xdwIBs0ebq2eUez6RKNB-UG_y6fD0e6fb_nANvmNCWjsoFjWv3XP3ApXUabMgyBA{"v":"KERI10JSON000105_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w","s":"0","t":"vrc","d":"EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o","a":{"i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg","s":"0","d":"EGFSGYH2BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzupo"}}-AABAAb6S-RXeAqUKl8UuNwYpiaFARhMj-95elxmr7uNU8m7buVSPVLbTWcQYfI_04HoP_A_fvlU_b099fiEJyDSA2Cg')


EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w sent cue:
{'pre': 'EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg', 'serder': <keri.core.coring.Serder object at 0x10b3d4a90>}


EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w sent chit:
b'{"v":"KERI10JSON000105_","i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg","s":"0","t":"vrc","d":"EGFSGYH2BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzupo","a":{"i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w","s":"0","d":"EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o"}}-AABAAZqxNTt_LDZnmwEIaJX0cK9VKkCGq1UieEx6881MKKOtlRirvs_4pzFgmw3aRwAaIM2XV0biQ7xHeOoXglluDCA'


EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w sent event:
b'{"v":"KERI10JSON000122_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w","s":"1","t":"rot","p":"EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","wt":"0","wr":[],"wa":[],"a":[]}-AABAAEuHTj2jo-QgGg1FP0tq_q2MjCeJnzYoJY1Iw2h4ov3J4ki82aHDWxYhxMiXX-E8b0vRDfr3-EB11ofd_zx3cBQ'


EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w received:
bytearray(b'{"v":"KERI10JSON000105_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w","s":"1","t":"vrc","d":"Enrq74_Q11S2vHx1gpK_46Ik5Q7Yy9K1zZ5BavqGDKnk","a":{"i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg","s":"0","d":"EGFSGYH2BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzupo"}}-AABAAb1BJLLTkcTlefF1DOPKiOixLgQqnqxRsqEqGaaADLNwQ-uDeb2nNTQBB6SeclaihimPg9QwLnulUbdgYxI5ADg')


EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w sent event:
b'{"v":"KERI10JSON000098_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w","s":"2","t":"ixn","p":"Enrq74_Q11S2vHx1gpK_46Ik5Q7Yy9K1zZ5BavqGDKnk","a":[]}-AABAARxj7iqT5m3wQIPOfCPFkeGEw1j5QY-lXbRGaRSVxzW9SZIX-mXJfIjs7m6MlaYFEIJs3fiCWCj9JdUz0BHlRDA'


EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w received:
bytearray(b'{"v":"KERI10JSON000105_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w","s":"2","t":"vrc","d":"E-5RimdY_OWoreR-Z-Q5G81-I4tjASJCaP_MqkBbtM2w","a":{"i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg","s":"0","d":"EGFSGYH2BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzupo"}}-AABAA71XY3Y7gt3FQ3RkRDN2JN5wsKVFSqxc55yBl3PecKEpSSn_tjjtKxhvZZgWtvUxHiaSt94h8huBZ0jVdWeM6DA')





```

### Eve's terminal window
```zsh
% python3 -m keri.demo.demo_bob
Direct Mode demo of bob as EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w on TCP port 5620 to port 5621.

% python3 -m keri.demo.demo_eve
Direct Mode demo of eve as EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg on TCP port 5621 to port 5620.


EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg:
 connected to ('127.0.0.1', 5620).


EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg received:
bytearray(b'{"v":"KERI10JSON0000e6_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAmDoPp9jDio1hznNDO-3T2KA_FUbY8f_qybT6_FqPAuf89e9AMDXP5wch6jvT4Ev4QRp8HqtTb9t2Y6_KJPYlBw')


EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg sent cue:
{'pre': 'EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w', 'serder': <keri.core.coring.Serder object at 0x10717c790>}


EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg sent event:
b'{"v":"KERI10JSON0000e6_","i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg","s":"0","t":"icp","kt":"1","k":["D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"],"n":"EOWDAJvex5dZzDxeHBANyaIoUG3F4-ic81G6GwtnC4f4","wt":"0","w":[],"c":[]}-AABAAll_W0_FsjUyJnYokSNPqq7xdwIBs0ebq2eUez6RKNB-UG_y6fD0e6fb_nANvmNCWjsoFjWv3XP3ApXUabMgyBA'


EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg sent chit:
b'{"v":"KERI10JSON000105_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w","s":"0","t":"vrc","d":"EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o","a":{"i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg","s":"0","d":"EGFSGYH2BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzupo"}}-AABAAb6S-RXeAqUKl8UuNwYpiaFARhMj-95elxmr7uNU8m7buVSPVLbTWcQYfI_04HoP_A_fvlU_b099fiEJyDSA2Cg'


EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg received:
bytearray(b'{"v":"KERI10JSON000105_","i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg","s":"0","t":"vrc","d":"EGFSGYH2BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzupo","a":{"i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w","s":"0","d":"EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o"}}-AABAAZqxNTt_LDZnmwEIaJX0cK9VKkCGq1UieEx6881MKKOtlRirvs_4pzFgmw3aRwAaIM2XV0biQ7xHeOoXglluDCA')


EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg received:
bytearray(b'{"v":"KERI10JSON000122_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w","s":"1","t":"rot","p":"EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","wt":"0","wr":[],"wa":[],"a":[]}-AABAAEuHTj2jo-QgGg1FP0tq_q2MjCeJnzYoJY1Iw2h4ov3J4ki82aHDWxYhxMiXX-E8b0vRDfr3-EB11ofd_zx3cBQ')


EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg sent cue:
{'pre': 'EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w', 'serder': <keri.core.coring.Serder object at 0x10717c880>}


EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg sent chit:
b'{"v":"KERI10JSON000105_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w","s":"1","t":"vrc","d":"Enrq74_Q11S2vHx1gpK_46Ik5Q7Yy9K1zZ5BavqGDKnk","a":{"i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg","s":"0","d":"EGFSGYH2BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzupo"}}-AABAAb1BJLLTkcTlefF1DOPKiOixLgQqnqxRsqEqGaaADLNwQ-uDeb2nNTQBB6SeclaihimPg9QwLnulUbdgYxI5ADg'


EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg received:
bytearray(b'{"v":"KERI10JSON000098_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w","s":"2","t":"ixn","p":"Enrq74_Q11S2vHx1gpK_46Ik5Q7Yy9K1zZ5BavqGDKnk","a":[]}-AABAARxj7iqT5m3wQIPOfCPFkeGEw1j5QY-lXbRGaRSVxzW9SZIX-mXJfIjs7m6MlaYFEIJs3fiCWCj9JdUz0BHlRDA')


EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg sent cue:
{'pre': 'EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w', 'serder': <keri.core.coring.Serder object at 0x10717c790>}


EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg sent chit:
b'{"v":"KERI10JSON000105_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w","s":"2","t":"vrc","d":"E-5RimdY_OWoreR-Z-Q5G81-I4tjASJCaP_MqkBbtM2w","a":{"i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg","s":"0","d":"EGFSGYH2BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzupo"}}-AABAA71XY3Y7gt3FQ3RkRDN2JN5wsKVFSqxc55yBl3PecKEpSSn_tjjtKxhvZZgWtvUxHiaSt94h8huBZ0jVdWeM6DA'





```
