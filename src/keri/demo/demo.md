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

To exit each script just type in cntl-c in the respective terminal window or set a run time expiration when invoking each script.

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