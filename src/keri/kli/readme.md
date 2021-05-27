# KLI

KERI CLI 

A set of example commands which can be used to create a naive KERI demo.
These commands were created to work for a GLIEF demo, use cases will vary.

Usage:

```shell
kli incept -n <name>
```

Create a new prefix with a human friendly identifier. Currently, uses all defaults for generating the prefix, 
but uses persistent storage at the defualt location. Will support configuration through a `-f` option.

```shell
kli rotate -n <name>
```

Performs a key rotation for the given human friendly identifier.

```shell
kli info -n <name>
```

Basic information about the prefix associated with the human friendly identifier.

```shell
kli purge -n <name>  
```
Remove any persisted databases, useful for clean up :)

```shell
kli sign -n <name> --text <foo>
```
Signs an arbitrary string with the current key for the human friendly identifier.

```shell
kli issue -n <name> -dsi <id> --lei <GLEIF LEI>
```

Creates a signed VC, specific to the GLEIF demo.