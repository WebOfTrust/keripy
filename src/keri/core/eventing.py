# -*- encoding: utf-8 -*-
"""
keri.core.eventing module

"""

"""
serialization encoding

KERI_1.0_application/keri+json
KERI_1.0_application/keri+cbor
KERI_1.0_application/keri+msgpack
KERI_1.0_application/keri+binary

event = {}
event["version"] = "KERI_1.0_application/keri+json"
event["prefix"] = "ABCDEFG"
event["sn"] = "1"


event
{'version': 'KERI_1.0_application/keri+json', 'prefix': 'ABCDEFG', 'sn': '1'}



j = json.dumps(event, indent=2)

('{\n'
 '  "version": "KERI_1.0_application/keri+json",\n'
 '  "prefix": "ABCDEFG",\n'
 '  "sn": "1"\n'
 '}')

k = json.dumps(event)

'{"version": "KERI_1.0_application/keri+json", "prefix": "ABCDEFG", "sn": "1"}'

json.dumps(event, separators=(",", ":"),  ensure_ascii=False)
'{"version":"KERI_1.0_application/keri+json","prefix":"ABCDEFG","sn":"1"}'

import json
j = json.dumps(event, separators=(",", ":"))
j
'{"version":"KERI_1.0_application/keri+json","prefix":"ABCDEFG","sn":"1"}'

separators=(',', ':')

json.dumps(event, separators=(",", ":"),  indent=2)
('{\n'
 '  "version":"KERI_1.0_application/keri+json",\n'
 '  "prefix":"ABCDEFG",\n'
 '  "sn":"1"\n'
 '}')

Default javascript json.stringify behavior is the same as the python json with
separators = (',', ':') i.e. no spaces so the most compact form.

Adding indents in python or spaces in javascript also adds newlines

import ujson
ujson.dumps(event)
'{"version":"KERI_1.0_application\\/keri+json","prefix":"ABCDEFG","sn":"1"}'

ujson.dumps(event, escape_forward_slashes=False)
'{"version":"KERI_1.0_application/keri+json","prefix":"ABCDEFG","sn":"1"}'

ujson.dumps(event, escape_forward_slashes=False, ensure_ascii=False)
'{"version":"KERI_1.0_application/keri+json","prefix":"ABCDEFG","sn":"1"}'

ujson.dumps(event, escape_forward_slashes=False, ensure_ascii=False, indent=2)
('{\n'
 '  "version": "KERI_1.0_application/keri+json",\n'
 '  "prefix": "ABCDEFG",\n'
 '  "sn": "1"\n'
 '}')


import simplejson
simplejson.dumps(event, separators=(",", ":"))
'{"version":"KERI_1.0_application/keri+json","prefix":"ABCDEFG","sn":"1"}'

simplejson.dumps(event, separators=(",", ":"),  ensure_ascii=False)
'{"version":"KERI_1.0_application/keri+json","prefix":"ABCDEFG","sn":"1"}'

c = cbor2.dumps(event)
c
b'\xa3gversionx\x1eKERI_1.0_application/keri+jsonfprefixgABCDEFGbsna1'
b = bytearray(c)
b
bytearray(b'\xa3gversionx\x1eKERI_1.0_application/keri+jsonfprefixgABCDEFGbsna'
          b'1')
b.hex()
'a36776657273696f6e781e4b4552495f312e305f6170706c69636174696f6e2f6b6572692b6a736f6e66707265666978674142434445464762736e6131'

m = msgpack.dumps(event)
m
(b'\x83\xa7version\xbeKERI_1.0_application/keri+json\xa6prefix\xa7ABCDEFG\xa2'
 b'sn\xa11')


alt = {}
alt["sn"] = "1"
alt["prefix"] = "ABCDEFG"
alt["version"] = "KERI_1.0_application/keri+json"
alt
{'sn': '1', 'prefix': 'ABCDEFG', 'version': 'KERI_1.0_application/keri+json'}

json.dumps(alt)
'{"sn": "1", "prefix": "ABCDEFG", "version": "KERI_1.0_application/keri+json"}'

cbor2.dumps(alt)
b'\xa3bsna1fprefixgABCDEFGgversionx\x1eKERI_1.0_application/keri+json'

msgpack.dumps(alt)
(b'\x83\xa2sn\xa11\xa6prefix\xa7ABCDEFG\xa7version\xbeKERI_1.0_application/k'
 b'eri+json')




https://blog.ionelmc.ro/2015/11/22/memory-use-and-speed-of-json-parsers/

The internal ownPropertyKeys method



e1
{'version': 'KERI_1.0_application/keri+json', 'prefix': 'ABCDEFG', 'sn': '0001'}

e2
{'version': 'KERI_1.0_application/keri+cbor', 'prefix': 'ZYXWVUT', 'sn': '0002'}


e1s = cbor2.dumps(e1)
len(e1s)
64
e2s = cbor2.dumps(e2)
len(e2s)
64

e1s
b'\xa3gversionx\x1eKERI_1.0_application/keri+jsonfprefixgABCDEFGbsnd0001'
e2s
b'\xa3gversionx\x1eKERI_1.0_application/keri+cborfprefixgZYXWVUTbsnd0002'

e3
{'version': 'KERI_1.0_application/keri+json',
 'prefix': 'ABCDEFG',
 'sn': '0001',
 'digest': 'MNOPQRST'}

e3s = cbor2.dumps(e3)
len(e3s)
80

e3s
(b'\xa4gversionx\x1eKERI_1.0_application/keri+jsonfprefixgABCDEFGbsnd0001fdig'
 b'esthMNOPQRST')
len(e3s)

e4
{'version': 'KERI_1.0_application/keri+json',
 'prefix': 'ABCDEFG',
 'sn': '0001',
 'digest': 'MNOPQRST',
 'ilk': 'icp'}
e4s = cbor2.dumps(e4)
e4s
(b'\xa5gversionx\x1eKERI_1.0_application/keri+jsonfprefixgABCDEFGbsnd0001fdig'
 b'esthMNOPQRSTcilkcicp')


x = e2s[1:41]
x
b'gversionx\x1eKERI_1.0_application/keri+cbor'


j = '{"version":"KERI_1.0_application/keri+json","prefix":"ABCDEFG","sn":"1"}'
j
'{"version":"KERI_1.0_application/keri+json","prefix":"ABCDEFG","sn":"1"}'
jb = j.encode("utf-8")
jb
b'{"version":"KERI_1.0_application/keri+json","prefix":"ABCDEFG","sn":"1"}'


e1s = msgpack.dumps(e1)
e1s
(b'\x83\xa7version\xbeKERI_1.0_application/keri+json\xa6prefix\xa7ABCDEFG\xa2'
 b'sn\xa40001')
e2s = msgpack.dumps(e2)
e2s
(b'\x83\xa7version\xbeKERI_1.0_application/keri+cbor\xa6prefix\xa7ZYXWVUT\xa2'
 b'sn\xa40002')
e3s = msgpack.dumps(e3)
e3s
(b'\x84\xa7version\xbeKERI_1.0_application/keri+json\xa6prefix\xa7ABCDEFG\xa2'
 b'sn\xa40001\xa6digest\xa8MNOPQRST')
e4
{'version': 'KERI_1.0_application/keri+json',
 'prefix': 'ABCDEFG',
 'sn': '0001',
 'digest': 'MNOPQRST',
 'ilk': 'icp'}
e4s = msgpack.dumps(e4)
e4s
(b'\x85\xa7version\xbeKERI_1.0_application/keri+json\xa6prefix\xa7ABCDEFG\xa2'
 b'sn\xa40001\xa6digest\xa8MNOPQRST\xa3ilk\xa3icp')



"""
