#!/usr/bin/python
from minidump.minidumpfile import MinidumpFile
import re
import os
import sys
from cryptography import x509
from rich import print


if len(sys.argv) <2:
  print('[red]\[!][/red] Supply a minidump file:\n> ExtractCerts.py sliver.dmp')
  print()
  exit()

minidump = MinidumpFile.parse(sys.argv[1])

reader = minidump.get_reader().get_buffered_reader(segment_chunk_size=10*1024)

def rex_search(reader,pattern,re_flags=0):

  matches = []
  for ms in minidump.memory_segments_64.memory_segments:
    reader.move(ms.start_virtual_address)
    try:
      data = reader.read(ms.size)
      if data:
        r = re.findall(pattern,data,re_flags)
        if len(r):
          for match in r:
            if match not in matches:
              matches += [match]
      del data
    except Exception as e:
      if e.args[0].endswith('segment boundaries!'):
        pass
      else:
        raise e
  return matches


implant_names = []


print()
print('[yellow]\[i][/yellow] Searching for mtls certificates')
print()


certs = rex_search(reader,rb'-----BEGIN [^-]+-----[^\x00-]+-----END[^\x00\n]+',re.MULTILINE)
for cert in certs:
  if b'CERTIFICATE' in cert:
    parsed = x509.load_pem_x509_certificate(cert).subject
    cn = parsed.rfc4514_string().split('=')
    if len(cn) > 1:
      print('[green]\[+][/green] Found implant certificate: [red]'+cn[1]+'[/red]')
      implant_names+=[cn[1]]
      out = 'certs/client.crt'
      os.makedirs(os.path.dirname(out),exist_ok=True)
      with open(out,'w') as f:
        f.write(cert.decode())
      print('Saved implant certificate to certs/ca.key')
    else:
      print('[green]\[+][/green] Found CA certificate')
      out = 'certs/ca.crt'
      os.makedirs(os.path.dirname(out),exist_ok=True)
      with open(out,'w') as f:
        f.write(cert.decode())
      print('Saved CA certificate to certs/ca.key')
  elif b'PRIVATE KEY' in cert:
    print('[green]\[+][/green] Found implant private key')
    out = 'certs/client.key'
    os.makedirs(os.path.dirname(out),exist_ok=True)
    with open(out,'w') as f:
      f.write(cert.decode())
    print('Saved private key to certs/client.key')

print('[yellow]\[i][/yellow] Searching for implant IDs')
print()

for name in implant_names:
  uuids = rex_search(reader,rb'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})[\S\s]{10,20}'+bytes(name,'utf-8'),re.MULTILINE)
  print('[green]\[+][/green] Found implant ID for [red]'+name+'[/red]: '+uuids[0].decode())


print()
print('[yellow]\[i][/yellow] Searching for mtls endpoints')
print()

endpoints = rex_search(reader,rb'mtls://[0-~,:,.]+',re.MULTILINE)
if len(endpoints):
  print('[green]\[+][/green] Found mtls endpoints')
  print('[red]\[!] Multiple mtls endpoints could indicate the attacker has canaries. Check network connections before interacting with the C2 server.[/red]')


for endpoint in endpoints:
  print('[white]'+endpoint.decode()+'[/white]')

