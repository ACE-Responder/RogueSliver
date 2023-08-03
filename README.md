# RogueSliver
A suite of tools to disrupt campaigns using the Sliver C2 framework.

This tool, its uses, and how it was created will be covered in depth on [ACEResponder.com](https://aceresponder.com)

![](https://assets.aceresponder.com/github/roguesliver-01.png)

**This tool is for educational purposes only.**

|||
| --- | --- |
| ExtractCerts.py | Extract mtls certificates and private keys from a minidump of an infected process. Also extracts the implant ID and mtls endpoints. |
| BeaconFlood.py | Flood a Sliver C2 server with beacon and session registrations. Requires mtls certificates. |
| HijackBeacon.py | Hijack a beacon with a valid implant ID and certificates. Log your attacker's requests and send them some memes. Can also create a new false beacon with just an mtls cert. |

## Installation
```
python -m pip install -r requirements.txt
```

## ExtractCerts
```
./ExtractCerts.py sliver.DMP
```

## BeaconFlood.py
```
./BeaconFlood.py 127.0.0.1 8888
```
![](https://assets.aceresponder.com/github/beaconflood.png)
## HijackBeacon
```
./HijackBeacon.py 2aa18069-652a-4484-8ebe-abae87ebc73e 127.0.0.1 8888 -r
```
![](https://assets.aceresponder.com/github/hijackbeacon.png)
