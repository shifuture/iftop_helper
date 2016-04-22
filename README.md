# IFTOP Helper

## General

By IFTOP log, limit ip by iptables

## CONFIG

```bash
# iftop log path
LOG_FILE="/var/log/iftop.log"

# log lines to check
LOG_LINES=2000

# to block ip prefix
BLOCK_PREFIX=['172.172.']

# skip ip for VERY IMPORTANT GUY
BLOCK_SKIP_IP=['172.172.0.1', '172.172.0.50']

# limit thresh hold
BLOCK_IF_OVER=1024*1024*10 # over 10M

```

## USAGE

```bash
[root@server ~]# netlimit.py 
usage: netlimit [-b <ip>] [-l list] [-a auto block] [-h help]

options:
  -h, --help   show this help message and exit
  -b BLOCK_IP  block the ip provided
  -l           list all ip traffic info
  -a, --auto   auto block the ip(s) which traffic is over limit
```

## Contribute
You are welcome to contribute. 

## License
[MIT](LICENSE)

