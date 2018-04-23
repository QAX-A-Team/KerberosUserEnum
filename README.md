# KerberosUserEnum
Kerberos accounts enumeration taking advantage of AS-REQ, I wrote this script to practice my understanding of Kerberos.

[Kerberos Domain Username Enumeration](https://www.attackdebris.com/?p=311)

[Kerberos AS-REQ 之用户枚举](https://mp.weixin.qq.com/s?__biz=MzI5Nzc0OTkxOQ==&mid=2247483789&idx=1&sn=e29dcc3c2d90d2a960543dc244c82ad2&chksm=ecb11d7ddbc6946bb253efef5f0a1e41a4ceca9177b8dd708a89b83818a0797afc259ec2e39d#rd)

Example:
./Enum.py --file=/tmp/usernames --dcip=192.168.88.1 --domain=TESTDOMAIN --port=88
