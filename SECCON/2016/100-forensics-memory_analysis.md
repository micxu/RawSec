---
layout: post
title: "SECCON - 100 - Memory Analysis - Forensics"
lang: en
categories:
  - security
  - writeups
tags:
  - security
  - writeups
  - ctf
  - forensics
date: 2016/12/10
thumbnail: /images/ctf.png
---
## Informations

### Version

| By            | Version | Comment
| ---           | ---     | ---
| Chill3d       | 1.0     | Creation

### CTF

- **Name** : SECCON 2016 Online CTF
- **Website** : [seccon.jp](http://2016.seccon.jp/news/#124)
- **Type** : Online
- **Format** : Jeopardy
- **CTF Time** : [link](https://ctftime.org/event/354/)

### Description

> Find the website that the fake svchost is accessing.
>
> You can get the flag if you access the website!!
>
> The challenge files are huge, please download it first.
>
>Hint1: http://www.volatilityfoundation.org/
>
> Hint2: Check the hosts file
>
> password: fjliejflsjiejlsiejee33cnc

## Solution

For this challenge, we get a zip file wih a raw memory dump inside named *forensic_100.raw*.

First, let's determine which OS is this dump come from :

```
➜ volatility -f forensic_100.raw imageinfo
Volatility Foundation Volatility Framework 2.5
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/media/sf_Challenges/CTF/SECCON/forensic_100.raw)
                      PAE type : PAE
                           DTB : 0x34c000L
                          KDBG : 0x80545ce0L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2016-12-06 05:28:47 UTC+0000
     Image local date and time : 2016-12-06 14:28:47 +0900
```

Check the hosts file as the second hint say :

```
➜ volatility -f forensic_100.raw --profile=WinXPSP2x86 dumpfiles -Q 0x000000000217b748 --dump-dir=.
Volatility Foundation Volatility Framework 2.5
DataSectionObject 0x0217b748   None   \Device\HarddiskVolume1\WINDOWS\system32\drivers\etc\hosts

➜ ls
file.None.0x819a3008.dat  forensic_100.raw  memoryanalysis.zip

➜ cat file.None.0x819a3008.dat
# Copyright (c) 1993-1999 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

127.0.0.1       localhost
153.127.200.178    crattack.tistory.com #                                               
```

So the DNS entry crattack.tistory.com is pointing on the 153.127.200.178 IP adress.

List processus to see what was running when the memory was captured :

```
➜ volatility -f forensic_100.raw --profile=WinXPSP2x86 pstree
Volatility Foundation Volatility Framework 2.5
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0x8231f698:explorer.exe                             1556   1520     15    466 2016-12-06 05:27:10 UTC+0000
. 0x821f8438:vmtoolsd.exe                            1856   1556      3    129 2016-12-06 05:27:11 UTC+0000
. 0x819b4380:tcpview.exe                             3308   1556      2     84 2016-12-06 05:28:42 UTC+0000
. 0x82267900:rundll32.exe                            1712   1556      2    144 2016-12-06 05:27:16 UTC+0000
. 0x8216a5e8:DumpIt.exe                              3740   1556      1     25 2016-12-06 05:28:46 UTC+0000
. 0x82170da0:ctfmon.exe                              1872   1556      1     87 2016-12-06 05:27:11 UTC+0000
 0x823c8660:System                                      4      0     58    259 1970-01-01 00:00:00 UTC+0000
. 0x81a18020:smss.exe                                 540      4      3     19 2016-12-06 05:27:04 UTC+0000
.. 0x82173da0:winlogon.exe                            628    540     24    541 2016-12-06 05:27:07 UTC+0000
... 0x8216e670:services.exe                           672    628     15    286 2016-12-06 05:27:07 UTC+0000
.... 0x81f46238:alg.exe                              2028    672      7    104 2016-12-06 05:27:16 UTC+0000
.... 0x82312450:svchost.exe                          1036    672     87   1514 2016-12-06 05:27:08 UTC+0000
..... 0x81f2cb20:wuauclt.exe                         3164   1036      5    107 2016-12-06 05:28:15 UTC+0000
..... 0x82062b20:wuauclt.exe                          488   1036      7    132 2016-12-06 05:27:13 UTC+0000
..... 0x81e56228:wscntfy.exe                          720   1036      1     37 2016-12-06 05:27:18 UTC+0000
.... 0x82154880:vmacthlp.exe                          836    672      1     25 2016-12-06 05:27:08 UTC+0000
.... 0x82151ca8:svchost.exe                           936    672     10    272 2016-12-06 05:27:08 UTC+0000
.... 0x81e4b4b0:vmtoolsd.exe                          312    672      9    265 2016-12-06 05:27:13 UTC+0000
.... 0x81f92778:svchost.exe                          1088    672      7     83 2016-12-06 05:27:08 UTC+0000
.... 0x81f00558:VGAuthService.e                       196    672      2     60 2016-12-06 05:27:13 UTC+0000
.... 0x81e18da0:svchost.exe                           848    672     20    216 2016-12-06 05:27:08 UTC+0000
..... 0x81e89200:wmiprvse.exe                         596    848     12    255 2016-12-06 05:27:13 UTC+0000
.... 0x81e41928:svchost.exe                          1320    672     12    183 2016-12-06 05:27:10 UTC+0000
.... 0x81f0dbe0:spoolsv.exe                          1644    672     15    133 2016-12-06 05:27:10 UTC+0000
.... 0x81f65da0:svchost.exe                          1776    672      2     23 2016-12-06 05:27:10 UTC+0000
..... 0x8225bda0:IEXPLORE.EXE                         380   1776     22    385 2016-12-06 05:27:19 UTC+0000
...... 0x8229f7e8:IEXPLORE.EXE                       1080    380     19    397 2016-12-06 05:27:21 UTC+0000
.... 0x81e4f560:svchost.exe                          1704    672      5    107 2016-12-06 05:27:10 UTC+0000
... 0x81f8c9a0:lsass.exe                              684    628     26    374 2016-12-06 05:27:07 UTC+0000
.. 0x81ef6da0:csrss.exe                               604    540     11    480 2016-12-06 05:27:07 UTC+0000
 0x81e886f0:GoogleUpdate.ex                           372   1984      7    138 2016-12-06 05:27:13 UTC+0000
```

We see a IEXPLORE.EXE. Why don't check its history ?

```
➜ volatility -f forensic_100.raw --profile=WinXPSP2x86 iehistory
Volatility Foundation Volatility Framework 2.5
**************************************************
Process: 1080 IEXPLORE.EXE
Cache type "DEST" at 0x201ca83
Last modified: 2016-12-06 14:28:40 UTC+0000
Last accessed: 2016-12-06 05:28:42 UTC+0000
URL: SYSTEM@http://crattack.tistory.com/entry/Data-Science-import-pandas-as-pd
Title: Security &amp; Reverse :: [Data Science] Pandas - \),
```

If we visit this URL without matching the IP adress in the host file, we are on a CTF site. There is no flag on this site...

But, if we match the IP adress with the URL, we have a file to download, and this file hold the flag :-)

Flag : SECCON{_h3110_w3_h4ve_fun_w4rg4m3_}

**Note**: We could retrieve the IP adress with the connscan plugin, but it was impossible to determine that the crattack.tistory.com site was associated with this IP adress.
