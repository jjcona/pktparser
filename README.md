# pktparser


pktparser.py is an interactive shell used for parsing through pcaps. As configured the intention is to assist with finding IOCs in pcaps, but I plan on adding more functionality that might be useful for pentesters. 

## Examples: 

    python pktparser.py 
    
               /$$         /$$                                                                
              | $$        | $$                                                                
      /$$$$$$ | $$   /$$ /$$$$$$    /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$ 
     /$$__  $$| $$  /$$/|_  $$_/   /$$__  $$ |____  $$ /$$__  $$ /$$_____/ /$$__  $$ /$$__  $$
    | $$  \ $$| $$$$$$/   | $$    | $$  \ $$  /$$$$$$$| $$  \__/|  $$$$$$ | $$$$$$$$| $$  \__/
    | $$  | $$| $$_  $$   | $$ /$$| $$  | $$ /$$__  $$| $$       \____  $$| $$_____/| $$      
    | $$$$$$$/| $$ \  $$  |  $$$$/| $$$$$$$/|  $$$$$$$| $$       /$$$$$$$/|  $$$$$$$| $$      
    | $$____/ |__/  \__/   \___/  | $$____/  \_______/|__/      |_______/  \_______/|__/      
    | $$                          | $$                                                        
    | $$                          | $$                                                        
    |__/                          |__/                                                        
     
    Command line tool for pulling interesting info out of pcaps.
    Start by pointing pktparser to a pcap file with 'load file_name.pcap'
    
        pktparser>>> load 20170815.pcap
        <bound method PacketList.summary of <hidden_captured-intelligence.pcap: TCP:817 UDP:225 ICMP:0 Other:28>>
        pktparser>>> dnsunique
        Extracting unique dns queries now....
        wpad.localdomain.
        webchat.freenode.net.
        131.134.168.192.in-addr.arpa.
        bantha.deathstar.empire.localdomain.
        pktparser>>> 
    
    
    Type 'help' for a list of commands. 
    
    pktparser>>>

## Get help: 

    pktparser>>> help
    
    Documented commands (type help <topic>):
    ========================================
    EOF        exit  httpget   pkthex      pktsumm   stateful
    dnsall     help  httppost  pktpayload  printall  uaall   
    dnsunique  hist  load      pktshow     shell     uaunique



## Interact with the OS:

    pktparser>>> shell ls | grep pcap
    pcaphistogram.pl
    pcaphistogram.pl.txt
    tcp23.pcap
    tcp4444.pcap
    tcp8000.pcap
    tcp80.pcap


## Load a pcap: 

    pktparser>>> load tcp80.pcap
    <bound method PacketList.summary of <tcp80.pcap: TCP:6873 UDP:0 ICMP:0 Other:0>>

## Summary of stateful connections in the pcap: 

    pktparser>>> stateful
    The total stateful connections in this pcap is 353

## Print all packets. 
## Comma separate where first field is packet number, second is packet details: 

    pktparser>>> printall
    0,Ether / IP / TCP 10.0.0.35:41238 > 178.255.83.1:http S
    1,Ether / IP / TCP 178.255.83.1:http > 10.0.0.35:41238 SA
    2,Ether / IP / TCP 10.0.0.35:41238 > 178.255.83.1:http A
    3,Ether / IP / TCP 10.0.0.35:41238 > 178.255.83.1:http PA / Raw
    4,Ether / IP / TCP 178.255.83.1:http > 10.0.0.35:41238 A
 
## Packet details in hex, by number: 

    pktparser>>> pkthex 3
    0000   E0 3F 49 9F 18 A8 00 0C  29 E0 CF E8 08 00 45 00   .?I.....).....E.
    0010   01 F5 2C F5 40 00 40 06  FB EA 0A 00 00 23 B2 FF   ..,.@.@......#..
    0020   53 01 A1 16 00 50 8D BF  AE 13 A2 08 76 E7 80 18   S....P......v...
    0030   00 E5 12 0B 00 00 01 01  08 0A 0A 67 82 E8 12 F1   ...........g....
    0040   22 80 50 4F 53 54 20 2F  20 48 54 54 50 2F 31 2E   ".POST / HTTP/1.
    0050   31 0D 0A 48 6F 73 74 3A  20 6F 63 73 70 2E 63 6F   1..Host: ocsp.co
    0060   6D 6F 64 6F 63 61 2E 63  6F 6D 0D 0A 55 73 65 72   modoca.com..User
    0070   2D 41 67 65 6E 74 3A 20  4D 6F 7A 69 6C 6C 61 2F   -Agent: Mozilla/
    0080   35 2E 30 20 28 58 31 31  3B 20 4C 69 6E 75 78 20   5.0 (X11; Linux 
    0090   78 38 36 5F 36 34 3B 20  72 76 3A 34 33 2E 30 29   x86_64; rv:43.0)

    
## All UserAgents in the pcap, 
## Comma separated as packet sequence number, timestamp, UA, Destination IP: 

    pktparser>>> uaall
    3,1485402924.85,User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0 Iceweasel/43.0.4,178.255.83.1
    14,1485402926.32,User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0 Iceweasel/43.0.4,151.101.0.73
    34,1485402926.41,User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0 Iceweasel/43.0.4,151.101.0.73
    53,1485402926.42,User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0 Iceweasel/43.0.4,151.101.0.73
    56,1485402926.43,User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0 Iceweasel/43.0.4,151.101.0.73
    121,1485402926.52,User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0 Iceweasel/43.0.4,23.207.174.1

## Detailed packet info, scapy style:

    pktparser>>> pktshow 3
    ###[ Ethernet ]### 
      dst       = e0:3f:49:9f:18:a8
      src       = 00:0c:29:e0:cf:e8
      type      = 0x800
    ###[ IP ]### 
         version   = 4L
         ihl       = 5L
         tos       = 0x0
         len       = 501
         id        = 11509
         flags     = DF
         frag      = 0L
         ttl       = 64
         proto     = tcp
         chksum    = 0xfbea
         src       = 10.0.0.35
         dst       = 178.255.83.1
         \options   \
    ###[ TCP ]### 
            sport     = 41238
            dport     = http


## Unique UserAgents in the pcap: 

    pktparser>>> uaunique
    Vary: Accept-Encoding, User-Agent
    Vary: User-Agent
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0 Iceweasel/43.0.4


## Http get requests: 

    pktparser>>> httpget
    ############################################
    # Packet Number:
    ############################################
    14
    ############################################
    # Packet Summary:
    ############################################
    Ether / IP / TCP 10.0.0.35:44440 > 151.101.0.73:http PA / Raw
    ############################################
    # HTTP GET Header:
    ############################################
    GET / HTTP/1.1
    Host: www.cnn.com
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0 Iceweasel/43.0.4
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Connection: keep-alive



## Http post requests: 

    pktparser>>> httppost
    ############################################
    # Packet Number:
    ############################################
    2064
    ############################################
    # Packet Summary:
    ############################################
    Ether / IP / TCP 10.0.0.35:44204 > 72.21.91.29:http PA / Raw
    ############################################
    # HTTP POST Header:
    ############################################
    POST / HTTP/1.1
    Host: ocsp.digicert.com
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0 Iceweasel/43.0.4
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Content-Length: 83
    Content-Type: application/ocsp-request
    Connection: keep-alive

## Dns queries: 

    pktparser>>> load dns.pcap
    <bound method PacketList.summary of <dns.pcap: TCP:0 UDP:24 ICMP:0 Other:0>>
    pktparser>>> dnsall
    Extracting all dns queries now....
    0,1520030491.24,www.google.com.
    1,1520030492.24,www.google.com.
    2,1520030493.25,www.google.com.
    4,1520030493.28,www.google.com.
    5,1520030494.29,www.google.com.
    6,1520030495.29,www.google.com.
    8,1520030495.31,www.google.com.
    9,1520030496.32,www.google.com.
    10,1520030497.32,www.google.com.
    12,1520030503.06,evil.website.com.
    13,1520030504.06,evil.website.com.
    14,1520030505.06,evil.website.com.
    16,1520030505.21,evil.website.com.
    17,1520030506.21,evil.website.com.
    18,1520030507.21,evil.website.com.


## Unique dns queries: 

    pktparser>>> dnsunique
    Extracting unique dns queries now....
    www.google.com.
    evil.website.com.



