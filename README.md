# gfw_resist_tcp_proxy
knock up IP blockage

# goodbye IP filtering & goodbye GFW mf'er
<img src="/meme1.jpg?raw=true" width="300" >
<br><br>

# main Idea -> TCP violation:
- GFW need to check every packet agaist large list of filtered ip in order to drop them<br>
- since its not practical in huge traffic, they separate tcp handshake (SYN) and check them only.<br>
- in fact, they only drop SYN packet with blocked ip in both direction.
- so we can bypass ip filtering by building communication link without tcp handshake.<br><br>
<img src="/slide1.png?raw=true" width="500" >
<br><br>

# can GFW block tcp violation method?
- this method operate on lower layer of network (transport and ip layer)
- need lots of dedicated Hardware to fight with (not achievable in software)
- we use TCP ACK/PUSH packets which is 100000X more frequent than SYN
- they have large list of blocked ip that want to drop
- they cant hold & check every single packet in high speed traffic. (unless with a million dollar HW investment)

# how to run
- tcp violation need root/admin access to midify/send/sniff crafted packet
- we implement a prototype for proof-of-concept
- its not ready for production yet but we plan to build stable and standalone version in near future
