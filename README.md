# Packet-Size Side Channel Attack

***port_infer_demo.py*** demonstrates two cases of guessing the wrong port and guessing the right port;

***evict_seq_ack.py*** realizes the interception of the ACK packet sent from the server to the victim, and obtains the sequence number and acknowledgment number.

> Note: The parameters of the relevant equipment in the code need to be modified;

In the attack, packet capture tools such as wireshark/tcpdump are need to be used for simultaneous analysis.
