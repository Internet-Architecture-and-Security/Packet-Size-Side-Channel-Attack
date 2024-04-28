# Packet-Size Side Channel Attack

## Citations

```
@article{wang2024off,
  title={Off-Path TCP Hijacking in Wi-Fi Networks: A Packet-Size Side Channel Attack},
  author={Wang, Ziqiang and Feng, Xuewei and Li, Qi and Sun, Kun and Yang, Yuxiang and Li, Mengyuan and Xu, Ke},
  journal={arXiv preprint arXiv:2402.12716},
  year={2024}
}
```

## Get Started

***port_infer_demo.py*** demonstrates two cases of guessing the wrong port and guessing the right port;

***evict_seq_ack.py*** realizes the interception of the ACK packet sent from the server to the victim, and obtains the sequence number and acknowledgment number.

> Note: The parameters of the relevant equipment in the code need to be modified;

In the attack, packet capture tools such as wireshark/tcpdump are need to be used for simultaneous analysis.
