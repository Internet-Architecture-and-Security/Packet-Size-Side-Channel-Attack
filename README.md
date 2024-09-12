# Packet-Size Side Channel Attack

This is a C++ program that infers and hijacks the victim's TCP connection based on the Wi-Fi frame size.

## Citations

If you use any derivative of the code or datasets from our work, please cite our publicaiton:

```
@article{wang2024off,
  title={Off-Path TCP Hijacking in Wi-Fi Networks: A Packet-Size Side Channel Attack},
  author={Wang Ziqiang and Feng Xuewei and Li Qi and Sun Kun and Yang Yuxiang and Li Mengyuan and Du Ganqiu and Xu Ke and Wu Jianping},
  booktitle={Proceedings of the 2025 Network and Distributed System Security (NDSS) Symposium},
  year={2025}
}
```

## Get Started


Dependent library: [libtins](https://libtins.github.io/), `C++11 Compiler`

Before running this script, you need to set the wireless card to monitor mode using something like Aircrack-ng (https://www.aircrack-ng.org/), and then modify the configuration parameters section in main.py to set the attack parameters.
i.e., client_mac, client_ip, server_ip, server_port, send_if_name and sniff_if_name.

Note: You need to set the wireless card to the channel used by the victim to capture the victim's Wi-Fi frames.
e.g., iwconfig wlan1_monitor channel 6

Compile and run the project to infer the victim's TCP connection.

```bash
g++ main.cpp PortFinder.cpp SeqFinder.cpp AckFinder.cpp 

Attack.cpp -o main -litins

sudo ./main
```