gcc `libnet-config --cflags --defines` Kaminsky_pacgen.c -o Kaminsky `libnet-config --libs`

./Kaminsky #-p payload/payload_binary -t headers/tcp_udp_header -i headers/ip_header -e headers/eth_header

