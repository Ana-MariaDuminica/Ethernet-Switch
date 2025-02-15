#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def read_vlan_config(switch_id):
    vlan_config = {}
    filename = f'configs/switch{switch_id}.cfg'  # numele fisierului de configurare
    
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
            for line in lines[1:]:  # prima linie este prioritatea switch-ului
                parts = line.strip().split()
                interface_name = parts[0] # extrage numele interfetei
                vlan = parts[1] # extrage vlan id-ul
                vlan_config[interface_name] = 'T' if vlan == 'T' else int(vlan)
    except FileNotFoundError:
        print(f"[ERROR] Config file {filename} not found.")
        sys.exit(1)
    
    # returneaza dictionarul de configurare vlan
    return vlan_config

def is_unicast(mac_str):
    # converteste adresa MAC din string in bytes
    mac_bytes = bytes(int(b, 16) for b in mac_str.split(":"))
    
    # verifica daca least significant bit din primul byte este 0 (unicast)
    return (mac_bytes[0] & 1) == 0

def create_bpdu_packet(root_bridge_id, path_cost, sender_bridge_id):
    bpdu_packet = struct.pack(
        '!B8sI8sHHHHH',
        0, # flags
        root_bridge_id.to_bytes(8, 'big'),
        path_cost,
        sender_bridge_id.to_bytes(8, 'big'),
        0, # port id
        0,  # message_age3
        0,  # max_age
        0,  # hello_time
        0  # forward_delay
    )

    llc_header = struct.pack('!BBB', 0x42, 0x42, 0x03)

    full_packet = struct.pack(
        '!6s6sH',
        b'\x01\x80\xc2\x00\x00\x00',  # dst_mac
        b'\x00' * 6,                  # src_mac
        b'\x00' * 2                          # llc_length
        ) + b'\x00' * 3 + b'\x00' * 4 + bpdu_packet  # packet (31 bytes)

    return full_packet

def send_bpdu_every_sec(interfaces):
    while True:
        # daca switch-ul este root
        if own_bridge_ID == root_bridge_ID:

            sender_bridge_ID = own_bridge_ID
            sender_path_cost = 0
            
            for i in interfaces:
                # trimitem bpdu packet pe toate porturile trunk
                interface_name = get_interface_name(i)
                interface_vlan = vlan_config.get(interface_name)

                if interface_vlan == 'T':

                    # cream bpdu packet
                    bpdu_packet = create_bpdu_packet(
                        root_bridge_ID,
                        sender_path_cost,
                        sender_bridge_ID,
                    )
                    send_to_link(i, len(bpdu_packet), bpdu_packet)
        time.sleep(1)

def initialize_stp(stp_state, interfaces):
    global root_bridge_ID, own_bridge_ID, root_path_cost, root_path_cost

    # punem pe blocking porturile trunk pentru ca doar acolo pot
    # aparea bucle
    for i in interfaces:
        interface_name = get_interface_name(i)
        interface_vlan = vlan_config.get(interface_name)

        if interface_vlan == 'T':
            stp_state[i]  = 'BLOCKING'

    own_bridge_ID = int(open(f"configs/switch{sys.argv[1]}.cfg").readline().strip())
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0

    # daca portul devine root bridge setam porturile ca designated
    if own_bridge_ID == root_bridge_ID:
        for i in interfaces:
            stp_state[i] = 'DESIGNATED_PORT'

def receiving_bpdu(bpdu_data, interface, stp_state, interfaces):
    global root_bridge_ID, root_path_cost, root_port
    
    bpdu_parsed = struct.unpack('!B8sI8sHHHHH', bpdu_data[21:52])

    # extragem campurile relevante din bpdu packet
    bpdu_root_bridge_ID = int.from_bytes(bpdu_parsed[1], 'big')
    bpdu_sender_path_cost = bpdu_parsed[2]  # path cost
    bpdu_sender_bridge_ID = int.from_bytes(bpdu_parsed[3], 'big')
    
    # caz 1
    if bpdu_root_bridge_ID < root_bridge_ID:
        root_bridge_ID = bpdu_root_bridge_ID
        #adaugam 10 la cost
        root_path_cost = bpdu_sender_path_cost + 10

        # interfata unde BPDU a fost primit
        root_port = interface

        # setam toate porturile pe BLOCKING
        if root_bridge_ID == own_bridge_ID:
            for port in interfaces:
                stp_state[port] = 'BLOCKING'

        # daca root port este BLOCKING
        if stp_state[root_port] == 'BLOCKING':
            stp_state[root_port] = 'LISTENING'

        # actualizam si trimitem BPDU la toate porturile trunk
        sender_bridge_ID = own_bridge_ID
        sender_path_cost = root_path_cost

        for i in interfaces:
            interface_name = get_interface_name(i)
            interface_vlan = vlan_config.get(interface_name)

            if interface_vlan == 'T':

                # construim bpdu packet
                bpdu_packet = create_bpdu_packet(
                    root_bridge_ID,
                    sender_path_cost,
                    sender_bridge_ID,
                )
                send_to_link(i, len(bpdu_packet), bpdu_packet)

    # caz 2
    elif bpdu_root_bridge_ID == root_bridge_ID:
        # verificam daca bpdu a venit prin root port si costul recalculat este mai mic
        if interface == root_port and bpdu_sender_path_cost + 10 < root_path_cost:
            root_path_cost = bpdu_sender_path_cost + 10
        
        elif interface != root_port:
            # bpdu nu a venit prin root port
            if bpdu_sender_path_cost > root_path_cost:
                if stp_state[interface] != 'DESIGNATED_PORT':
                    stp_state[interface] = 'LISTENING'

    # caz 3
    elif bpdu_sender_bridge_ID == own_bridge_ID:
        # switch-ul a detectat un bpdu packet trimis de el insusi
        # inseamna ca exista bucle
        stp_state[interface] = 'BLOCKING'

    else:
        # discard BPDU
        print("[INFO] BPDU discarded")

    if own_bridge_ID == root_bridge_ID:
        for i in interfaces:
            stp_state[i] = 'DESIGNATED_PORT'
        


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    global vlan_config
    vlan_config = read_vlan_config(switch_id)

    num_interfaces = wrapper.init(sys.argv[2:])

    interfaces = range(0, num_interfaces)

    # starea porturilor
    stp_state = {}

    # initializam stp
    initialize_stp(stp_state, interfaces)
    global root_bridge_ID, own_bridge_ID, root_path_cost

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BPDU
    t = threading.Thread(target=send_bpdu_every_sec, args=(interfaces))
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    # MAC table
    mac_table = {}

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        if dest_mac == b'\x01\x80\xc2\x00\x00\x00':
            # Procesare cadru BPDU
            receiving_bpdu(data, interface, stp_state, interfaces)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        interface_name = get_interface_name(interface)
        interface_vlan = vlan_config.get(interface_name)

        # foloseste vlan-ul din tag, daca exista, altfel deduce din configuratia portului
        vlan_id_efectiv = vlan_id if vlan_id != -1 else interface_vlan
        mac_table[src_mac] = interface

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # TODO: Implement forwarding with learning
        # TODO: Implement VLAN support
        # TODO: Implement STP support

        # adresa MAC este unicast
        if is_unicast(dest_mac):
            # Destinatia este cunoscuta in tabela MAC
            if (dest_mac) in mac_table:
                # gasim vlan id-ul interfetei destinatie
                dest_interface = mac_table[dest_mac]
                target_name = get_interface_name(dest_interface)
                target_vlan = vlan_config.get(target_name)
        
                if dest_interface != interface:
                    if target_vlan == 'T':
                        # trimite pe un port trunk - adauga tag VLAN
                        tagged_frame = data[0:12] + create_vlan_tag(vlan_id_efectiv) + data[12:]
                        send_to_link(dest_interface, len(tagged_frame), tagged_frame)
                
                    elif target_vlan == vlan_id_efectiv:
                        # trimite pe un port access - trimite fara tag VLAN
                        if vlan_id != -1:
                            # trimite de pe un port trunk si scoate tag VLAN
                            untagged_frame = data[0:12] + data[16:]
                        else:
                            #trimite de pe un port access
                            untagged_frame = data
                        send_to_link(dest_interface, len(untagged_frame), untagged_frame)

            # Destinatia nu este cunoscuta in tabela MAC
            else:
                for i in range(num_interfaces):
                    # trimitem pe toate porturile mai putin pe cel de pe care vine
                    if i != interface and stp_state[i] != 'BLOCKING':
                        # gasim vlan id-ul interfetei destinatie
                        target_name = get_interface_name(i)
                        target_vlan = vlan_config.get(target_name)

                        if target_vlan == 'T':
                            # trimite pe un port trunk - adauga tag VLAN
                            tagged_frame = data[0:12] + create_vlan_tag(vlan_id_efectiv) + data[12:]
                            send_to_link(i, len(tagged_frame), tagged_frame)
                        elif target_vlan == vlan_id_efectiv:
                            # trimite pe un port access - trimite fara tag VLAN
                            if vlan_id != -1:
                                # trimite de pe un port trunk si scoate tag VLAN
                                untagged_frame = data[0:12] + data[16:]
                            else:
                                #trimite de pe un port access
                                untagged_frame = data
                            send_to_link(i, len(untagged_frame), untagged_frame)

        # adresa MAC este broadcast
        else:
            for i in range(num_interfaces):
                if i != interface and stp_state[i] != 'BLOCKING':
                    target_name = get_interface_name(i)
                    target_vlan = vlan_config.get(target_name)

                    if target_vlan == 'T':
                        # Port trunk - adauga tag VLAN daca nu exista
                        tagged_frame = data[0:12] + create_vlan_tag(vlan_id_efectiv) + data[12:]
                        send_to_link(i, len(tagged_frame), tagged_frame)
                    elif target_vlan == vlan_id_efectiv:
                        # trimite pe un port access - trimite fara tag VLAN
                        if vlan_id != -1:
                            # trimite de pe un port trunk si scoate tag VLAN
                            untagged_frame = data[0:12] + data[16:]
                        else:
                            #trimite de pe un port access
                            untagged_frame = data
                        send_to_link(i, len(untagged_frame), untagged_frame)

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()
