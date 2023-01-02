import socket
from struct import *
import binascii


class Packet:
    def __init__(self, src_ip, dest_ip, dest_port):
        # https://docs.python.org/3.7/library/struct.html#format-characters
        # all values need to be at least one byte long (-> we need to add up some values)

        ############
        # IP segment
        self.version = 0x4
        self.ihl = 0x5
        self.type_of_service = 0x0
        self.total_length = 0x28
        self.identification = 0xabcd
        self.flags = 0x0
        self.fragment_offset = 0x0
        self.ttl = 0x40
        self.protocol = 0x1
        self.header_checksum = 0x0
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_addr = socket.inet_aton(src_ip)
        self.dest_addr = socket.inet_aton(dest_ip)
        self.v_ihl = (self.version << 4) + self.ihl
        self.f_fo = (self.flags << 13) + self.fragment_offset
       
        ########
        # ICMP segment
        self.type_of_message = 0x8  #8 for echo request , 0 for echo replay
        self.code = 0x0000
        self.icmp_checksum = 0x0000
        self.identifier = 0x1234
        self.icmp_seq_num = 0x0001

        ########
        # packet

        self.ip_header = b""
        self.icmp_header = b""
        self.icmp_packet = b""



    def calc_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i+1]
            s = s + w
        # s = 0x119cc
        s = (s >> 16) + (s & 0xffff)
        # s = 0x19cd
        s = ~s & 0xffff
        # s = 0xe632
        return s


    def generate_tmp_ip_header(self):
        tmp_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                          self.identification, self.f_fo,
                                          self.ttl, self.protocol, self.header_checksum,
                                          self.src_addr,
                                          self.dest_addr)
        return tmp_ip_header


    def generate_temp_icmp_header(self):
        #icmp + checksum
        temp_icmp_header = pack("!BBHHH", self.type_of_message, self.code, self.icmp_checksum,
                                    self.identifier,self.icmp_seq_num)

        return temp_icmp_header


    def generate_ping(self):
        final_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                                self.identification, self.f_fo,
                                                self.ttl, self.protocol, self.calc_checksum(self.generate_tmp_ip_header()),
                                                self.src_addr,
                                                self.dest_addr)
        final_icmp_header = pack("!BBHHH", self.type_of_message, self.code, self.calc_checksum(self.generate_temp_icmp_header()),
                                    self.identifier,self.icmp_seq_num)
        self.ip_header = final_ip_header
        self.icmp_header = final_icmp_header
        self.icmp_packet = final_ip_header + final_icmp_header


    def send_icmp_packet(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.sendto(self.icmp_packet,(self.dest_ip,0))
        data = s.recvfrom(1024)
        s.close()
        return data



# could work with e.g. struct.unpack() here
# however, lazy PoC (012 = [SYN ACK]), therefore:
def check_if_open(port, response):
    cont = binascii.hexlify(response)
    if cont[65:68] == b"012":
        print("Port "+str(port)+" is: open")
    else:
        print("Port "+str(port)+" is: closed")



p = Packet("192.168.1.14", "8.8.8.8",0)
p.generate_ping()
result= p.send_icmp_packet()
print(len(result))

if result:
    print("host is up")
else:
    print("host is not up")
