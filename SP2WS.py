import win32pipe, win32file
import time, datetime
import struct
import serial
import sys

class sp2ws_serial():
    def __init__(self, port, baudrate):
        self.port = port
        self.baudrate = baudrate

    def open(self):
        self.ser = serial.Serial(self.port, self.baudrate, timeout = 0.5)

    def close(self):
        self.ser.close()
    
    def read(self, length):
        return self.ser.read(length)

    def write(self, buff):
        self.ser.write(buff)

class sp2ws_pipe():
    def __init__(self, pipe_name):
        self.magic_num = 0xa1b2c3d4
        self.major_ver = 0x02
        self.minor_ver = 0x04
        self.link_type = 1# 802.11: 105
        self.pipe_name = pipe_name

    
    def create_pipe(self):
        self.pipe = win32pipe.CreateNamedPipe(
                    self.pipe_name,
                    win32pipe.PIPE_ACCESS_OUTBOUND,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
                    1, 65536, 65536,
                    300,
                    None)
    
    def connect_pipe(self):
        '''
        struct pcap_file_header
        {
            uint32_t magic_number;  /* magic number */
            uint16_t version_major; /* major version number */
            uint16_t version_minor; /* minor version number */
            int32_t  thiszone;      /* GMT to local correction */
            uint32_t sigfigs;       /* accuracy of timestamps */
            uint32_t snaplen;       /* max length of captured packets, in octets */
            uint32_t linktype;      /* data link type */
        }
        '''
        win32pipe.ConnectNamedPipe(self.pipe, None)
        global_header = struct.pack('IHHiIII',
            self.magic_num,     # magic number 4
            self.major_ver,     # major version number 2
            self.minor_ver,     # minor version number 2
            0,                  # GMT to local correction 4
            0,                  # accuracy of timestamps 4
            0,                  # max length of captured packets, in octets 4
            self.link_type      # data link type 4
        )
        win32file.WriteFile(self.pipe, global_header)

    def write_pipe(self, packet):
        packet_len = len(packet)
        if packet_len <= 0:
            return

        '''
        struct pcaprec_hdr {
            uint32_t ts_sec;        /* timestamp seconds */
            uint32_t ts_usec;       /* timestamp microseconds (nsecs for PCAP_NSEC_MAGIC) */
            uint32_t incl_len;      /* number of octets of packet saved in file*/
            uint32_t orig_len;      /* actual length of packet */
        };
        '''
        packet_header = struct.pack('IIII',
            int(time.time()),                       # timestamp seconds
            datetime.datetime.now().microsecond,    # timestamp microseconds
            packet_len,                             # number of octets of packet
            packet_len                              # actual length of packet
        )
        
        win32file.WriteFile(self.pipe, packet_header)
        win32file.WriteFile(self.pipe, packet)

def hex_dump(buff):
    result = []
    digits = 2 if isinstance(buff, str) else 4
    for i in range(0, len(buff), 16):
        s = buff[i:i+16]
        hexa = ' '.join(['%0*X' % (digits, ord(x)) for x in s])
        text = ''.join([x if 0x20 <= ord(x) < 0x7F else '.' for x in s])
        result.append('%06X  %-*s   %s' % (i, 16*(digits + 1), hexa, text))
    for i in result:
        print(i)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("SP2WS.py com[port_num] wifi_master [ssid] [pwd]")
        print("SP2WS.py com[port_num] wifi_slave")
        print(r'\\.\pipe\wifi_master')
        print(r'\\.\pipe\wifi_slave')

    
    port = sys.argv[1].upper()
    if sys.argv[2].find("wifi_master") > -1:
        ssid = sys.argv[3]
        password = sys.argv[4]
        wifi_connect = r'wifi join ' + ssid + ' ' + password
    pipe_name = r'\\.\pipe' + '\\' + sys.argv[2]

    # create serial object
    sp2ws_serial = sp2ws_serial(port, 115200)
    sp2ws_serial.open()

    sp2ws_pipe = sp2ws_pipe(pipe_name)
    sp2ws_pipe.create_pipe()
    print("start connect pipi...")
    sp2ws_pipe.connect_pipe()
    print("pipe connect success!!!")

    raw_buf = bytearray()
    start = 0
    init = 0

    if sys.argv[2].find("wifi_master") > -1:
        sp2ws_serial.write(bytes(wifi_connect + "\r\n", encoding='utf-8'))
    
    sp2ws_serial.write(bytes("pipe_start\r\n", encoding='utf-8'))

    while True:
        raw = sp2ws_serial.read(1024)
        raw_len = len(raw)

        if raw_len > 0:
            raw_buf = raw_buf + raw

            while True:
                raw_len = len(raw_buf)
                # find packet header
                for index in range(raw_len):
                    if (index + 2) < (raw_len - 1):
                        if raw_buf[index] == 114 and raw_buf[index + 1] == 116 and raw_buf[index + 2] == 116:
                            start = index + 3
                            break
                        start = 0
                    else:
                        start = 0
                        break

                if start == 0:
                    break
                
                # find packet tail
                for index in range(start, raw_len):
                    if (index + 2) < (raw_len - 1):
                        if raw_buf[index] == 101 and raw_buf[index + 1] == 110 and raw_buf[index + 2] == 100:
                            end = index
                            break
                        end = 0
                    else:
                        end = 0
                        break

                if end == 0:
                    break

                frame = raw_buf[start : end]
                sp2ws_pipe.write_pipe(frame)

                end += 3
                raw_buf = raw_buf[end : ]

