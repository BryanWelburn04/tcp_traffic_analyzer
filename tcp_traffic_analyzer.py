from packet_struct import *
import sys

def checkBigEndian(magicNum):

    if(magicNum == b"\xd4\xc3\xb2\xa1"):
        return "<"

    if(magicNum == b"\xa1\xb2\xc3\xd4"):
        return ">"

    return None

def configureIPv4PacketData(newPacket, endian):

    # ipStartOffset = 14

    # # Probably a better way to extract the number of header bytes but if it ain't broke don't fix it
    # IHLFirstByte = (struct.unpack(endian + "B", newPacket.buffer[ipStartOffset+0:ipStartOffset+1]))[0]
    # IHL = IHLFirstByte & 0x0F # bitmask out the lower bytes
    # headerBytes = IHL*4

    # # H represents a unsigned short
    # totalLength = (struct.unpack(endian + "H", newPacket.buffer[ipStartOffset+2:ipStartOffset+4]))[0]
    # totalLengthBytes = totalLength*4

    ipStartOffset = 14

    newPacket.IP_header.get_header_len(newPacket.buffer[ipStartOffset+0:ipStartOffset+1])
    newPacket.IP_header.get_total_len(newPacket.buffer[ipStartOffset+2:ipStartOffset+4])
    newPacket.IP_header.get_IP(newPacket.buffer[ipStartOffset + 12:ipStartOffset + 16], newPacket.buffer[ipStartOffset + 16:ipStartOffset + 20]) # Given tutorial code get_IP function seems to be a set function?

    if(newPacket.IP_header.ip_header_len < 20):
        print("Error: IPv4 header length too small")
        return None
    if(newPacket.IP_header.ip_header_len > 60):
        print("Error: IPv4 header length too large")
        return None
    
    return newPacket

def configureTCPPacketData(newPacket, endian):
    # ethernetHeaderLength = 14
    # ipHeaderLength = newPacket.IP_header.ip_header_len
    # tcpStartOffset = ethernetHeaderLength + ipHeaderLength

    # # TODO add some check for header length
    # srcPort = (struct.unpack(endian + "H", newPacket.buffer[tcpStartOffset+0:tcpStartOffset+2]))[0]
    # dstPort = (struct.unpack(endian + "H", newPacket.buffer[tcpStartOffset+2:tcpStartOffset+4]))[0]

    # seqNumber = (struct.unpack(endian + "I", newPacket.buffer[tcpStartOffset+4:tcpStartOffset+8]))[0]
    # ackNumber = (struct.unpack(endian + "I", newPacket.buffer[tcpStartOffset+8:tcpStartOffset+12]))[0]

    # dataOffsetByte = (struct.unpack(endian + "B", newPacket.buffer[tcpStartOffset+12:tcpStartOffset+13]))[0]
    # dataOffset = dataOffsetByte & 0xF0

    # allFlagsByte = (struct.unpack(endian + "B", newPacket.buffer[tcpStartOffset+13:tcpStartOffset+14]))[0]
    # # cwrFlag = allFlagsByte & 0x80 # 1000 0000 -> 0x80
    # # eceFlag = allFlagsByte & 0x40 # 0100 0000 -> 0x40
    # # urgFlag = allFlagsByte & 0x20 # 0010 0000 -> 0x20
    # ackFlag = allFlagsByte & 0x10 # 0001 0000 -> 0x10
    # # pshFlag = allFlagsByte & 0x08 # 0000 1000 -> 0x08
    # rstFlag = allFlagsByte & 0x04 # 0000 0100 -> 0x04
    # synFlag = allFlagsByte & 0x02 # 0000 0010 -> 0x02
    # finFlag = allFlagsByte & 0x01 # 0000 0001 -> 0x01

    # windowSize = (struct.unpack(endian + "H", newPacket.buffer[tcpStartOffset+14:tcpStartOffset+16]))[0]
    # checkSum = (struct.unpack(endian + "H", newPacket.buffer[tcpStartOffset+16:tcpStartOffset+18]))[0]
    # urgentPointer = (struct.unpack(endian + "H", newPacket.buffer[tcpStartOffset+18:tcpStartOffset+20]))[0]

    # newPacket.TCP_header.src_port_set(srcPort)
    # newPacket.TCP_header.dst_port_set(dstPort)
    # newPacket.TCP_header.seq_num_set(seqNumber)
    # newPacket.TCP_header.ack_num_set(ackNumber)
    # newPacket.TCP_header.data_offset_set(dataOffset)
    # newPacket.TCP_header.flags_set(ackFlag, rstFlag, synFlag, finFlag)
    # newPacket.TCP_header.win_size_set(windowSize)
    # newPacket.TCP_header.checksum = checkSum
    # newPacket.TCP_header.ugp = urgentPointer

    ethernetHeaderLength = 14
    ipHeaderLength = newPacket.IP_header.ip_header_len
    tcpStartOffset = ethernetHeaderLength + ipHeaderLength

    newPacket.TCP_header.get_src_port(newPacket.buffer[tcpStartOffset+0:tcpStartOffset+2])
    newPacket.TCP_header.get_dst_port(newPacket.buffer[tcpStartOffset+2:tcpStartOffset+4])
    newPacket.TCP_header.get_seq_num(newPacket.buffer[tcpStartOffset+4:tcpStartOffset+8])
    newPacket.TCP_header.get_ack_num(newPacket.buffer[tcpStartOffset+8:tcpStartOffset+12])
    newPacket.TCP_header.get_flags(newPacket.buffer[tcpStartOffset+13:tcpStartOffset+14])
    newPacket.TCP_header.get_window_size(newPacket.buffer[tcpStartOffset+14:tcpStartOffset+16])
    newPacket.TCP_header.get_data_offset(newPacket.buffer[tcpStartOffset+12:tcpStartOffset+13])

    return newPacket


def main():

    # require a valid input
    if(len(sys.argv) < 2):
        print("Error: Too few arguements provided, please provide a .cap file")
        return
    if(len(sys.argv) > 2):
        print("Error: Too many arguements provided, please provide only a .cap file")
        return

    globalHeaderStatus = True

    # open and read the .cap file
    with open(sys.argv[1], "rb") as file:
        globalHeader = file.read(24) # first 24 bytes contain the global header
        
        if(len(globalHeader) != 24):
            print("Error: Packet header is wrong length")
            globalHeaderStatus = False

        endian = checkBigEndian(globalHeader[:4])
        if(endian == None):
            print("Error: Neither big or little endian format found")
            globalHeaderStatus = False

        numberOfPackets = 0
        packets = []
        origTime = None

        while globalHeaderStatus:
            packetHeader = file.read(16)

            if(len(packetHeader) == 0):
                break

            if(len(packetHeader) != 16):
                print("Error: Packet header is wrong length")
                break

            
            tsSec = (struct.unpack(endian + "I", packetHeader[0:4]))[0]
            tsUsec = (struct.unpack(endian + "I", packetHeader[4:8]))[0]
            inclLen = (struct.unpack(endian + "I", packetHeader[8:12]))[0]
            origLen = (struct.unpack(endian + "I", packetHeader[12:16]))[0]
            
            packetData = file.read(inclLen)

            if(len(packetData) != inclLen):
                print("Error: Packet data length does not match")
                break

            # Calculate the absolute timestamp.
            absoluteTime = tsSec + tsUsec / 1000000

            if(origTime == None):
                origTime = absoluteTime

            numberOfPackets+=1

            newPacket = packet()
            newPacket.timestamp_set(packetHeader[0:4], packetHeader[4:8], origTime)
            newPacket.packet_No_set(numberOfPackets)
            newPacket.buffer = packetData

            newPacket = configureIPv4PacketData(newPacket, endian)
            if(newPacket == None):
                break
            newPacket = configureTCPPacketData(newPacket, endian)
            if(newPacket == None):
                break

            packets.append(newPacket)


    print("Total packets:", len(packets))

    for individualPacket in packets:
        print(individualPacket.packet_No, individualPacket.TCP_header.seq_num)


            

main()