from packet_struct import *
import sys

def checkBigEndian(magicNum):

    if(magicNum == b"\xd4\xc3\xb2\xa1"):
        return "<"

    if(magicNum == b"\xa1\xb2\xc3\xd4"):
        return ">"

    return None

def configureIPv4PacketData(newPacket, endian):
    return newPacket

def configureTCPPacketData(newPacket, endian):
    return newPacket


def main():

    # require a valid input
    if len(sys.argv) < 2:
        print("Error: Too few arguements provided, please provide a .cap file")
        return
    if len(sys.argv) > 2:
        print("Error: Too many arguements provided, please provide only a .cap file")
        return

    globalHeaderStatus = True

    # open and read the .cap file
    with open(sys.argv[1], "rb") as file:
        globalHeader = file.read(24) # first 24 bytes contain the global header
        
        if len(globalHeader) != 24:
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

            if len(packetHeader) == 0:
                break

            if len(packetHeader) != 16:
                print("Error: Packet header is wrong length")
                break

            
            tsSec = (struct.unpack(endian + "I", packetHeader[0:4]))[0]
            tsUsec = (struct.unpack(endian + "I", packetHeader[4:8]))[0]
            inclLen = (struct.unpack(endian + "I", packetHeader[8:12]))[0]
            origLen = (struct.unpack(endian + "I", packetHeader[12:16]))[0]
            
            packetData = file.read(inclLen)

            if len(packetData) != inclLen:
                print("Error: Packet data length does not match")
                break

            # Calculate the absolute timestamp.
            absoluteTime = tsSec + tsUsec / 1000000

            if origTime is None:
                origTime = absoluteTime

            numberOfPackets+=1

            newPacket = packet()
            newPacket.timestamp_set(packetHeader[0:4], packetHeader[4:8], origTime)
            newPacket.packet_No_set(numberOfPackets)
            newPacket.buffer = packetData

            newPacket = configureIPv4PacketData(newPacket, endian)
            newPacket = configureTCPPacketData(newPacket, endian)


            packets.append(newPacket)

            # print(
            #     f"Packet {numberOfPackets}: "
            #     f"time={tsSec}.{tsUsec:06d}, "
            #     f"included={inclLen}, "
            #     f"original={origLen}"
            # )

    print("Total packets:", len(packets))


            

main()