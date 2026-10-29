from packet_struct import *
import sys
import statistics

def checkBigEndian(magicNum):

    if(magicNum == b"\xd4\xc3\xb2\xa1"):
        return "<"

    if(magicNum == b"\xa1\xb2\xc3\xd4"):
        return ">"

    return None


def configureIPv4PacketData(newPacket, endian):

    ipStartOffset = 14
    isTCP = True

    newPacket.IP_header.get_header_len(newPacket.buffer[ipStartOffset+0:ipStartOffset+1])
    newPacket.IP_header.get_total_len(newPacket.buffer[ipStartOffset+2:ipStartOffset+4])
    newPacket.IP_header.get_IP(newPacket.buffer[ipStartOffset + 12:ipStartOffset + 16], newPacket.buffer[ipStartOffset + 16:ipStartOffset + 20]) # Given tutorial code get_IP function seems to be a set function?
    protocol = newPacket.buffer[ipStartOffset+9]

    if(protocol != 6):
        isTCP = False
    if(newPacket.IP_header.ip_header_len < 20):
        print("Error: IPv4 header length too small")
        return None
    if(newPacket.IP_header.ip_header_len > 60):
        print("Error: IPv4 header length too large")
        return None
    
    return newPacket, isTCP


def configureTCPPacketData(newPacket, endian):

    ethernetHeaderLength = 14
    ipHeaderLength = newPacket.IP_header.ip_header_len
    tcpStartOffset = ethernetHeaderLength + ipHeaderLength

    newPacket.TCP_header.get_src_port(newPacket.buffer[tcpStartOffset+0:tcpStartOffset+2])
    newPacket.TCP_header.get_dst_port(newPacket.buffer[tcpStartOffset+2:tcpStartOffset+4])
    newPacket.TCP_header.get_seq_num(newPacket.buffer[tcpStartOffset+4:tcpStartOffset+8])
    newPacket.TCP_header.get_ack_num(newPacket.buffer[tcpStartOffset+8:tcpStartOffset+12])
    newPacket.TCP_header.get_flags(newPacket.buffer[tcpStartOffset+13:tcpStartOffset+14])
    newPacket.TCP_header.get_window_size(newPacket.buffer[tcpStartOffset+14:tcpStartOffset+15], newPacket.buffer[tcpStartOffset+15:tcpStartOffset+16])
    newPacket.TCP_header.get_data_offset(newPacket.buffer[tcpStartOffset+12:tcpStartOffset+13])

    return newPacket



def groupPacketsByConnection(packets):
    connections = {}

    for individualPacket in packets:
        srcIP = individualPacket.IP_header.src_ip
        dstIP = individualPacket.IP_header.dst_ip

        srcPort = individualPacket.TCP_header.src_port
        dstPort = individualPacket.TCP_header.dst_port

        direction1 = (srcIP, srcPort)
        direction2 = (dstIP, dstPort)

        sortedBothDirections = tuple(sorted((direction1, direction2)))

        if sortedBothDirections not in connections:
            connections[sortedBothDirections] = []

        connections[sortedBothDirections].append(individualPacket)

    return connections


def getConnectionStatus(groupOfPackets):
    synCount = 0
    finCount = 0
    rCount = 0

    for packet in groupOfPackets:

        syn = packet.TCP_header.flags.get("SYN", 0)
        fin = packet.TCP_header.flags.get("FIN", 0)
        rst = packet.TCP_header.flags.get("RST", 0)

        if rst:
            rCount += 1

        if syn:
            synCount += 1

        if fin:
            finCount += 1


    return f"R{rCount}S{synCount}F{finCount}"

def getConnectionEndTime(groupOfPackets):
    endTime = 0
    for packet in groupOfPackets:
        packet.TCP_header.flags

        # Check whether this packet contains a FIN.
        if(packet.TCP_header.flags.get("FIN", 0)):
            endTime = packet.timestamp
    
    return endTime


def getNumberOfPacketsFromSource(groupOfPackets, sourcePort):
    numberOfPackets = 0
    for packet in groupOfPackets:
        if(packet.TCP_header.src_port == sourcePort):
            numberOfPackets += 1

    return numberOfPackets


def getNumberOfPacketsFromDestination(groupOfPackets, destinationPort):
    numberOfPackets = 0
    for packet in groupOfPackets:
        if(packet.TCP_header.src_port == destinationPort):
            numberOfPackets += 1

    return numberOfPackets


def getNumberOfBytesFromSource(groupOfPackets, sourcePort):
    numberOfBytes = 0
    for packet in groupOfPackets:
        if(packet.TCP_header.src_port == sourcePort):
            numberOfBytes += (packet.IP_header.total_len - packet.IP_header.ip_header_len - packet.TCP_header.data_offset)
            
    return numberOfBytes


def getNumberOfBytesFromDestination(groupOfPackets, destinationPort):
    numberOfBytes = 0
    for packet in groupOfPackets:
        if(packet.TCP_header.src_port == destinationPort):
            numberOfBytes += (packet.IP_header.total_len - packet.IP_header.ip_header_len - packet.TCP_header.data_offset)

    return numberOfBytes


def getCompleteConnections(groupedPackets):
    completeConnections = []
    for groupOfPackets in groupedPackets.values():
        status = getConnectionStatus(groupOfPackets)
        r, s, f = [int(char) for char in status if char.isdigit()]

        if(s>=1 and f>=1):
            completeConnections.append(groupOfPackets)

    return completeConnections


def getTotalNumberOfResetConnections(groupedPackets):
    numberOfResetConnections = 0
    for groupOfPackets in groupedPackets.values():
        status = getConnectionStatus(groupOfPackets)
        r, s, f = [int(char) for char in status if char.isdigit()]

        if(r>0):
            numberOfResetConnections+=1

    return numberOfResetConnections


def getTotalNumberOfOpenConnections(groupedPackets):
    numberOfOpenConnections = 0

    for groupOfPackets in groupedPackets.values():
        finOccurred = False

        for packet in groupOfPackets:
            packet.TCP_header.flags

            numberOfBytes = (packet.IP_header.total_len - packet.IP_header.ip_header_len - packet.TCP_header.data_offset)

            # Check whether this packet contains a FIN.
            if(packet.TCP_header.flags.get("FIN", 0)):
                finOccurred = True

            # Check for data in a packet after a FIN.
            elif(finOccurred and numberOfBytes > 0):
                numberOfOpenConnections += 1
                break

    return numberOfOpenConnections


def getTotalNumberOfBeforeCaptureConnections(groupedPackets):
    numberOfBeforeCaptureConnections = 0
    for groupOfPackets in groupedPackets.values():
        if groupOfPackets[0].TCP_header.flags.get("SYN", 0) < 1:
            numberOfBeforeCaptureConnections+=1

    return numberOfBeforeCaptureConnections


def durationStatistics(completeConnection):
    durations = []

    for groupOfPackets in completeConnection:
        endTime = 0
        for packet in groupOfPackets:
            packet.TCP_header.flags
    
            # Check whether this packet contains a FIN.
            if(packet.TCP_header.flags.get("FIN", 0)):
                endTime = packet.timestamp
        
        durations.append(endTime - groupOfPackets[0].timestamp)

    if(not durations):
        return None, None, None
    
    return min(durations), statistics.mean(durations), max(durations)


def RTTStatistics(completeConnections):
    RTTs = []

    for groupOfPackets in completeConnections:
        i = 0
        for packet in groupOfPackets:

            # Only consider packets sent from client to server.
            dataLength = (packet.IP_header.total_len - packet.IP_header.ip_header_len - packet.TCP_header.data_offset)

            flags = packet.TCP_header.flags

            # Determine how much sequence space this packet consumes.
            sequenceLength = dataLength

            if flags.get("SYN", 0):
                sequenceLength += 1

            if flags.get("FIN", 0):
                sequenceLength += 1

            # Ignore packets that consume no sequence space.
            if sequenceLength <= 0:
                i+=1
                continue

            expectedAck = (packet.TCP_header.seq_num + sequenceLength) & 0xFFFFFFFF

            for ackPacket in groupOfPackets[i + 1:]:

                # ACK must travel in the opposite direction.
                if (ackPacket.IP_header.src_ip == packet.IP_header.dst_ip
                    and ackPacket.IP_header.dst_ip == packet.IP_header.src_ip
                    and ackPacket.TCP_header.src_port == packet.TCP_header.dst_port
                    and ackPacket.TCP_header.dst_port == packet.TCP_header.src_port
                ):
                    if ackPacket.TCP_header.flags.get("ACK", 0):
                        if ackPacket.TCP_header.ack_num == expectedAck:
                            packet.get_RTT_value(ackPacket)
                            packet.RTT_flag = True
                            break

            i+=1

    for groupOfPackets in completeConnections:
        for packet in groupOfPackets:
            if packet.RTT_flag:
                RTTs.append(packet.RTT_value)

    if not RTTs:
        return None, None, None

    return min(RTTs), statistics.mean(RTTs), max(RTTs)


def numberOfPacketsStatistics(completeConnection):
    numberOfPackets = []

    for groupOfPackets in completeConnection:
        numberOfPackets.append(len(groupOfPackets))

    if(not numberOfPackets):
        return None, None, None

    return min(numberOfPackets), statistics.mean(numberOfPackets), max(numberOfPackets)

def reciveWindowSizeStatistics(completeConnection):
    reciveWindowSizes = []

    for groupOfPackets in completeConnection:
        for packet in groupOfPackets:
            reciveWindowSizes.append(packet.TCP_header.window_size)

    if(not reciveWindowSizes):
        return None, None, None
    
    return min(reciveWindowSizes), statistics.mean(reciveWindowSizes), max(reciveWindowSizes)


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

            # Create new instance of packet struct
            newPacket = packet()
            newPacket.timestamp_set(packetHeader[0:4], packetHeader[4:8], origTime)
            newPacket.packet_No_set(numberOfPackets)
            newPacket.buffer = packetData

            newPacket, isTCP = configureIPv4PacketData(newPacket, endian)
            if(newPacket == None):
                break
            newPacket = configureTCPPacketData(newPacket, endian)
            if(newPacket == None):
                break

            if(isTCP):
                packets.append(newPacket)


    groupedPackets = groupPacketsByConnection(packets)

    # pre-made this list because its used a lot in various sections
    completeConnection = getCompleteConnections(groupedPackets)

    numberOfConnections = len(groupedPackets)
    print("A) Total number of connections:", numberOfConnections)

    print("\n-----------------------------------------\n")

    print("B) Connections' details\n")

    connectionNumber = 1
    for groupOfPackets in groupedPackets.values():
        
        print("Connection Number:", connectionNumber)

        # Take source address from first packet in group
        connectionSourceAddress = groupOfPackets[0].IP_header.src_ip
        print("Source Address:", connectionSourceAddress)

        # Take destination address from first packet in group
        connectionDestinationAddress = groupOfPackets[0].IP_header.dst_ip
        print("Destination Address:", connectionDestinationAddress)

        # Take source port from first packet in group
        connectionSourcePort = groupOfPackets[0].TCP_header.src_port
        print("Source Port:", connectionSourcePort)

        # Take destination port from first packet in group
        connectionDestinationPort = groupOfPackets[0].TCP_header.dst_port
        print("Destination Port:", connectionDestinationPort)

        # get the number of R's S's and F's (RST, SYN, FIN)
        connectionStatus = getConnectionStatus(groupOfPackets)
        print("Status:", connectionStatus)

        # only continue for complete connections
        r, s, f = [int(char) for char in connectionStatus if char.isdigit()]
        if(s>=1 and f>=1):

            # Take the start time from the first packet in the group
            firstPacketStartTime = groupOfPackets[0].timestamp
            print("Start Time:", round(firstPacketStartTime,5), "s")

            # Take the end time from the last FIN in the group
            lastPacketEndTime = getConnectionEndTime(groupOfPackets)
            print("End Time:", round(lastPacketEndTime, 5), "s")

            # Subtract the start time from the end time
            duration = lastPacketEndTime - firstPacketStartTime
            print("Duration:", round(duration, 5), "s")

            # Using the source of the fisrt packet compare the source address of the packet to the expected source value
            numberOfPacketsFromSource = getNumberOfPacketsFromSource(groupOfPackets, groupOfPackets[0].TCP_header.src_port)
            print("Number of packets sent from Source to Destination:", numberOfPacketsFromSource)

            # Using the destination of the fisrt packet compare the source address of the packet to the expected destination value
            numberOfPacketsFromDestination = getNumberOfPacketsFromDestination(groupOfPackets, groupOfPackets[0].TCP_header.dst_port)
            print("Number of packets sent from Destination to Source:", numberOfPacketsFromDestination)

            # Take the total length of the groupOfPackets
            totalNumberOfPackets = len (groupOfPackets)
            print("Total number of packets:", totalNumberOfPackets)

            # Calculate number of bytes send from src
            numberOfBytesFromSource = getNumberOfBytesFromSource(groupOfPackets, groupOfPackets[0].TCP_header.src_port)
            print("Number of data bytes sent from Source to Destination:", numberOfBytesFromSource, "B")

            # Calculate number of bytes sent from dest
            numberOfBytesFromDestination = getNumberOfBytesFromDestination(groupOfPackets, groupOfPackets[0].TCP_header.dst_port)
            print("Number of data bytes sent from Destination to Source:", numberOfBytesFromDestination, "B")

            # Calculate number of bytes send in both directions
            totalNumberOfBytes = numberOfBytesFromSource + numberOfBytesFromDestination
            print("Total number of data bytes:", totalNumberOfBytes, "B")

        print("END\n")

        connectionNumber+=1


    print("-----------------------------------------\n")
    print("C) General\n")

    # Check number of connections with S>0 and F>0
    totalNumberOfCompleteConnections = len(completeConnection)
    print("The total number of complete TCP connections:", totalNumberOfCompleteConnections)

    # Check number of connections with R>0
    totalNumberOfResetConnections = getTotalNumberOfResetConnections(groupedPackets)
    print("The number of reset TCP connections:", totalNumberOfResetConnections)

    # Check number of connections with F=0
    totalNumberOfOpenConnections = getTotalNumberOfOpenConnections(groupedPackets)
    print("The number of TCP connections that were still open when the trace capture ended:", totalNumberOfOpenConnections)

    # Check number of connections with data before S flag (while S=0)
    totalNumberOfBeforeCaptureConnections = getTotalNumberOfBeforeCaptureConnections(groupedPackets)
    print("The number of TCP connections established before the capture started:", totalNumberOfBeforeCaptureConnections)

    print("\n-----------------------------------------\n")
    print("D) Complete TCP connections\n")

    # Calculate all the duration stats
    minimumDuration, meanDuration, maximumDuration = durationStatistics(completeConnection)
    print("Minimum time duration:", round(minimumDuration, 5), "s")
    print("Mean time duration:", round(meanDuration, 5), "s")
    print("Maximum time duration:", round(maximumDuration, 5), "s", "\n")

    # Calculate all the RTT stats
    minimumRTT, meanRTT, maximumRTT = RTTStatistics(completeConnection)
    print("Minimum RTT value:", round(minimumRTT, 5), "s")
    print("Mean RTT value:", round(meanRTT, 5), "s")
    print("Maximum RTT value:", round(maximumRTT, 5), "s", "\n")

    # Calculate all the number of packets stats
    minimumNumberOfPackets, meanNumberOfPackets, maximumNumberOfPackets = numberOfPacketsStatistics(completeConnection)
    print("Minimum number of packets including both send/received:", minimumNumberOfPackets)
    print("Mean number of packets including both send/received:", round(meanNumberOfPackets, 5))
    print("Maximum number of packets including both send/received:", maximumNumberOfPackets, "\n")

    # Calculate all the rwnd size stats
    minimumReciveWindowSize, meanReciveWindowSize, maximumReciveWindowSize = reciveWindowSizeStatistics(completeConnection)
    print("Minimum receive window size including both send/received:", minimumReciveWindowSize, "B")
    print("Mean receive window size including both send/received:", round(meanReciveWindowSize, 5), "B")
    print("Maximum receive window size including both send/received:", maximumReciveWindowSize, "B")




main()