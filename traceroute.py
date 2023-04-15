from socket import *
import os
import sys
import struct
import time
import select
import binascii
import pandas as pd

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 60
TIMEOUT = 2.0
TRIES = 1


# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
    # In this function we make the checksum of our packet
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def build_packet():
    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.
    myChecksum = 0
    ID = os.getpid() & 0xFFFF

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())

    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Now that we have the right checksum, we put that in. It's just easier to
    # make up a new header than to stuff it into the dummy.
    if sys.platform == 'darwin':
        myChecksum = socket.htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)

    # Don’t send the packet yet , just return the final packet in this function.
    packet = header + data
    return packet


def get_route(hostname):
    timeLeft = TIMEOUT
    df = pd.DataFrame(columns=['Hop Count', 'Try', 'IP', 'Hostname', 'Response Code'])
    destAddr = socket.gethostbyname(hostname)

    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):
            mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []:  # Timeout
                    df = df.append(
                        {'Hop Count': ttl, 'Try': tries + 1, 'IP': '*', 'Hostname': '*', 'Response Code': 'timeout'},
                        ignore_index=True)
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    df = df.append(
                        {'Hop Count': ttl, 'Try': tries + 1, 'IP': '*', 'Hostname': '*', 'Response Code': 'timeout'},
                        ignore_index=True)
            except socket.error as e:
                continue

            else:
                icmpHeader = recvPacket[20:28]
                types, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
                try:  # try to fetch the hostname of the router that returned the packet - don't confuse with the hostname that you are tracing
                    host = socket.gethostbyaddr(addr[0])[0]
                except socket.herror:  # if the router host does not provide a hostname use "hostname not returnable"
                    host = 'hostname not returnable'

                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    df = df.append({'Hop Count': ttl, 'Try': tries + 1, 'IP': addr[0], 'Hostname': host,
                                    'Response Code': 'ttl-expired'}, ignore_index=True)
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    df = df.append({'Hop Count': ttl, 'Try': tries + 1, 'IP': addr[0], 'Hostname': host,
                                    'Response Code': 'dest-unreachable'}, ignore_index=True)
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    df = df.append({'Hop Count': ttl, 'Try': tries + 1, 'IP': addr[0], 'Hostname': host,
                                    'Response Code': 'success'}, ignore_index=True)
                    return df
                else:
                    df = df.append({'Hop Count': ttl, 'Try': tries + 1, 'IP': addr[0], 'Hostname': host,
                                    'Response Code': 'unknown'}, ignore_index=True)
                break
    return df

if __name__ == '__main__':
    get_route("google.co.il")
