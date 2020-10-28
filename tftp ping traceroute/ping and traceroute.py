# -*- coding: utf-8 -*-

# import socket
# import os
# import sys
# import struct
# import time
# import select

# ICMP_ECHO_REQUEST = 8
# MAX_HOPS = 30
# TIMEOUT = 2.0
# TRIES = 2


# def checksum(str_):
#     # In this function we make the checksum of our packet 
#     str_ = bytearray(str_)
#     csum = 0
#     countTo = (len(str_) // 2) * 2

#     for count in range(0, countTo, 2):
#         thisVal = str_[count+1] * 256 + str_[count]
#         csum = csum + thisVal
#         csum = csum & 0xffffffff

#     if countTo < len(str_):
#         csum = csum + str_[-1]
#         csum = csum & 0xffffffff

#     csum = (csum >> 16) + (csum & 0xffff)
#     csum = csum + (csum >> 16)
#     answer = ~csum
#     answer = answer & 0xffff
#     answer = answer >> 8 | (answer << 8 & 0xff00)
#     return answer

# def build_packet():
#     # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
#     # packet to be sent was made, secondly the checksum was appended to the header and
#     # then finally the complete packet was sent to the destination.

#     # Make the header in a similar way to the ping exercise.
#     myChecksum = 0
#     myID = os.getpid() & 0xFFFF

#     # Make a dummy header with a 0 checksum.
#     # struct -- Interpret strings as packed binary data
#     header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
#     #header = struct.pack("!HHHHH", ICMP_ECHO_REQUEST, 0, myChecksum, pid, 1)
#     data = struct.pack("d", time.time())

#     # Calculate the checksum on the data and the dummy header.
#     # Append checksum to the header.
#     myChecksum = checksum(header + data)    
#     if sys.platform == 'darwin':
#         myChecksum = socket.htons(myChecksum) & 0xffff
#         #Convert 16-bit integers from host to network byte order.
#     else:
#         myChecksum = socket.htons(myChecksum)

#     header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
#     packet = header + data
#     return packet

# def get_route(hostname):
#     timeLeft = TIMEOUT
#     for ttl in range(1,MAX_HOPS):
#         for tries in range(TRIES):
#             destAddr = socket.gethostbyname(hostname)
            
#             #Fill in start
#             # Make a raw socket named mySocket
#             icmp = socket.getprotobyname("icmp")
#             mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
#             #mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, icmp)
#             #Fill in end
            
#             mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
#             mySocket.settimeout(TIMEOUT)
#             try:
#                 d = build_packet()
#                 mySocket.sendto(d, (hostname, 0))
#                 t = time.time()
#                 startedSelect = time.time()
#                 whatReady = select.select([mySocket], [], [], timeLeft)
#                 howLongInSelect = (time.time() - startedSelect)

#                 if whatReady[0] == []: # Timeout
#                     print ("*    *    * Request timed out.")

#                 recvPacket, addr = mySocket.recvfrom(1024)
#                 print (addr)
#                 timeReceived = time.time()
#                 timeLeft = timeLeft - howLongInSelect

#                 if timeLeft <= 0:
#                     print ("*    *    * Request timed out.")

#             except socket.timeout:
#                 continue

#             else:
#                 icmpHeader = recvPacket[20:28]
#                 request_type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

#                 if request_type == 11:
#                     bytes = struct.calcsize("d")
#                     timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
#                     print (" %d   rtt=%.0f ms %s" % (ttl,(timeReceived -t)*1000, addr[0]))
#                 elif request_type == 3:
#                     bytes = struct.calcsize("d")
#                     timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
#                     print (" %d   rtt=%.0f ms %s" % (ttl,(timeReceived -t)*1000, addr[0]))
#                 elif request_type == 0:
#                     bytes = struct.calcsize("d")
#                     timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
#                     print (" %d   rtt=%.0f ms %s" % (ttl,(timeReceived -timeSent)*1000, addr[0]))
#                     return
#                 else:
#                     print ("error")
#                     break
#             finally:
#                 mySocket.close()

# get_route('www.baidu.com')

"""
原理：发送icmp包获取响应来探测目标ip是否存活，分为以下几步：
1.构造icmp包
2.用套接字将其发送到目标ip
3.接收返回的信息判断是否存活
"""

import time
import struct
import socket
import select
import sys


"""
1.将校验和字段置为0。
2.将每两个字节（16位）相加（二进制求和）直到最后得出结果，若出现最后还剩一个字节继续与前面结果相加。
3.(溢出)将高16位与低16位相加，直到高16位为0为止。
4.将最后的结果（二进制）取反。
"""
def chesksum(data):
    n=len(data)
    m=n % 2
    sum=0
    for i in range(0, n - m ,2):
        sum += (data[i]) + ((data[i+1]) << 8)#传入data以每两个字节（十六进制）通过ord转十进制，第一字节在低位，第二个字节在高位
    if m:
        sum += (data[-1])
    #将高于16位与低16位相加
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16) #如果还有高于16位，将继续与低16位相加
    answer = ~sum & 0xffff
    #  主机字节序转网络字节序列（参考小端序转大端序）
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def request_ping(data_type,data_code,data_checksum,data_ID,data_Sequence,payload_body):
    #  把字节打包成二进制数据,> 大端编码,B unsigned char,H unsigned short,32s 32字节长的字符串
    imcp_packet = struct.pack('>BBHHH32s',data_type,data_code,data_checksum,data_ID,data_Sequence,payload_body)
    icmp_chesksum = chesksum(imcp_packet)  #获取校验和
    #  把校验和传入，再次打包
    imcp_packet = struct.pack('>BBHHH32s',data_type,data_code,icmp_chesksum,data_ID,data_Sequence,payload_body)
    return imcp_packet


def raw_socket(dst_addr,imcp_packet):
    '''
        连接套接字,并将数据发送到套接字
    '''
    #实例化一个socket对象，ipv4，原套接字，分配协议端口
    rawsocket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.getprotobyname("icmp"))
    #记录当前请求时间
    send_request_ping_time = time.time()
    #发送数据到网络
    rawsocket.sendto(imcp_packet,(dst_addr,80))
    #返回数据
    return send_request_ping_time,rawsocket,dst_addr


def reply_ping(send_request_ping_time,rawsocket,data_Sequence,timeout = 2):
    while True:
        #开始时间
        started_select = time.time()
        #实例化select对象，可读rawsocket，可写为空，可执行为空，超时时间
        what_ready = select.select([rawsocket], [], [], timeout)
        #等待时间
        wait_for_time = (time.time() - started_select)
        #没有返回可读的内容，判断超时
        if what_ready[0] == []:  # Timeout
            return -1
        #记录接收时间
        time_received = time.time()
        #设置接收的包的字节为1024
        received_packet, addr = rawsocket.recvfrom(1024)
        #获取接收包的icmp头
        #print(icmpHeader)
        icmpHeader = received_packet[20:28]
        #反转编码
        type, code, checksum, packet_id, sequence = struct.unpack(
            ">BBHHH", icmpHeader
        )

        if type == 0 and sequence == data_Sequence:
            return time_received - send_request_ping_time

        #数据包的超时时间判断
        timeout = timeout - wait_for_time
        if timeout <= 0:
            return -1
def dealtime(dst_addr,sumtime,shorttime,longtime,accept,i,time):
    sumtime+=time
    print(sumtime)
    if i==4:
        print("{0}的Ping统计信息：".format(dst_addr))
        print("数据包：已发送={0},接收={1}，丢失={2}（{3}%丢失），\n往返行程的估计时间（以毫秒为单位）：\n\t最短={4}ms，最长={5}ms，平均={6}ms".format(i+1,accept,i+1-accept,(i+1-accept)/(i+1)*100,shorttime,longtime,sumtime))
def ping(host):
    send, accept, lost = 0, 0, 0
    sumtime, shorttime, longtime, avgtime = 0, 1000, 0, 0
    #TODO icmp数据包的构建
    data_type = 8 # ICMP Echo Request
    data_code = 0 # must be zero
    data_checksum = 0 # "...with value 0 substituted for this field..."
    data_ID = 0 #Identifier
    data_Sequence = 1 #Sequence number
    payload_body = b'abcdefghijklmnopqrstuvwabcdefghi' #data

    # 将主机名转ipv4地址格式，返回以ipv4地址格式的字符串，如果主机名称是ipv4地址，则它将保持不变
    dst_addr = socket.gethostbyname(host)
    print("正在 Ping {0} [{1}] 具有 32 字节的数据:".format(host,dst_addr))
    for i in range(0,4):
        send=i+1
        #请求ping数据包的二进制转换
        icmp_packet = request_ping(data_type,data_code,data_checksum,data_ID,data_Sequence + i,payload_body)
        #连接套接字,并将数据发送到套接字
        send_request_ping_time,rawsocket,addr = raw_socket(dst_addr,icmp_packet)
        #数据包传输时间
        times = reply_ping(send_request_ping_time,rawsocket,data_Sequence + i)
        if times > 0:
            print("来自 {0} 的回复: 字节=32 时间={1}ms".format(addr,int(times*1000)))

            accept+=1
            return_time=int(times * 1000)
            sumtime += return_time
            if return_time > longtime:
                longtime = return_time
            if return_time < shorttime:
                shorttime = return_time
            time.sleep(0.7)
        else:
            lost+=1
            print("请求超时。")

        if send == 4:
            print("{0}的Ping统计信息:".format(dst_addr))
            print("\t数据包：已发送={0},接收={1}，丢失={2}（{3}%丢失），\n往返行程的估计时间（以毫秒为单位）：\n\t最短={4}ms，最长={5}ms，平均={6}ms".format(
                i + 1, accept, i + 1 - accept, (i + 1 - accept) / (i + 1) * 100, shorttime, longtime, sumtime/send))



if __name__ == "__main__":
    # if len(sys.argv) < 2:
    #     sys.exit('Usage: ping.py <host>')
    # ping(sys.argv[1])
    i=input("请输入要ping的主机或域名\n")
    ping(i)