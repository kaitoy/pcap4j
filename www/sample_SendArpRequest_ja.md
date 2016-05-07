[org.pcap4j.sample.SendArpRequest](https://github.com/kaitoy/pcap4j/tree/v1/pcap4j-sample/src/main/java/org/pcap4j/sample/SendArpRequest.java)は
ARPリクエストを送信してIPアドレスをMACアドレスに解決するサンプルクラス。
以下はLinuxで192.168.209.1を解決する実行例。


      [root@localhost Desktop]# java -cp pcap4j-core.jar:pcap4j-packetfactory-static.jar:pcap4j-sample.jar:jna-3.5.2.jar:slf4j-api-1.6.4.jar org.pcap4j.sample.SendArpRequest 192.168.209.1
      org.pcap4j.sample.SendArpRequest.count: 1
      org.pcap4j.sample.SendArpRequest.readTimeout: 10
      org.pcap4j.sample.SendArpRequest.maxCapLen: 65536


      SLF4J: Failed to load class "org.slf4j.impl.StaticLoggerBinder".
      SLF4J: Defaulting to no-operation (NOP) logger implementation
      SLF4J: See http://www.slf4j.org/codes.html#StaticLoggerBinder for further details.
      NIF[0]: eth0
            : description: null
            : address: /192.168.209.128
      NIF[1]: eth1
            : description: null
            : address: /192.168.76.128
      NIF[2]: eth2
            : description: null
            : address: /192.168.2.109
      NIF[3]: any
            : description: Pseudo-device that captures on all interfaces
      NIF[4]: lo
            : description: null
            : address: /127.0.0.1

      Select a device number to capture packets, or enter 'q' to quit > 0
      eth0(null)
      [Ethernet Header (14 bytes)]
        Destination address: ff:ff:ff:ff:ff:ff
        Source address: fe:00:01:02:03:04
        Type: 0x0806(ARP)
      [ARP Header (28 bytes)]
        Hardware type: 1(Ethernet(10Mb))
        Protocol type: 0x0800(IPv4)
        Hardware length: 6 [bytes]
        Protocol length: 4 [bytes]
        Operation: 1(REQUEST)
        Source hardware address: fe:00:01:02:03:04
        Source protocol address: /192.0.2.100
        Destination hardware address: ff:ff:ff:ff:ff:ff
        Destination protocol address: /192.168.209.1
      [Ethernet Pad (18 bytes)]
        Hex stream: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

      [Ethernet Header (14 bytes)]
        Destination address: fe:00:01:02:03:04
        Source address: 00:50:56:c0:00:08
        Type: 0x0806(ARP)
      [ARP Header (28 bytes)]
        Hardware type: 1(Ethernet(10Mb))
        Protocol type: 0x0800(IPv4)
        Hardware length: 6 [bytes]
        Protocol length: 4 [bytes]
        Operation: 2(REPLY)
        Source hardware address: 00:50:56:c0:00:08
        Source protocol address: /192.168.209.1
        Destination hardware address: fe:00:01:02:03:04
        Destination protocol address: /192.0.2.100
      [Ethernet Pad (18 bytes)]
        Hex stream: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

      192.168.209.1 was resolved to 00:50:56:c0:00:08
