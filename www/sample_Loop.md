[org.pcap4j.sample.Loop](https://github.com/kaitoy/pcap4j/tree/v1/pcap4j-sample/src/main/java/org/pcap4j/sample/Loop.java) is
a sample class which captures packets and dumps them.
In the following example, this sample is executed on Linux to capture two ICMP packets via eth2.


      [root@localhost Desktop]# java -cp pcap4j-core.jar:pcap4j-packetfactory-static.jar:pcap4j-sample.jar:jna-3.5.2.jar:slf4j-api-1.6.4.jar -Dorg.pcap4j.sample.Loop.count=2 org.pcap4j.sample.Loop icmp
      org.pcap4j.sample.Loop.count: 2
      org.pcap4j.sample.Loop.readTimeout: 10
      org.pcap4j.sample.Loop.maxCapLen: 65536


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

      Select a device number to capture packets, or enter 'q' to quit > 2
      eth2(null)
      2012-10-05 03:48:51.881454
      [Ethernet Header (14 bytes)]
        Destination address: 00:0c:29:02:65:62
        Source address: 04:7d:7b:4c:2f:0a
        Type: 0x0800(IPv4)
      [IPv4 Header (20 bytes)]
        Version: 4(IPv4)
        IHL: 5 (20 [bytes])
        TOS: [precedence: 0(Routine)] [tos: 0(Default)] [mbz: 0]
        Total length: 60 [bytes]
        Identification: 3340
        Flags: (Reserved, Don't Fragment, More Fragment) = (false, false, false)
        Flagment offset: 0 (0 [bytes])
        TTL: 128
        Protocol: 1(ICMPv4)
        Header checksum: 0xa792
        Source address: /192.168.2.101
        Destination address: /192.168.2.109
      [ICMP Common Header (4 bytes)]
        Type: 8(Echo)
        Code: 0(No Code)
        Checksum: 0x4c53
      [ICMPv4 Echo Header (4 bytes)]
        Identifier: 256
        SequenceNumber: 9
      [data (32 bytes)]
        Hex stream: 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 61 62 63 64 65 66 67 68 69

      2012-10-05 03:48:51.979233
      [Ethernet Header (14 bytes)]
        Destination address: 04:7d:7b:4c:2f:0a
        Source address: 00:0c:29:02:65:62
        Type: 0x0800(IPv4)
      [IPv4 Header (20 bytes)]
        Version: 4(IPv4)
        IHL: 5 (20 [bytes])
        TOS: [precedence: 0(Routine)] [tos: 0(Default)] [mbz: 0]
        Total length: 60 [bytes]
        Identification: 19161
        Flags: (Reserved, Don't Fragment, More Fragment) = (false, false, false)
        Flagment offset: 0 (0 [bytes])
        TTL: 64
        Protocol: 1(ICMPv4)
        Header checksum: 0xa9c5
        Source address: /192.168.2.109
        Destination address: /192.168.2.101
      [ICMP Common Header (4 bytes)]
        Type: 0(Echo Reply)
        Code: 0(No Code)
        Checksum: 0x5453
      [ICMPv4 Echo Reply Header (4 bytes)]
        Identifier: 256
        SequenceNumber: 9
      [data (32 bytes)]
        Hex stream: 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 61 62 63 64 65 66 67 68 69
