package org.pcap4j.test.util;

import static org.junit.Assert.*;

import java.io.EOFException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.TimeoutException;
import org.junit.Test;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.IpV6Helper;
import org.pcap4j.util.MacAddress;

@SuppressWarnings("javadoc")
public class IpV6HelperTest {
  private static final String PCAP_FILE_KEY = IpV6HelperTest.class.getName() + ".pcapFile";
  private static final String PCAP_FILE =
      System.getProperty(
          PCAP_FILE_KEY,
          "src/test/resources/org/pcap4j/test/core/"
              + IpV6HelperTest.class.getSimpleName()
              + ".pcap");

  @Test
  public void testDefragment() throws Exception {
    UnknownPacket.Builder unknownb = new UnknownPacket.Builder();
    unknownb.rawData(new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});

    Inet6Address srcIp = (Inet6Address) InetAddress.getByName("2001:db8::3:2:1");
    Inet6Address dstIp = (Inet6Address) InetAddress.getByName("2001:db8::3:2:2");

    UdpPacket.Builder udpb = new UdpPacket.Builder();
    udpb.srcPort(UdpPort.SNMP_TRAP)
        .dstPort(UdpPort.getInstance((short) 0))
        .payloadBuilder(unknownb)
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true)
        .srcAddr(srcIp)
        .dstAddr(dstIp);

    IpV6Packet.Builder ipv6b = new IpV6Packet.Builder();
    ipv6b
        .version(IpVersion.IPV6)
        .hopLimit((byte) 100)
        .trafficClass(IpV6SimpleTrafficClass.newInstance((byte) 0x12))
        .flowLabel(IpV6SimpleFlowLabel.newInstance(0x12345))
        .nextHeader(IpNumber.UDP)
        .srcAddr(srcIp)
        .dstAddr(dstIp)
        .payloadBuilder(udpb)
        .correctLengthAtBuild(true);

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
        .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
        .type(EtherType.IPV6)
        .payloadBuilder(ipv6b)
        .paddingAtBuild(true);

    EthernetPacket expectedPacket = eb.build();

    PcapHandle handle = Pcaps.openOffline(PCAP_FILE);
    List<IpV6Packet> ipV6Packets = new ArrayList<IpV6Packet>();
    Packet firstPacket = null;

    while (true) {
      try {
        Packet packet = handle.getNextPacketEx();
        if (firstPacket == null) {
          firstPacket = packet;
        }
        ipV6Packets.add(packet.get(IpV6Packet.class));
      } catch (TimeoutException e) {
        continue;
      } catch (EOFException e) {
        break;
      }
    }
    handle.close();

    Collections.shuffle(ipV6Packets);

    IpV6Packet defragmentedIpV6Packet = IpV6Helper.defragment(ipV6Packets);
    Packet.Builder actualb = firstPacket.getBuilder();
    actualb
        .getOuterOf(IpV6Packet.Builder.class)
        .payloadBuilder(new SimpleBuilder(defragmentedIpV6Packet));

    assertEquals(expectedPacket, actualb.build());
  }
}
