/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.test.util;

import static org.junit.Assert.*;
import java.io.EOFException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
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

  private EthernetPacket getPacket(boolean fragmented) throws UnknownHostException {
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

    IpV6ExtFragmentPacket.Builder fragHeadb = new IpV6ExtFragmentPacket.Builder();
    fragHeadb
        .fragmentOffset((short) 0)
        .identification(123)
        .nextHeader(IpNumber.UDP)
        .payloadBuilder(udpb);

    IpV6Packet.Builder ipv6b = new IpV6Packet.Builder();
    ipv6b
        .version(IpVersion.IPV6)
        .hopLimit((byte) 100)
        .trafficClass(IpV6SimpleTrafficClass.newInstance((byte) 0x12))
        .flowLabel(IpV6SimpleFlowLabel.newInstance(0x12345))
        .nextHeader(fragmented ? IpNumber.IPV6_FRAG : IpNumber.UDP)
        .srcAddr(srcIp)
        .dstAddr(dstIp)
        .payloadBuilder(fragmented ? fragHeadb : udpb)
        .correctLengthAtBuild(true);

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
        .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
        .type(EtherType.IPV6)
        .payloadBuilder(ipv6b)
        .paddingAtBuild(true);

    return eb.build();
  }

  private Packet addExtRoutingHeader(Packet packet, boolean isFragmented)
      throws IllegalRawDataException, UnknownHostException {

    IpV6ExtRoutingPacket.Builder ipV6ExtRoutingPacketb = new IpV6ExtRoutingPacket.Builder();
    ipV6ExtRoutingPacketb
        .nextHeader(isFragmented ? IpNumber.IPV6_FRAG : IpNumber.UDP)
        .correctLengthAtBuild(true)
        .routingType(IpV6RoutingType.NIMROD)
        .segmentsLeft((byte) 2)
        .data(
            new IpV6RoutingSourceRouteData(
                0,
                new ArrayList<Inet6Address>(
                    Arrays.asList(
                        new Inet6Address[] {
                          (Inet6Address) InetAddress.getByName("2200::210:2:0:0:4")
                        }))))
        .payloadBuilder(
            isFragmented
                ? packet.get(IpV6ExtFragmentPacket.class).getBuilder()
                : packet.get(UdpPacket.class).getBuilder());

    Packet.Builder packetb = packet.getBuilder();
    packetb
        .get(IpV6Packet.Builder.class)
        .correctLengthAtBuild(true)
        .payloadBuilder(ipV6ExtRoutingPacketb)
        .nextHeader(IpNumber.IPV6_ROUTE);

    return packetb.build();
  }

  @Test(expected = IllegalArgumentException.class)
  public void twoNoFragmentedPackets() throws UnknownHostException {
    List<IpV6Packet> ipV6Packets = new ArrayList<IpV6Packet>();
    IpV6Packet ipV6Packet = getPacket(false).get(IpV6Packet.class);
    ipV6Packets.add(ipV6Packet);
    ipV6Packets.add(ipV6Packet);
    IpV6Helper.defragment(ipV6Packets);
  }

  @Test(expected = IllegalArgumentException.class)
  public void oneNoFragmentedPacket() throws UnknownHostException {
    List<IpV6Packet> ipV6Packets = new ArrayList<IpV6Packet>();
    ipV6Packets.add(getPacket(true).get(IpV6Packet.class));
    ipV6Packets.add(getPacket(false).get(IpV6Packet.class));
    IpV6Helper.defragment(ipV6Packets);
  }

  private void testDefragment(boolean routingHeader) throws Exception {
    EthernetPacket expectedPacket;
    if (routingHeader) {
      expectedPacket = (EthernetPacket) addExtRoutingHeader(getPacket(false), false);
    } else {
      expectedPacket = getPacket(false);
    }

    PcapHandle handle = Pcaps.openOffline(PCAP_FILE);
    List<IpV6Packet> ipV6Packets = new ArrayList<IpV6Packet>();
    Packet firstPacket = null;

    while (true) {
      try {
        Packet packet;
        if (routingHeader) {
          packet = addExtRoutingHeader(handle.getNextPacketEx(), true);
        } else {
          packet = handle.getNextPacketEx();
        }
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

  @Test
  public void testDefragmentWithRoutingHeader() throws Exception {
    testDefragment(true);
  }

  @Test
  public void testDefragmentWithoutExtHeaders() throws Exception {
    testDefragment(false);
  }
}
