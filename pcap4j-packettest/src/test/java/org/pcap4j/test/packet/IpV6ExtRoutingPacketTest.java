package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtRoutingPacket;
import org.pcap4j.packet.IpV6ExtRoutingPacket.IpV6ExtRoutingHeader;
import org.pcap4j.packet.IpV6ExtRoutingPacket.IpV6RoutingData;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.IpV6RoutingSourceRouteData;
import org.pcap4j.packet.IpV6SimpleFlowLabel;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket.Builder;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpV6RoutingType;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class IpV6ExtRoutingPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(IpV6ExtRoutingPacketTest.class);

  private final IpNumber nextHeader;
  private final byte hdrExtLen;
  private final IpV6RoutingType routingType;
  private final byte segmentsLeft;
  private final IpV6RoutingData data;
  private final IpV6ExtRoutingPacket packet;

  private final Inet6Address srcAddr;
  private final Inet6Address dstAddr;

  public IpV6ExtRoutingPacketTest() throws Exception {
    this.nextHeader = IpNumber.UDP;
    this.hdrExtLen = (byte) 6;
    this.routingType = IpV6RoutingType.SOURCE_ROUTE;
    this.segmentsLeft = (byte) 2;

    try {
      srcAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:1");
      dstAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:2");
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    ArrayList<Inet6Address> addresses = new ArrayList<Inet6Address>(3);
    addresses.add((Inet6Address) InetAddress.getByName("abcd:ef::1:1:1"));
    addresses.add((Inet6Address) InetAddress.getByName("abcd:ef::2:2:2"));
    addresses.add(dstAddr);
    this.data = new IpV6RoutingSourceRouteData(54321, addresses);

    Builder anonb = new Builder();
    anonb.rawData(new byte[] {(byte) 0, (byte) 1, (byte) 2, (byte) 3});

    UdpPacket.Builder udpb = new UdpPacket.Builder();
    udpb.dstPort(UdpPort.getInstance((short) 0))
        .srcPort(UdpPort.SNMP_TRAP)
        .dstAddr(dstAddr)
        .srcAddr(srcAddr)
        .payloadBuilder(anonb)
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true);

    IpV6ExtRoutingPacket.Builder b = new IpV6ExtRoutingPacket.Builder();
    b.nextHeader(nextHeader)
        .hdrExtLen(hdrExtLen)
        .routingType(routingType)
        .segmentsLeft(segmentsLeft)
        .data(data)
        .correctLengthAtBuild(false)
        .payloadBuilder(udpb);

    this.packet = b.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    IpV6Packet.Builder IpV6b = new IpV6Packet.Builder();
    IpV6b.version(IpVersion.IPV6)
        .trafficClass(IpV6SimpleTrafficClass.newInstance((byte) 0x12))
        .flowLabel(IpV6SimpleFlowLabel.newInstance(0x12345))
        .nextHeader(IpNumber.IPV6_ROUTE)
        .hopLimit((byte) 100)
        .srcAddr(srcAddr)
        .dstAddr(dstAddr)
        .payloadBuilder(packet.getBuilder())
        .correctLengthAtBuild(true);

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
        .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
        .type(EtherType.IPV6)
        .payloadBuilder(IpV6b)
        .paddingAtBuild(true);

    eb.get(UdpPacket.Builder.class).dstAddr(dstAddr).srcAddr(srcAddr);
    return eb.build();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
        "########## " + IpV6ExtRoutingPacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      IpV6ExtRoutingPacket p =
          IpV6ExtRoutingPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testGetHeader() {
    IpV6ExtRoutingHeader h = packet.getHeader();
    assertEquals(nextHeader, h.getNextHeader());
    assertEquals(routingType, h.getRoutingType());
    assertEquals(segmentsLeft, h.getSegmentsLeft());
    assertEquals(data, h.getData());

    IpV6ExtRoutingPacket.Builder b = packet.getBuilder();
    IpV6ExtRoutingPacket p;

    b.hdrExtLen((byte) 0);
    b.segmentsLeft((byte) 0);
    p = b.build();
    assertEquals((byte) 0, (byte) p.getHeader().getHdrExtLenAsInt());
    assertEquals((byte) 0, (byte) p.getHeader().getSegmentsLeftAsInt());

    b.hdrExtLen((byte) -1);
    b.segmentsLeft((byte) -1);
    p = b.build();
    assertEquals((byte) -1, (byte) p.getHeader().getHdrExtLenAsInt());
    assertEquals((byte) -1, (byte) p.getHeader().getSegmentsLeftAsInt());

    b.hdrExtLen((byte) 127);
    b.segmentsLeft((byte) 127);
    p = b.build();
    assertEquals((byte) 127, (byte) p.getHeader().getHdrExtLenAsInt());
    assertEquals((byte) 127, (byte) p.getHeader().getSegmentsLeftAsInt());

    b.hdrExtLen((byte) -128);
    b.segmentsLeft((byte) -128);
    p = b.build();
    assertEquals((byte) -128, (byte) p.getHeader().getHdrExtLenAsInt());
    assertEquals((byte) -128, (byte) p.getHeader().getSegmentsLeftAsInt());
  }
}
