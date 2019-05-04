package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.IpV6Packet.IpV6FlowLabel;
import org.pcap4j.packet.IpV6Packet.IpV6Header;
import org.pcap4j.packet.IpV6Packet.IpV6TrafficClass;
import org.pcap4j.packet.IpV6SimpleFlowLabel;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket.Builder;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class IpV6PacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(IpV6PacketTest.class);

  private final IpVersion version;
  private final IpV6TrafficClass trafficClass;
  private final IpV6FlowLabel flowLabel;
  private final short payloadLength;
  private final IpNumber nextHeader;
  private final byte hopLimit;
  private final Inet6Address srcAddr;
  private final Inet6Address dstAddr;
  private final IpV6Packet packet;

  public IpV6PacketTest() throws Exception {
    this.version = IpVersion.IPV6;
    this.trafficClass = IpV6SimpleTrafficClass.newInstance((byte) 0x12);
    this.flowLabel = IpV6SimpleFlowLabel.newInstance(0x12345);
    this.payloadLength = (short) 12;
    this.nextHeader = IpNumber.UDP;
    this.hopLimit = (byte) 100;
    try {
      this.srcAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:1");
      this.dstAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:2");
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    Builder unknownb = new Builder();
    unknownb.rawData(new byte[] {(byte) 0, (byte) 1, (byte) 2, (byte) 3});

    UdpPacket.Builder udpb = new UdpPacket.Builder();
    udpb.dstPort(UdpPort.getInstance((short) 0))
        .srcPort(UdpPort.SNMP_TRAP)
        .dstAddr(dstAddr)
        .srcAddr(srcAddr)
        .payloadBuilder(unknownb)
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true);

    IpV6Packet.Builder b = new IpV6Packet.Builder();
    b.version(version)
        .trafficClass(trafficClass)
        .flowLabel(flowLabel)
        .payloadLength(payloadLength)
        .nextHeader(nextHeader)
        .hopLimit(hopLimit)
        .srcAddr(srcAddr)
        .dstAddr(dstAddr)
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
    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
        .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
        .type(EtherType.IPV6)
        .payloadBuilder(packet.getBuilder())
        .paddingAtBuild(true);

    eb.get(UdpPacket.Builder.class)
        .dstAddr(packet.getHeader().getDstAddr())
        .srcAddr(packet.getHeader().getSrcAddr());
    return eb.build();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info("########## " + IpV6PacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      IpV6Packet p = IpV6Packet.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testNewPacketRandom() {
    RandomPacketTester.testClass(IpV6Packet.class, packet);
  }

  @Test
  public void testGetHeader() {
    IpV6Header h = packet.getHeader();
    assertEquals(version, h.getVersion());
    assertEquals(trafficClass, h.getTrafficClass());
    assertEquals(flowLabel, h.getFlowLabel());
    assertEquals(payloadLength, h.getPayloadLength());
    assertEquals(nextHeader, h.getNextHeader());
    assertEquals(hopLimit, h.getHopLimit());
    assertEquals(srcAddr, h.getSrcAddr());
    assertEquals(dstAddr, h.getDstAddr());

    IpV6Packet.Builder b = packet.getBuilder();
    IpV6Packet p;

    b.payloadLength((short) 0);
    b.hopLimit((byte) 0);
    p = b.build();
    assertEquals((short) 0, (short) p.getHeader().getPayloadLengthAsInt());
    assertEquals((byte) 0, (byte) p.getHeader().getHopLimitAsInt());

    b.payloadLength((short) -1);
    b.hopLimit((byte) -1);
    p = b.build();
    assertEquals((short) -1, (short) p.getHeader().getPayloadLengthAsInt());
    assertEquals((byte) -1, (byte) p.getHeader().getHopLimitAsInt());

    b.payloadLength((short) 32767);
    b.hopLimit((byte) 127);
    p = b.build();
    assertEquals((short) 32767, (short) p.getHeader().getPayloadLengthAsInt());
    assertEquals((byte) 127, (byte) p.getHeader().getHopLimitAsInt());

    b.payloadLength((short) -32768);
    b.hopLimit((byte) -128);
    p = b.build();
    assertEquals((short) -32768, (short) p.getHeader().getPayloadLengthAsInt());
    assertEquals((byte) -128, (byte) p.getHeader().getHopLimitAsInt());
  }
}
