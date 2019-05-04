package org.pcap4j.test.packet;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtUnknownPacket;
import org.pcap4j.packet.IpV6ExtUnknownPacket.IpV6ExtUnknownHeader;
import org.pcap4j.packet.IpV6Packet;
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
public class IpV6ExtUnknownPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(IpV6ExtUnknownPacketTest.class);

  private final IpNumber nextHeader;
  private final byte hdrExtLen;
  private final byte[] data;
  private final Inet6Address srcAddr;
  private final Inet6Address dstAddr;
  private final IpV6ExtUnknownPacket packet;

  public IpV6ExtUnknownPacketTest() throws Exception {
    this.nextHeader = IpNumber.UDP;
    this.hdrExtLen = (byte) 1;
    this.data = new byte[(hdrExtLen + 1) * 8 - 2];
    for (byte i = 0; i < data.length; i++) {
      data[i] = i;
    }
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

    IpV6ExtUnknownPacket.Builder b = new IpV6ExtUnknownPacket.Builder();
    b.nextHeader(nextHeader).hdrExtLen(hdrExtLen).data(data).payloadBuilder(udpb);

    this.packet = b.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    IpV6Packet.Builder ipv6b = new IpV6Packet.Builder();
    ipv6b
        .version(IpVersion.IPV6)
        .trafficClass(IpV6SimpleTrafficClass.newInstance((byte) 0x12))
        .flowLabel(IpV6SimpleFlowLabel.newInstance(0x12345))
        .payloadLength((short) 28)
        .nextHeader(IpNumber.getInstance((byte) 254))
        .hopLimit((byte) 100)
        .srcAddr(srcAddr)
        .dstAddr(dstAddr)
        .correctLengthAtBuild(false)
        .payloadBuilder(packet.getBuilder());

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
        .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
        .type(EtherType.IPV6)
        .payloadBuilder(ipv6b)
        .paddingAtBuild(true);

    eb.get(UdpPacket.Builder.class).dstAddr(srcAddr).srcAddr(dstAddr);

    return eb.build();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
        "########## " + IpV6ExtUnknownPacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      IpV6ExtUnknownPacket p =
          IpV6ExtUnknownPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testGetHeader() {
    IpV6ExtUnknownHeader h = packet.getHeader();
    assertEquals(nextHeader, h.getNextHeader());
    assertEquals(hdrExtLen, h.getHdrExtLen());
    assertArrayEquals(data, h.getData());

    IpV6ExtUnknownPacket.Builder b = packet.getBuilder();
    IpV6ExtUnknownPacket p;

    b.hdrExtLen((byte) 0);
    p = b.build();
    assertEquals((byte) 0, (byte) p.getHeader().getHdrExtLenAsInt());

    b.hdrExtLen((byte) -1);
    p = b.build();
    assertEquals((byte) -1, (byte) p.getHeader().getHdrExtLenAsInt());

    b.hdrExtLen((byte) 127);
    p = b.build();
    assertEquals((byte) 127, (byte) p.getHeader().getHdrExtLenAsInt());

    b.hdrExtLen((byte) -128);
    p = b.build();
    assertEquals((byte) -128, (byte) p.getHeader().getHdrExtLenAsInt());
  }
}
