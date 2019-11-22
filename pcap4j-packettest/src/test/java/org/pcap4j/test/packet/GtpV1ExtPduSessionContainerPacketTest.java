package org.pcap4j.test.packet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.Inet6Address;
import java.net.InetAddress;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.GtpV1ExtPduSessionContainerPacket;
import org.pcap4j.packet.GtpV1ExtPduSessionContainerPacket.GtpV1ExtPduSessionContainerHeader;
import org.pcap4j.packet.GtpV1Packet;
import org.pcap4j.packet.GtpV1Packet.ProtocolType;
import org.pcap4j.packet.GtpVersion;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.IpV6SimpleFlowLabel;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket.Builder;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.GtpV1ExtPduSessionContainerPduType;
import org.pcap4j.packet.namednumber.GtpV1ExtensionHeaderType;
import org.pcap4j.packet.namednumber.GtpV1MessageType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class GtpV1ExtPduSessionContainerPacketTest extends AbstractPacketTest {

  private static final Logger logger =
      LoggerFactory.getLogger(GtpV1ExtPduSessionContainerPacketTest.class);

  private final byte extensionHeaderLength;
  private final GtpV1ExtPduSessionContainerPduType pduType;
  private final byte spare1;
  private final boolean ppp;
  private final boolean rqi;
  private final byte qfi;
  private final Byte ppi;
  private final Byte spare2;
  private final byte[] padding;
  private final GtpV1ExtensionHeaderType nextExtensionHeaderType;
  private final GtpV1ExtPduSessionContainerPacket packet;

  public GtpV1ExtPduSessionContainerPacketTest() throws Exception {
    this.extensionHeaderLength = 2;
    this.pduType = GtpV1ExtPduSessionContainerPduType.DL_PDU_SESSION_INFORMATION;
    this.spare1 = (byte) 5;
    this.ppp = true;
    this.rqi = false;
    this.qfi = (byte) 15;
    this.ppi = (byte) 7;
    this.spare2 = (byte) 0x12;
    this.padding = new byte[] {0x03, 0x02, 0x01};
    this.nextExtensionHeaderType = GtpV1ExtensionHeaderType.NO_MORE_EXTENSION_HEADERS;

    Builder unknownb = new Builder();
    unknownb.rawData(new byte[] {(byte) 0, (byte) 1, (byte) 2, (byte) 3});

    GtpV1ExtPduSessionContainerPacket.Builder b = new GtpV1ExtPduSessionContainerPacket.Builder();
    b.extensionHeaderLength(extensionHeaderLength)
        .pduType(pduType)
        .spare1(spare1)
        .ppp(ppp)
        .rqi(rqi)
        .qfi(qfi)
        .ppi(ppi)
        .spare2(spare2)
        .padding(padding)
        .nextExtensionHeaderType(nextExtensionHeaderType)
        .payloadBuilder(unknownb)
        .correctLengthAtBuild(false)
        .paddingAtBuild(false);

    this.packet = b.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    GtpV1Packet.Builder b = new GtpV1Packet.Builder();
    b.version(GtpVersion.V1)
        .protocolType(ProtocolType.GTP)
        .reserved(false)
        .extensionHeaderFlag(true)
        .sequenceNumberFlag(true)
        .nPduNumberFlag(true)
        .messageType(GtpV1MessageType.ECHO_RESPONSE)
        .teid(1234567890)
        .sequenceNumber((short) 0x1122)
        .nPduNumber((byte) 0x33)
        .nextExtensionHeaderType(GtpV1ExtensionHeaderType.PDU_SESSION_CONTAINER)
        .payloadBuilder(packet.getBuilder().correctLengthAtBuild(true).paddingAtBuild(true))
        .correctLengthAtBuild(true);

    Inet6Address srcAddr;
    Inet6Address dstAddr;
    try {
      srcAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:1");
      dstAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:2");
    } catch (Exception e) {
      throw new AssertionError("Never get here.");
    }

    UdpPacket.Builder udpb = new UdpPacket.Builder();
    udpb.dstPort(UdpPort.GTP_C)
        .srcPort(UdpPort.getInstance((short) 12345))
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true)
        .payloadBuilder(b);

    IpV6Packet.Builder IpV6b = new IpV6Packet.Builder();
    IpV6b.version(IpVersion.IPV6)
        .trafficClass(IpV6SimpleTrafficClass.newInstance((byte) 0x12))
        .flowLabel(IpV6SimpleFlowLabel.newInstance(0x12345))
        .nextHeader(IpNumber.UDP)
        .hopLimit((byte) 100)
        .srcAddr(srcAddr)
        .dstAddr(dstAddr)
        .payloadBuilder(udpb)
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

  @BeforeAll
  public static void setUpBeforeClass() throws Exception {
    logger.info(
        "########## "
            + GtpV1ExtPduSessionContainerPacketTest.class.getSimpleName()
            + " START ##########");
  }

  @AfterAll
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      GtpV1ExtPduSessionContainerPacket p =
          GtpV1ExtPduSessionContainerPacket.newPacket(
              packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testGetHeader() {
    GtpV1ExtPduSessionContainerHeader h = packet.getHeader();
    assertEquals(extensionHeaderLength, h.getExtensionHeaderLength());
    assertEquals(pduType, h.getPduType());
    assertEquals(spare1, h.getSpare1());
    assertEquals(ppp, h.getPpp());
    assertEquals(rqi, h.getRqi());
    assertEquals(qfi, h.getQfi());
    assertEquals(ppi, h.getPpi());
    assertEquals(spare2, h.getSpare2());
    assertArrayEquals(padding, h.getPadding());
    assertEquals(nextExtensionHeaderType, h.getNextExtensionHeaderType());

    GtpV1ExtPduSessionContainerPacket.Builder b = packet.getBuilder();
    GtpV1ExtPduSessionContainerPacket p;

    b.extensionHeaderLength((byte) 0);
    p = b.build();
    assertEquals((byte) 0, (byte) p.getHeader().getExtensionHeaderLengthAsInt());

    b.extensionHeaderLength((byte) -1);
    p = b.build();
    assertEquals((byte) -1, (byte) p.getHeader().getExtensionHeaderLengthAsInt());

    b.extensionHeaderLength((byte) 127);
    p = b.build();
    assertEquals((byte) 127, (byte) p.getHeader().getExtensionHeaderLengthAsInt());

    b.extensionHeaderLength((byte) -128);
    p = b.build();
    assertEquals((byte) -128, (byte) p.getHeader().getExtensionHeaderLengthAsInt());

    b.spare1((byte) 0);
    p = b.build();
    assertEquals((byte) 0, p.getHeader().getSpare1());

    b.spare1((byte) 15);
    p = b.build();
    assertEquals((byte) 15, p.getHeader().getSpare1());

    b.spare1((byte) 16);
    try {
      b.build();
      fail();
    } catch (IllegalArgumentException e) {
      // pass
    }

    b.spare1((byte) -1);
    try {
      b.build();
      fail();
    } catch (IllegalArgumentException e) {
      // pass
    }

    b.spare1((byte) 0);

    b.qfi((byte) 0);
    p = b.build();
    assertEquals((byte) 0, p.getHeader().getQfi());

    b.qfi((byte) 63);
    p = b.build();
    assertEquals((byte) 63, p.getHeader().getQfi());

    b.qfi((byte) 64);
    try {
      b.build();
      fail();
    } catch (IllegalArgumentException e) {
      // pass
    }

    b.qfi((byte) -1);
    try {
      b.build();
      fail();
    } catch (IllegalArgumentException e) {
      // pass
    }

    b.qfi((byte) 0);

    b.ppi((byte) 0);
    p = b.build();
    assertEquals((byte) 0, p.getHeader().getPpi().byteValue());

    b.ppi((byte) 7);
    p = b.build();
    assertEquals((byte) 7, p.getHeader().getPpi().byteValue());

    b.ppi((byte) 8);
    try {
      b.build();
      fail();
    } catch (IllegalArgumentException e) {
      // pass
    }

    b.ppi((byte) -1);
    try {
      b.build();
      fail();
    } catch (IllegalArgumentException e) {
      // pass
    }

    b.ppi((byte) 0);

    b.spare2((byte) 0);
    p = b.build();
    assertEquals((byte) 0, p.getHeader().getSpare2().byteValue());

    b.spare2((byte) 31);
    p = b.build();
    assertEquals((byte) 31, p.getHeader().getSpare2().byteValue());

    b.spare2((byte) 32);
    try {
      b.build();
      fail();
    } catch (IllegalArgumentException e) {
      // pass
    }

    b.spare2((byte) -1);
    try {
      b.build();
      fail();
    } catch (IllegalArgumentException e) {
      // pass
    }

    b.spare2((byte) 0);
  }
}
