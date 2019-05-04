package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;

import java.net.Inet6Address;
import java.net.InetAddress;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.GtpV1Packet;
import org.pcap4j.packet.GtpV1Packet.GtpV1Header;
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
import org.pcap4j.packet.namednumber.GtpV1ExtensionHeaderType;
import org.pcap4j.packet.namednumber.GtpV1MessageType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class GtpV1PacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(GtpV1PacketTest.class);

  private final GtpVersion version;
  private final ProtocolType protocolType;
  private final boolean reserved;
  private final boolean extensionHeaderFlag;
  private final boolean sequenceNumberFlag;
  private final boolean nPduNumberFlag;
  private final GtpV1MessageType messageType;
  private final short length;
  private final int teid;
  private final Short sequenceNumber;
  private final Byte nPduNumber;
  private final GtpV1ExtensionHeaderType nextExtensionHeaderType;
  private final GtpV1Packet packet;

  public GtpV1PacketTest() throws Exception {
    this.version = GtpVersion.V1;
    this.protocolType = ProtocolType.GTP;
    this.reserved = false;
    this.extensionHeaderFlag = false;
    this.sequenceNumberFlag = true;
    this.nPduNumberFlag = true;
    this.messageType = GtpV1MessageType.ECHO_RESPONSE;
    this.length = 8;
    this.teid = 1234567890;
    this.sequenceNumber = 4321;
    this.nPduNumber = (byte) 222;
    this.nextExtensionHeaderType = GtpV1ExtensionHeaderType.PDCP_PDU_NUMBER;

    Builder unknownb = new Builder();
    unknownb.rawData(new byte[] {(byte) 0, (byte) 1, (byte) 2, (byte) 3});

    GtpV1Packet.Builder b = new GtpV1Packet.Builder();
    b.version(version)
        .protocolType(protocolType)
        .reserved(reserved)
        .extensionHeaderFlag(extensionHeaderFlag)
        .sequenceNumberFlag(sequenceNumberFlag)
        .nPduNumberFlag(nPduNumberFlag)
        .messageType(messageType)
        .length(length)
        .teid(teid)
        .sequenceNumber(sequenceNumber)
        .nPduNumber(nPduNumber)
        .nextExtensionHeaderType(nextExtensionHeaderType)
        .payloadBuilder(unknownb);

    this.packet = b.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    Inet6Address srcAddr;
    Inet6Address dstAddr;
    try {
      srcAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:1");
      dstAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:2");
    } catch (Exception e) {
      throw new AssertionError("Never get here.");
    }

    UdpPacket.Builder b = new UdpPacket.Builder();
    b.dstPort(UdpPort.GTP_C)
        .srcPort(UdpPort.getInstance((short) 12345))
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true)
        .payloadBuilder(packet.getBuilder().correctLengthAtBuild(true));

    IpV6Packet.Builder IpV6b = new IpV6Packet.Builder();
    IpV6b.version(IpVersion.IPV6)
        .trafficClass(IpV6SimpleTrafficClass.newInstance((byte) 0x12))
        .flowLabel(IpV6SimpleFlowLabel.newInstance(0x12345))
        .nextHeader(IpNumber.UDP)
        .hopLimit((byte) 100)
        .srcAddr(srcAddr)
        .dstAddr(dstAddr)
        .payloadBuilder(b)
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
    logger.info("########## " + GtpV1PacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      GtpV1Packet p = GtpV1Packet.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testGetHeader() {
    GtpV1Header h = packet.getHeader();
    assertEquals(version, h.getVersion());
    assertEquals(protocolType, h.getProtocolType());
    assertEquals(extensionHeaderFlag, h.isExtensionHeaderFieldPresent());
    assertEquals(sequenceNumberFlag, h.isSequenceNumberFieldPresent());
    assertEquals(nPduNumberFlag, h.isNPduNumberFieldPresent());
    assertEquals(messageType, h.getMessageType());
    assertEquals(length, h.getLength());
    assertEquals(teid, h.getTeid());
    assertEquals(sequenceNumber, h.getSequenceNumber());
    assertEquals(nPduNumber, h.getNPduNumber());
    assertEquals(nextExtensionHeaderType, h.getNextExtensionHeaderType());

    GtpV1Packet.Builder b = packet.getBuilder();
    GtpV1Packet p;

    b.length((short) 0);
    p = b.build();
    assertEquals((short) 0, (short) p.getHeader().getLengthAsInt());

    b.length((short) -1);
    p = b.build();
    assertEquals((short) -1, (short) p.getHeader().getLengthAsInt());

    b.length((short) 32767);
    p = b.build();
    assertEquals((short) 32767, (short) p.getHeader().getLengthAsInt());

    b.length((short) -32768);
    p = b.build();
    assertEquals((short) -32768, (short) p.getHeader().getLengthAsInt());

    b.teid(0);
    p = b.build();
    assertEquals(0, (int) p.getHeader().getTeidAsLong());

    b.teid(-1);
    p = b.build();
    assertEquals(-1, (int) p.getHeader().getTeidAsLong());

    b.teid(2147483647);
    p = b.build();
    assertEquals(2147483647, (int) p.getHeader().getTeidAsLong());

    b.teid(-2147483648);
    p = b.build();
    assertEquals(-2147483648, (int) p.getHeader().getTeidAsLong());

    b.sequenceNumber((short) 0);
    p = b.build();
    assertEquals((short) 0, p.getHeader().getSequenceNumberAsInt().shortValue());

    b.sequenceNumber((short) -1);
    p = b.build();
    assertEquals((short) -1, p.getHeader().getSequenceNumberAsInt().shortValue());

    b.sequenceNumber((short) 32767);
    p = b.build();
    assertEquals((short) 32767, p.getHeader().getSequenceNumberAsInt().shortValue());

    b.sequenceNumber((short) -32768);
    p = b.build();
    assertEquals((short) -32768, p.getHeader().getSequenceNumberAsInt().shortValue());

    b.nPduNumber((byte) 0);
    p = b.build();
    assertEquals((byte) 0, p.getHeader().getNPduNumberAsInt().byteValue());

    b.nPduNumber((byte) -1);
    p = b.build();
    assertEquals((byte) -1, p.getHeader().getNPduNumberAsInt().byteValue());

    b.nPduNumber((byte) 127);
    p = b.build();
    assertEquals((byte) 127, p.getHeader().getNPduNumberAsInt().byteValue());

    b.nPduNumber((byte) -128);
    p = b.build();
    assertEquals((byte) -128, p.getHeader().getNPduNumberAsInt().byteValue());
  }
}
