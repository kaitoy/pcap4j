package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.IpV6SimpleFlowLabel;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SctpPacket;
import org.pcap4j.packet.SctpPacket.SctpChunk;
import org.pcap4j.packet.SctpPacket.SctpHeader;
import org.pcap4j.packet.TransportPacket;
import org.pcap4j.packet.UnknownSctpChunk.Builder;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.SctpChunkType;
import org.pcap4j.packet.namednumber.SctpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class SctpPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(SctpPacketTest.class);

  private final SctpPort srcPort;
  private final SctpPort dstPort;
  private final int verificationTag;
  private final int checksum;
  private final List<SctpChunk> chunks;
  private final SctpPacket packet;

  public SctpPacketTest() throws Exception {
    this.srcPort = SctpPort.getInstance((short) 0);
    this.dstPort = SctpPort.HTTP;
    this.verificationTag = 0xFADEFADE;
    this.checksum = 0xABCDABCD;
    this.chunks = new ArrayList<SctpChunk>();
    chunks.add(
        new Builder()
            .type(SctpChunkType.SHUTDOWN)
            .flags((byte) 0xaf)
            .value(new byte[] {1, 2, 3, 4})
            .correctLengthAtBuild(true)
            .paddingAtBuild(true)
            .build());

    SctpPacket.Builder b = new SctpPacket.Builder();
    b.dstPort(dstPort)
        .srcPort(srcPort)
        .verificationTag(verificationTag)
        .checksum(checksum)
        .chunks(chunks);

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
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    IpV6Packet.Builder IpV6b = new IpV6Packet.Builder();
    IpV6b.version(IpVersion.IPV6)
        .trafficClass(IpV6SimpleTrafficClass.newInstance((byte) 0x12))
        .flowLabel(IpV6SimpleFlowLabel.newInstance(0x12345))
        .nextHeader(IpNumber.SCTP)
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

    return eb.build();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info("########## " + SctpPacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      SctpPacket p = SctpPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testNewPacketRandom() {
    RandomPacketTester.testClass(SctpPacket.class, packet);
  }

  @Test
  public void testGetHeader() {
    SctpHeader h = packet.getHeader();
    assertEquals(srcPort, h.getSrcPort());
    assertEquals(dstPort, h.getDstPort());
    assertEquals(verificationTag, h.getVerificationTag());
    assertEquals(checksum, h.getChecksum());
    assertEquals(chunks, h.getChunks());
  }

  @Test
  public void testHasValidChecksum() {
    SctpPacket.Builder b = packet.getBuilder();
    SctpPacket p = b.correctChecksumAtBuild(false).build();

    assertFalse(packet.hasValidChecksum());

    b.correctChecksumAtBuild(true);
    p = b.build();
    assertTrue(p.hasValidChecksum());
  }

  @Test
  public void testGetPacketWithTransportPacket() {
    Packet wholePacket = getWholePacket();
    TransportPacket tPacket = wholePacket.get(TransportPacket.class);
    assertNotNull(tPacket);
    assertEquals(0, tPacket.getHeader().getDstPort().compareTo(dstPort));
    assertEquals(0, tPacket.getHeader().getSrcPort().compareTo(srcPort));
  }
}
