package org.pcap4j.test.packet;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpEndOfOptionList;
import org.pcap4j.packet.TcpMaximumSegmentSizeOption.Builder;
import org.pcap4j.packet.TcpNoOperationOption;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.TcpSackOption;
import org.pcap4j.packet.TcpSackOption.Sack;
import org.pcap4j.packet.TcpSackPermittedOption;
import org.pcap4j.packet.TcpTimestampsOption;
import org.pcap4j.packet.TcpWindowScaleOption;
import org.pcap4j.packet.TransportPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class TcpPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(TcpPacketTest.class);

  private final TcpPort srcPort;
  private final TcpPort dstPort;
  private final int sequenceNumber;
  private final int acknowledgmentNumber;
  private final byte dataOffset;
  private final byte reserved;
  private final boolean urg;
  private final boolean ack;
  private final boolean psh;
  private final boolean rst;
  private final boolean syn;
  private final boolean fin;
  private final short window;
  private final short checksum;
  private final short urgentPointer;
  private final List<TcpOption> options;
  private final byte[] padding;
  private final Inet4Address srcAddr;
  private final Inet4Address dstAddr;
  private final TcpPacket packet;

  public TcpPacketTest() throws Exception {
    this.srcPort = TcpPort.SNMP;
    this.dstPort = TcpPort.getInstance((short) 0);
    this.sequenceNumber = 1234567;
    this.acknowledgmentNumber = 7654321;
    this.dataOffset = 15;
    this.reserved = (byte) 11;
    this.urg = false;
    this.ack = true;
    this.psh = false;
    this.rst = true;
    this.syn = false;
    this.fin = true;
    this.window = (short) 9999;
    this.checksum = (short) 0xABCD;
    this.urgentPointer = (short) 1111;

    this.options = new ArrayList<TcpOption>();
    options.add(new Builder().maxSegSize((short) 5555).correctLengthAtBuild(true).build());
    options.add(TcpNoOperationOption.getInstance());
    options.add(
        new TcpWindowScaleOption.Builder().shiftCount((byte) 2).correctLengthAtBuild(true).build());
    options.add(TcpSackPermittedOption.getInstance());
    options.add(
        new TcpTimestampsOption.Builder()
            .tsValue(200)
            .tsEchoReply(111)
            .correctLengthAtBuild(true)
            .build());
    List<Sack> sacks = new ArrayList<Sack>();
    sacks.add(new Sack(2000, 4000));
    sacks.add(new Sack(6000, 10000));
    options.add(new TcpSackOption.Builder().sacks(sacks).correctLengthAtBuild(true).build());
    options.add(TcpEndOfOptionList.getInstance());

    this.padding = new byte[] {(byte) 0xaa};

    try {
      this.srcAddr = (Inet4Address) InetAddress.getByName("192.168.0.1");
      this.dstAddr = (Inet4Address) InetAddress.getByName("192.168.0.2");
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    UnknownPacket.Builder unknownb = new UnknownPacket.Builder();
    unknownb.rawData(new byte[] {(byte) 0, (byte) 1, (byte) 2, (byte) 3});

    TcpPacket.Builder b = new TcpPacket.Builder();
    b.dstPort(dstPort)
        .srcPort(srcPort)
        .sequenceNumber(sequenceNumber)
        .acknowledgmentNumber(acknowledgmentNumber)
        .dataOffset(dataOffset)
        .reserved(reserved)
        .urg(urg)
        .ack(ack)
        .psh(psh)
        .rst(rst)
        .syn(syn)
        .fin(fin)
        .window(window)
        .checksum(checksum)
        .urgentPointer(urgentPointer)
        .options(options)
        .padding(padding)
        .correctChecksumAtBuild(false)
        .correctLengthAtBuild(false)
        .paddingAtBuild(false)
        .payloadBuilder(unknownb);

    this.packet = b.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    IpV4Packet.Builder IpV4b = new IpV4Packet.Builder();
    IpV4b.version(IpVersion.IPV4)
        .tos(IpV4Rfc1349Tos.newInstance((byte) 0))
        .identification((short) 100)
        .ttl((byte) 100)
        .protocol(IpNumber.TCP)
        .srcAddr(srcAddr)
        .dstAddr(dstAddr)
        .payloadBuilder(
            packet
                .getBuilder()
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .paddingAtBuild(true))
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true)
        .paddingAtBuild(true);

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
        .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
        .type(EtherType.IPV4)
        .payloadBuilder(IpV4b)
        .paddingAtBuild(true);

    eb.get(TcpPacket.Builder.class).dstAddr(dstAddr).srcAddr(srcAddr);
    return eb.build();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info("########## " + TcpPacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      TcpPacket p = TcpPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testNewPacketRandom() {
    RandomPacketTester.testClass(TcpPacket.class, packet);
  }

  @Test
  public void testGetHeader() {
    TcpHeader h = packet.getHeader();
    assertEquals(srcPort, h.getSrcPort());
    assertEquals(dstPort, h.getDstPort());
    assertEquals(sequenceNumber, h.getSequenceNumber());
    assertEquals(acknowledgmentNumber, h.getAcknowledgmentNumber());
    assertEquals(dataOffset, h.getDataOffset());
    assertEquals(reserved, h.getReserved());
    assertEquals(urg, h.getUrg());
    assertEquals(ack, h.getAck());
    assertEquals(psh, h.getPsh());
    assertEquals(rst, h.getRst());
    assertEquals(syn, h.getSyn());
    assertEquals(fin, h.getFin());
    assertEquals(window, h.getWindow());
    assertEquals(checksum, h.getChecksum());
    assertEquals(urgentPointer, h.getUrgentPointer());
    assertEquals(options.size(), h.getOptions().size());

    Iterator<TcpOption> iter = h.getOptions().iterator();
    for (TcpOption o : options) {
      TcpOption actual = iter.next();
      assertEquals(o, actual);
    }

    assertArrayEquals(padding, h.getPadding());

    TcpPacket.Builder b = packet.getBuilder();
    TcpPacket p;

    b.sequenceNumber(0);
    b.acknowledgmentNumber(0);
    b.window((short) 0);
    b.urgentPointer((short) 0);
    p = b.build();
    assertEquals(0, (int) p.getHeader().getSequenceNumberAsLong());
    assertEquals(0, (int) p.getHeader().getAcknowledgmentNumberAsLong());
    assertEquals((short) 0, (short) p.getHeader().getWindowAsInt());
    assertEquals((short) 0, (short) p.getHeader().getUrgentPointerAsInt());

    b.sequenceNumber(-1);
    b.acknowledgmentNumber(-1);
    b.window((short) -1);
    b.urgentPointer((short) -1);
    p = b.build();
    assertEquals(-1, (int) p.getHeader().getSequenceNumberAsLong());
    assertEquals(-1, (int) p.getHeader().getAcknowledgmentNumberAsLong());
    assertEquals((short) -1, (short) p.getHeader().getWindowAsInt());
    assertEquals((short) -1, (short) p.getHeader().getUrgentPointerAsInt());

    b.sequenceNumber(-2147483648);
    b.acknowledgmentNumber(-2147483648);
    b.window((short) -32768);
    b.urgentPointer((short) -32768);
    p = b.build();
    assertEquals(-2147483648, (int) p.getHeader().getSequenceNumberAsLong());
    assertEquals(-2147483648, (int) p.getHeader().getAcknowledgmentNumberAsLong());
    assertEquals((short) -32768, (short) p.getHeader().getWindowAsInt());
    assertEquals((short) -32768, (short) p.getHeader().getUrgentPointerAsInt());

    b.sequenceNumber(2147483647);
    b.acknowledgmentNumber(2147483647);
    b.window((short) 32767);
    b.urgentPointer((short) 32767);
    p = b.build();
    assertEquals(2147483647, (int) p.getHeader().getSequenceNumberAsLong());
    assertEquals(2147483647, (int) p.getHeader().getAcknowledgmentNumberAsLong());
    assertEquals((short) 32767, (short) p.getHeader().getWindowAsInt());
    assertEquals((short) 32767, (short) p.getHeader().getUrgentPointerAsInt());

    b.dataOffset((byte) 0);
    p = b.build();
    assertEquals((byte) 0, p.getHeader().getDataOffset());

    b.dataOffset((byte) 15);
    p = b.build();
    assertEquals((byte) 15, p.getHeader().getDataOffset());

    b.dataOffset((byte) 16);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }

    b.dataOffset((byte) -1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }

    b.dataOffset((byte) 0);

    b.reserved((byte) 0);
    p = b.build();
    assertEquals((byte) 0, p.getHeader().getReserved());

    b.reserved((byte) 63);
    p = b.build();
    assertEquals((byte) 63, p.getHeader().getReserved());

    b.reserved((byte) 64);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }

    b.reserved((byte) -1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }

    b.reserved((byte) 0);
  }

  @Test
  public void testHasValidChecksum() {
    TcpPacket.Builder b = packet.getBuilder();
    b.srcAddr(srcAddr).dstAddr(dstAddr);
    TcpPacket p = b.correctChecksumAtBuild(false).build();

    assertFalse(packet.hasValidChecksum(srcAddr, dstAddr, false));
    assertFalse(packet.hasValidChecksum(srcAddr, dstAddr, true));

    b.checksum((short) 0).correctChecksumAtBuild(false);
    p = b.build();
    assertFalse(p.hasValidChecksum(srcAddr, dstAddr, false));
    assertTrue(p.hasValidChecksum(srcAddr, dstAddr, true));

    b.correctChecksumAtBuild(true);
    p = b.build();
    assertTrue(p.hasValidChecksum(srcAddr, dstAddr, false));
    assertTrue(p.hasValidChecksum(srcAddr, dstAddr, true));
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
