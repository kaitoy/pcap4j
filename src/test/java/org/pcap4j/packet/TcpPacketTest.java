package org.pcap4j.packet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito
 *
 */
public class TcpPacketTest {

  private static final Logger logger
    = LoggerFactory.getLogger(TcpPacketTest.class);

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
    this.dstPort = TcpPort.getInstance((short)0);
    this.sequenceNumber = 1234567;
    this.acknowledgmentNumber = 7654321;
    this.dataOffset = 7;
    this.reserved = (byte)11;
    this.urg = false;
    this.ack = true;
    this.psh = false;
    this.rst = true;
    this.syn = false;
    this.fin = true;
    this.window = (short)9999;
    this.checksum = (short)0xABCD;
    this.urgentPointer = (short)1111;

    this.options = new ArrayList<TcpOption>();
    options.add(
      new TcpMaximumSegmentSizeOption.Builder()
        .maxSegSize((short)5555)
        .correctLengthAtBuild(true)
        .build()
    );
    options.add(TcpNoOperationOption.getInstance());
    options.add(TcpNoOperationOption.getInstance());
    options.add(TcpEndOfOptionList.getInstance());

    this.padding = new byte[] { (byte)0xEE };

    try {
      this.srcAddr
        = (Inet4Address)InetAddress.getByName("192.168.0.1");
      this.dstAddr
        = (Inet4Address)InetAddress.getByName("192.168.0.2");
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    UnknownPacket.Builder unknownb = new UnknownPacket.Builder();
    unknownb.rawData(new byte[] { (byte)0, (byte)1, (byte)2, (byte)3 });

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

  /**
   * @throws java.lang.Exception
   */
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
      "########## " + TcpPacketTest.class.getSimpleName() + " START ##########"
    );
  }

  /**
   * @throws java.lang.Exception
   */
  @AfterClass
  public static void tearDownAfterClass() throws Exception {
  }

  /**
   * @throws java.lang.Exception
   */
  @Before
  public void setUp() throws Exception {
  }

  /**
   * @throws java.lang.Exception
   */
  @After
  public void tearDown() throws Exception {
    logger.info(
      "=================================================="
    );
  }

  /**
   * {@link org.pcap4j.packet.TcpPacket#getBuilder()} のためのテスト・メソッド。
   */
  @Test
  public void testGetBuilder() {
    TcpPacket.Builder builder = packet.getBuilder();
    assertEquals(packet, builder.build());
  }

  /**
   * {@link org.pcap4j.packet.TcpPacket#newPacket(byte[])} のためのテスト・メソッド。
   */
  @Test
  public void testNewPacket() {
    TcpPacket p = TcpPacket.newPacket(packet.getRawData());
    assertEquals(packet, p);
  }

  /**
   * {@link org.pcap4j.packet.TcpPacket#getHeader()} のためのテスト・メソッド。
   */
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
    for (TcpOption o: options) {
      TcpOption actual = iter.next();
      assertEquals(o, actual);
    }

    assertArrayEquals(padding, h.getPadding());

    TcpPacket.Builder b = packet.getBuilder();
    TcpPacket p;

    b.sequenceNumber(0);
    b.acknowledgmentNumber(0);
    b.window((short)0);
    b.urgentPointer((short)0);
    p = b.build();
    assertEquals(0, (int)p.getHeader().getSequenceNumberAsLong());
    assertEquals(0, (int)p.getHeader().getAcknowledgmentNumberAsLong());
    assertEquals((short)0, (short)p.getHeader().getWindowAsInt());
    assertEquals((short)0, (short)p.getHeader().getUrgentPointerAsInt());

    b.sequenceNumber(-1);
    b.acknowledgmentNumber(-1);
    b.window((short)-1);
    b.urgentPointer((short)-1);
    p = b.build();
    assertEquals(-1, (int)p.getHeader().getSequenceNumberAsLong());
    assertEquals(-1, (int)p.getHeader().getAcknowledgmentNumberAsLong());
    assertEquals((short)-1, (short)p.getHeader().getWindowAsInt());
    assertEquals((short)-1, (short)p.getHeader().getUrgentPointerAsInt());

    b.sequenceNumber(-2147483648);
    b.acknowledgmentNumber(-2147483648);
    b.window((short)-32768);
    b.urgentPointer((short)-32768);
    p = b.build();
    assertEquals(-2147483648, (int)p.getHeader().getSequenceNumberAsLong());
    assertEquals(-2147483648, (int)p.getHeader().getAcknowledgmentNumberAsLong());
    assertEquals((short)-32768, (short)p.getHeader().getWindowAsInt());
    assertEquals((short)-32768, (short)p.getHeader().getUrgentPointerAsInt());

    b.sequenceNumber(2147483647);
    b.acknowledgmentNumber(2147483647);
    b.window((short)32767);
    b.urgentPointer((short)32767);
    p = b.build();
    assertEquals(2147483647, (int)p.getHeader().getSequenceNumberAsLong());
    assertEquals(2147483647, (int)p.getHeader().getAcknowledgmentNumberAsLong());
    assertEquals((short)32767, (short)p.getHeader().getWindowAsInt());
    assertEquals((short)32767, (short)p.getHeader().getUrgentPointerAsInt());

    b.dataOffset((byte)0);
    p = b.build();
    assertEquals((byte)0, p.getHeader().getDataOffset());

    b.dataOffset((byte)15);
    p = b.build();
    assertEquals((byte)15, p.getHeader().getDataOffset());

    b.dataOffset((byte)16);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {}

    b.dataOffset((byte)-1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {}

    b.dataOffset((byte)0);

    b.reserved((byte)0);
    p = b.build();
    assertEquals((byte)0, p.getHeader().getReserved());

    b.reserved((byte)63);
    p = b.build();
    assertEquals((byte)63, p.getHeader().getReserved());

    b.reserved((byte)64);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {}

    b.reserved((byte)-1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {}

    b.reserved((byte)0);
  }

  @Test
  public void testHasValidChecksum() {
    TcpPacket.Builder b = packet.getBuilder();
    b.srcAddr(srcAddr).dstAddr(dstAddr);
    TcpPacket p = b.correctChecksumAtBuild(false).build();

    assertFalse(packet.hasValidChecksum(srcAddr, dstAddr, false));
    assertFalse(packet.hasValidChecksum(srcAddr, dstAddr, true));

    b.checksum((short)0).correctChecksumAtBuild(false);
    p = b.build();
    assertFalse(p.hasValidChecksum(srcAddr, dstAddr, false));
    assertTrue(p.hasValidChecksum(srcAddr, dstAddr, true));

    b.correctChecksumAtBuild(true);
    p = b.build();
    assertTrue(p.hasValidChecksum(srcAddr, dstAddr, false));
    assertTrue(p.hasValidChecksum(srcAddr, dstAddr, true));
  }

  /**
   * {@link org.pcap4j.packet.AbstractPacket#length()} のためのテスト・メソッド。
   */
  @Test
  public void testLength() {
    assertEquals(packet.getRawData().length, packet.length());
  }

  /**
   * {@link org.pcap4j.packet.AbstractPacket#toString()} のためのテスト・メソッド。
   */
  @Test
  public void testToString() throws Exception {
    logger.info(packet.toString());
    FileReader fr
      = new FileReader(
          "src/test/resources/" + getClass().getSimpleName() + ".log"
        );
    BufferedReader fbr = new BufferedReader(fr);
    StringReader sr = new StringReader(packet.toString());
    BufferedReader sbr = new BufferedReader(sr);

    String line;
    while ((line = fbr.readLine()) != null) {
      assertEquals(line, sbr.readLine());
    }

    assertNull(sbr.readLine());

    fbr.close();
    fr.close();
    sr.close();
    sbr.close();
  }

  @Test
  public void testDump() throws Exception {
    String dumpFile = "test/" + this.getClass().getSimpleName() + ".pcap";

    IpV4Packet.Builder IpV4b = new IpV4Packet.Builder();
    IpV4b.version(IpVersion.IPV4)
         .tos(IpV4Rfc791Tos.newInstance((byte)0))
         .identification((short)100)
         .ttl((byte)100)
         .protocol(IpNumber.TCP)
         .srcAddr(srcAddr)
         .dstAddr(dstAddr)
         .payloadBuilder(
            packet.getBuilder()
              .correctChecksumAtBuild(true)
              .correctLengthAtBuild(true)
              .paddingAtBuild(true)
          )
         .correctChecksumAtBuild(true)
         .correctLengthAtBuild(true)
         .paddingAtBuild(true);

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
      .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
      .type(EtherType.IPV4)
      .payloadBuilder(IpV4b)
      .paddingAtBuild(true);

    eb.get(TcpPacket.Builder.class)
      .dstAddr(dstAddr)
      .srcAddr(srcAddr);

    EthernetPacket ep = eb.build();

    PcapHandle handle = Pcaps.openDead(DataLinkType.EN10MB, 65536);
    PcapDumper dumper = handle.dumpOpen(dumpFile);
    dumper.dump(ep, 0, 0);
    dumper.close();
    handle.close();

    PcapHandle reader = Pcaps.openOffline(dumpFile);
    assertEquals(ep, reader.getNextPacket());
    reader.close();

    FileInputStream in1
      = new FileInputStream(
          "src/test/resources/" + getClass().getSimpleName() + ".pcap"
        );
    FileInputStream in2 = new FileInputStream(dumpFile);

    byte[] buffer1 = new byte[100];
    byte[] buffer2 = new byte[100];
    int size;
    while ((size = in1.read(buffer1)) != -1) {
      assertEquals(size, in2.read(buffer2));
      assertArrayEquals(buffer1, buffer2);
    }

    in1.close();
    in2.close();
  }

  @Test
  public void testWriteRead() throws Exception {
    String objFile = "test/" + this.getClass().getSimpleName() + ".obj";

    ObjectOutputStream oos
      = new ObjectOutputStream(
          new FileOutputStream(new File(objFile))
        );
    oos.writeObject(packet);
    oos.close();

    ObjectInputStream ois
      = new ObjectInputStream(new FileInputStream(new File(objFile)));
    assertEquals(packet, ois.readObject());
    ois.close();
    FileInputStream in1
      = new FileInputStream(
          "src/test/resources/" + getClass().getSimpleName() + ".obj"
        );
    FileInputStream in2 = new FileInputStream(objFile);

    byte[] buffer1 = new byte[100];
    byte[] buffer2 = new byte[100];
    int size;
    while ((size = in1.read(buffer1)) != -1) {
      assertEquals(size, in2.read(buffer2));
      assertArrayEquals(buffer1, buffer2);
    }

    in1.close();
    in2.close();
  }

}
