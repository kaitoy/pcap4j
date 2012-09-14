package org.pcap4j.packet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertArrayEquals;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringReader;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.UdpPacket.UdpHeader;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito
 *
 */
public class UdpPacketTest {

  private static final Logger logger
    = LoggerFactory.getLogger(UdpPacketTest.class);

  private final UdpPort srcPort;
  private final UdpPort dstPort;
  private final short length;
  private final short checksum;
  private final Inet6Address srcAddr;
  private final Inet6Address dstAddr;
  private final UdpPacket packet;

  public UdpPacketTest() throws Exception {
    this.srcPort = UdpPort.SNMP;
    this.dstPort = UdpPort.getInstance((short)0);
    this.length = (short)12;
    this.checksum = (short)0xABCD;
    try {
      this.srcAddr
        = (Inet6Address)InetAddress.getByName("aa:bb:cc::3:2:1");
      this.dstAddr
        = (Inet6Address)InetAddress.getByName("aa:bb:cc::3:2:2");
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    UnknownPacket.Builder unknownb = new UnknownPacket.Builder();
    unknownb.rawData(new byte[] { (byte)0, (byte)1, (byte)2, (byte)3 });

    UdpPacket.Builder b = new UdpPacket.Builder();
    b.dstPort(dstPort)
     .srcPort(srcPort)
     .length(length)
     .checksum(checksum)
     .correctChecksumAtBuild(false)
     .correctLengthAtBuild(false)
     .payloadBuilder(unknownb);

    this.packet = b.build();
  }

  /**
   * @throws java.lang.Exception
   */
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
      "########## " + UdpPacketTest.class.getSimpleName() + " START ##########"
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
   * {@link org.pcap4j.packet.UdpPacket#getBuilder()} のためのテスト・メソッド。
   */
  @Test
  public void testGetBuilder() {
    UdpPacket.Builder builder = packet.getBuilder();
    assertEquals(packet, builder.build());
  }

  /**
   * {@link org.pcap4j.packet.UdpPacket#newPacket(byte[])} のためのテスト・メソッド。
   */
  @Test
  public void testNewPacket() {
    UdpPacket p = UdpPacket.newPacket(packet.getRawData());
    assertEquals(packet, p);
  }

  /**
   * {@link org.pcap4j.packet.UdpPacket#getHeader()} のためのテスト・メソッド。
   */
  @Test
  public void testGetHeader() {
    UdpHeader h = packet.getHeader();
    assertEquals(srcPort, h.getSrcPort());
    assertEquals(dstPort, h.getDstPort());
    assertEquals(length, h.getLength());
    assertEquals(checksum, h.getChecksum());

    UdpPacket.Builder b = packet.getBuilder();
    UdpPacket p;

    b.length((short)0);
    p = b.build();
    assertEquals((short)0, (short)p.getHeader().getLengthAsInt());

    b.length((short)-1);
    p = b.build();
    assertEquals((short)-1, (short)p.getHeader().getLengthAsInt());

    b.length((short)32767);
    p = b.build();
    assertEquals((short)32767, (short)p.getHeader().getLengthAsInt());

    b.length((short)-32768);
    p = b.build();
    assertEquals((short)-32768, (short)p.getHeader().getLengthAsInt());
  }

  @Test
  public void testHasValidChecksum() {
    UdpPacket.Builder b = packet.getBuilder();
    b.srcAddr(srcAddr).dstAddr(dstAddr);
    UdpPacket p = b.correctChecksumAtBuild(false).build();

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

    IpV6Packet.Builder IpV6b = new IpV6Packet.Builder();
    IpV6b.version(IpVersion.IPV6)
         .trafficClass(IpV6SimpleTrafficClass.newInstance((byte)0x12))
         .flowLabel(IpV6SimpleFlowLabel.newInstance(0x12345))
         .nextHeader(IpNumber.UDP)
         .hopLimit((byte)100)
         .srcAddr(srcAddr)
         .dstAddr(dstAddr)
         .payloadBuilder(
            packet.getBuilder()
              .correctChecksumAtBuild(true)
              .correctLengthAtBuild(true)
          )
         .correctLengthAtBuild(true);

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
      .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
      .type(EtherType.IPV6)
      .payloadBuilder(IpV6b)
      .paddingAtBuild(true);

    eb.get(UdpPacket.Builder.class)
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
