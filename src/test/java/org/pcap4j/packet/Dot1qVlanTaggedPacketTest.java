package org.pcap4j.packet;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringReader;
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
import org.pcap4j.packet.Dot1qVlanTagPacket.Dot1qVlanTagHeader;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito
 *
 */
public class Dot1qVlanTaggedPacketTest {

  private static final Logger logger
    = LoggerFactory.getLogger(Dot1qVlanTaggedPacketTest.class);

  private final Dot1qVlanTagPacket packet;
  private final byte priority;
  private final boolean cfi;
  private final short vid;
  private final EtherType type;

  public Dot1qVlanTaggedPacketTest() {
    ArpPacket.Builder ab = new ArpPacket.Builder();
    try {
      ab.hardwareType(ArpHardwareType.ETHERNET)
        .protocolType(EtherType.IPV4)
        .hardwareLength((byte)MacAddress.SIZE_IN_BYTES)
        .protocolLength((byte)ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
        .srcHardwareAddr(MacAddress.getByName("fe:00:00:00:00:01"))
        .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
        .srcProtocolAddr(
           InetAddress.getByAddress(
             new byte[] { (byte)192, (byte)0, (byte)2, (byte)1 }
           )
         )
        .dstProtocolAddr(
           InetAddress.getByAddress(
             new byte[] { (byte)192, (byte)0, (byte)2, (byte)2 }
           )
         )
        .operation(ArpOperation.REQUEST);
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    this.priority = (byte)3;
    this.cfi = false;
    this.vid = (short)123;
    this.type = EtherType.ARP;

    Dot1qVlanTagPacket.Builder db = new Dot1qVlanTagPacket.Builder();
    db.priority(priority)
      .cfi(cfi)
      .vid(vid)
      .type(type)
      .payloadBuilder(ab);
    this.packet = db.build();
  }

  /**
   * @throws java.lang.Exception
   */
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
      "########## " + Dot1qVlanTaggedPacketTest.class.getSimpleName() + " START ##########"
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
   * {@link org.pcap4j.packet.Dot1qVlanTagPacket#getBuilder()} のためのテスト・メソッド。
   */
  @Test
  public void testGetBuilder() {
    Dot1qVlanTagPacket.Builder b = packet.getBuilder();
    assertEquals(packet, b.build());
  }

  /**
   * {@link org.pcap4j.packet.Dot1qVlanTagPacket#newPacket(byte[])} のためのテスト・メソッド。
   */
  @Test
  public void testNewPacket() {
    Dot1qVlanTagPacket p = Dot1qVlanTagPacket.newPacket(packet.getRawData());
    assertEquals(packet, p);
  }

  /**
   * {@link org.pcap4j.packet.Dot1qVlanTagPacket#getHeader()} のためのテスト・メソッド。
   */
  @Test
  public void testGetHeader() {
    Dot1qVlanTagHeader h = packet.getHeader();
    assertEquals(priority, h.getPriority());
    assertEquals(cfi, h.getCfi());
    assertEquals(vid, h.getVid());
    assertEquals(type, h.getType());

    Dot1qVlanTagPacket.Builder b = packet.getBuilder();
    Dot1qVlanTagPacket p;

    b.vid((short)0);
    p = b.build();
    assertEquals((short)0, (short)p.getHeader().getVidAsInt());

    b.vid((short)1000);
    p = b.build();
    assertEquals((short)1000, (short)p.getHeader().getVidAsInt());

    b.vid((short)4095);
    p = b.build();
    assertEquals((short)4095, (short)p.getHeader().getVidAsInt());

    b.vid((short)4096);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {}

    b.vid((short)-1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {}

    b.vid((short)100);

    b.priority((byte)-1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {}

    b.priority((byte)0);
    try {
      p = b.build();
    } catch (IllegalArgumentException e) {
      fail();
    }

    b.priority((byte)7);
    try {
      p = b.build();
    } catch (IllegalArgumentException e) {
      fail();
    }

    b.priority((byte)8);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {}
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

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(((ArpPacket)packet.getPayload()).getHeader().getDstHardwareAddr())
      .srcAddr(((ArpPacket)packet.getPayload()).getHeader().getSrcHardwareAddr())
      .type(EtherType.DOT1Q_VLAN_TAGGED_FRAMES)
      .payloadBuilder(new SimpleBuilder(packet))
      .paddingAtBuild(true);
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
