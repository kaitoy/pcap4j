package org.pcap4j.packet;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
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
import org.pcap4j.packet.ArpPacket.ArpHeader;
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
public class ArpPacketTest {

  private static final Logger logger
    = LoggerFactory.getLogger(ArpPacketTest.class);

  private final ArpPacket packet;
  private final ArpHardwareType hardwareType;
  private final EtherType protocolType;
  private final byte hardwareLength;
  private final byte protocolLength;
  private final MacAddress srcHardwareAddr;
  private final MacAddress dstHardwareAddr;
  private final InetAddress srcProtocolAddr;
  private final InetAddress dstProtocolAddr;
  private final ArpOperation operation;

  public ArpPacketTest() {
    this.hardwareType = ArpHardwareType.ETHERNET;
    this.protocolType = EtherType.IPV4;
    this.hardwareLength = (byte)MacAddress.SIZE_IN_BYTES;
    this.protocolLength = (byte)ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES;
    this.srcHardwareAddr = MacAddress.getByName("fe:00:00:00:00:01");
    this.dstHardwareAddr = MacAddress.ETHER_BROADCAST_ADDRESS;
    try {
      this.srcProtocolAddr
        = InetAddress.getByAddress(
            new byte[] { (byte)192, (byte)0, (byte)2, (byte)1 }
          );
      this.dstProtocolAddr
        = InetAddress.getByAddress(
            new byte[] { (byte)192, (byte)0, (byte)2, (byte)2 }
          );
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }
    this.operation = ArpOperation.REQUEST;

    ArpPacket.Builder ab = new ArpPacket.Builder();
    ab.hardwareType(hardwareType)
      .protocolType(protocolType)
      .hardwareLength(hardwareLength)
      .protocolLength(protocolLength)
      .srcHardwareAddr(srcHardwareAddr)
      .dstHardwareAddr(dstHardwareAddr)
      .srcProtocolAddr(srcProtocolAddr)
      .dstProtocolAddr(dstProtocolAddr)
      .operation(operation);
    this.packet = ab.build();
  }

  /**
   * @throws java.lang.Exception
   */
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
      "########## " + ArpPacketTest.class.getSimpleName() + " START ##########"
    );
  }

  /**
   * @throws java.lang.Exception
   */
  @AfterClass
  public static void tearDownAfterClass() throws Exception {
    logger.info(
      "########## " + ArpPacketTest.class.getSimpleName() + " END ##########"
    );
  }

  /**
   * @throws java.lang.Exception
   */
  @Before
  public void setUp() throws Exception {}

  /**
   * @throws java.lang.Exception
   */
  @After
  public void tearDown() throws Exception {
    logger.info(
      "=================================================="
    );
  }

  @Test
  public void testGetHeader() {
    ArpHeader h = packet.getHeader();
    assertEquals(hardwareType, h.getHardwareType());
    assertEquals(protocolType, h.getProtocolType());
    assertEquals(hardwareLength, h.getHardwareLength());
    assertEquals(hardwareLength, (byte)h.getHardwareLengthAsInt());
    assertEquals(protocolLength, h.getProtocolLength());
    assertEquals(protocolLength, (byte)h.getProtocolLengthAsInt());
    assertEquals(dstHardwareAddr, h.getDstHardwareAddr());
    assertEquals(srcHardwareAddr, h.getSrcHardwareAddr());
    assertEquals(dstProtocolAddr, h.getDstProtocolAddr());
    assertEquals(srcProtocolAddr, h.getSrcProtocolAddr());
    assertEquals(operation, h.getOperation());

    ArpPacket.Builder ab = packet.getBuilder();
    ArpPacket p;

    ab.hardwareLength((byte)0);
    ab.protocolLength((byte)0);
    p = ab.build();
    assertEquals((byte)0, (byte)p.getHeader().getHardwareLengthAsInt());
    assertEquals((byte)0, (byte)p.getHeader().getProtocolLengthAsInt());

    ab.hardwareLength((byte)50);
    ab.protocolLength((byte)50);
    p = ab.build();
    assertEquals((byte)50, (byte)p.getHeader().getHardwareLengthAsInt());
    assertEquals((byte)50, (byte)p.getHeader().getProtocolLengthAsInt());

    ab.hardwareLength((byte)127);
    ab.protocolLength((byte)127);
    p = ab.build();
    assertEquals((byte)127, (byte)p.getHeader().getHardwareLengthAsInt());
    assertEquals((byte)127, (byte)p.getHeader().getProtocolLengthAsInt());

    ab.hardwareLength((byte)-1);
    ab.protocolLength((byte)-1);
    p = ab.build();
    assertEquals((byte)-1, (byte)p.getHeader().getHardwareLengthAsInt());
    assertEquals((byte)-1, (byte)p.getHeader().getProtocolLengthAsInt());

    ab.hardwareLength((byte)-128);
    ab.protocolLength((byte)-128);
    p = ab.build();
    assertEquals((byte)-128, (byte)p.getHeader().getHardwareLengthAsInt());
    assertEquals((byte)-128, (byte)p.getHeader().getProtocolLengthAsInt());
  }

  /**
   * {@link org.pcap4j.packet.ArpPacket#getBuilder()} のためのテスト・メソッド。
   */
  @Test
  public void testGetBuilder() {
    ArpPacket.Builder ab = packet.getBuilder();
    assertEquals(packet, ab.build());
  }

  /**
   * {@link org.pcap4j.packet.ArpPacket#newPacket(byte[])} のためのテスト・メソッド。
   */
  @Test
  public void testNewPacket() {
    ArpPacket p = ArpPacket.newPacket(packet.getRawData());
    assertEquals(packet, p);
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
   * @throws Exception
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
    eb.dstAddr(packet.getHeader().getDstHardwareAddr())
      .srcAddr(packet.getHeader().getSrcHardwareAddr())
      .type(EtherType.ARP)
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
