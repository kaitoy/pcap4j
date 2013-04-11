/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/
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
import org.pcap4j.packet.EthernetPacket.EthernetHeader;
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
public class EthernetPacketTest {

  private static final Logger logger
    = LoggerFactory.getLogger(EthernetPacketTest.class);

  private final EthernetPacket packet;
  private final MacAddress dstAddr;
  private final MacAddress srcAddr;
  private final EtherType type;
  private final byte[] pad;

  public EthernetPacketTest() {
    this.dstAddr = MacAddress.ETHER_BROADCAST_ADDRESS;
    this.srcAddr = MacAddress.getByName("fe:00:00:00:00:01");
    this.type = EtherType.ARP;
    this.pad = new byte[] {
                 (byte)0, (byte)1, (byte)0, (byte)1, (byte)0, (byte)1,
                 (byte)0, (byte)1, (byte)0, (byte)1, (byte)0, (byte)1,
                 (byte)0, (byte)1, (byte)0, (byte)1, (byte)0, (byte)1,
                 (byte)0, (byte)1, (byte)0, (byte)1, (byte)0, (byte)1,
                 (byte)0, (byte)1, (byte)0, (byte)1, (byte)0, (byte)1,
               };


    ArpPacket.Builder ab = new ArpPacket.Builder();
    try {
      ab.hardwareType(ArpHardwareType.ETHERNET)
        .protocolType(EtherType.IPV4)
        .hardwareLength((byte)MacAddress.SIZE_IN_BYTES)
        .protocolLength((byte)ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
        .srcHardwareAddr(srcAddr)
        .dstHardwareAddr(dstAddr)
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

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(dstAddr)
      .srcAddr(srcAddr)
      .type(type)
      .payloadBuilder(ab)
      .pad(pad)
      .paddingAtBuild(false);
    this.packet = eb.build();
  }

  /**
   * @throws java.lang.Exception
   */
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
      "########## " + EthernetPacketTest.class.getSimpleName() + " START ##########"
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
   * {@link org.pcap4j.packet.EthernetPacket#getBuilder()} のためのテスト・メソッド。
   */
  @Test
  public void testGetBuilder() {
    EthernetPacket.Builder b = packet.getBuilder();
    assertEquals(packet, b.build());
  }

  /**
   * {@link org.pcap4j.packet.EthernetPacket#newPacket(byte[])} のためのテスト・メソッド。
   */
  @Test
  public void testNewPacket() {
    EthernetPacket p = EthernetPacket.newPacket(packet.getRawData());
    assertEquals(packet, p);
  }

  /**
   * {@link org.pcap4j.packet.EthernetPacket#getHeader()} のためのテスト・メソッド。
   */
  @Test
  public void testGetHeader() {
    EthernetHeader h = packet.getHeader();
    assertEquals(dstAddr, h.getDstAddr());
    assertEquals(srcAddr, h.getSrcAddr());
    assertEquals(type, h.getType());
    assertArrayEquals(pad, packet.getPad());
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

    PcapHandle handle = Pcaps.openDead(DataLinkType.EN10MB, 65536);
    PcapDumper dumper = handle.dumpOpen(dumpFile);
    dumper.dump(packet, 0, 0);
    dumper.close();
    handle.close();

    PcapHandle reader = Pcaps.openOffline(dumpFile);
    assertEquals(packet, reader.getNextPacket());
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
