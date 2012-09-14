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
import java.net.Inet4Address;
import java.net.InetAddress;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IcmpV4CommonPacket.IcmpV4CommonHeader;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * @author Kaito
 *
 */
public class IcmpV4CommonPacketTest {

  private static final Logger logger
    = LoggerFactory.getLogger(IcmpV4CommonPacketTest.class);

  private final IcmpV4CommonPacket packet;
  private final IcmpV4Type type;
  private final IcmpV4Code code;
  private final short checksum;

  public IcmpV4CommonPacketTest() {
    UnknownPacket.Builder unknownb = new UnknownPacket.Builder();
    unknownb.rawData(new byte[] { (byte)0, (byte)1, (byte)2, (byte)3 });

    IcmpV4EchoPacket.Builder echob = new IcmpV4EchoPacket.Builder();
    echob.identifier((short)100)
         .sequenceNumber((short)10)
         .payloadBuilder(unknownb);

    this.type = IcmpV4Type.ECHO;
    this.code = IcmpV4Code.NO_CODE;
    this.checksum = (short)0x1234;

    IcmpV4CommonPacket.Builder b = new IcmpV4CommonPacket.Builder();
    b.type(type)
     .code(code)
     .checksum(checksum)
     .correctChecksumAtBuild(false)
     .payloadBuilder(echob);
    this.packet = b.build();
  }

  /**
   * @throws java.lang.Exception
   */
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
      "########## " + IcmpV4CommonPacketTest.class.getSimpleName() + " START ##########"
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
   * {@link org.pcap4j.packet.IcmpV4CommonPacket#getBuilder()} のためのテスト・メソッド。
   */
  @Test
  public void testGetBuilder() {
    IcmpV4CommonPacket.Builder b = packet.getBuilder();
    assertEquals(packet, b.build());
  }

  /**
   * {@link org.pcap4j.packet.IcmpV4CommonPacket#newPacket(byte[])} のためのテスト・メソッド。
   */
  @Test
  public void testNewPacket() {
    IcmpV4CommonPacket p = IcmpV4CommonPacket.newPacket(packet.getRawData());
    assertEquals(packet, p);
  }

  /**
   * {@link org.pcap4j.packet.IcmpV4CommonPacket#getHeader()} のためのテスト・メソッド。
   */
  @Test
  public void testGetHeader() {
    IcmpV4CommonHeader h = packet.getHeader();
    assertEquals(type, h.getType());
    assertEquals(code, h.getCode());
    assertEquals(checksum, h.getChecksum());
  }

  @Test
  public void testHasValidChecksum() {
    assertFalse(packet.hasValidChecksum(false));
    assertFalse(packet.hasValidChecksum(true));


    IcmpV4CommonPacket.Builder b = packet.getBuilder();
    IcmpV4CommonPacket p;

    b.checksum((short)0).correctChecksumAtBuild(false);
    p = b.build();
    assertFalse(p.hasValidChecksum(false));
    assertTrue(p.hasValidChecksum(true));

    b.correctChecksumAtBuild(true);
    p = b.build();
    assertTrue(p.hasValidChecksum(false));
    assertTrue(p.hasValidChecksum(true));
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

    IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
    ipv4b.version(IpVersion.IPV4)
         .tos(IpV4Rfc791Tos.newInstance((byte)0))
         .identification((short)100)
         .ttl((byte)100)
         .protocol(IpNumber.ICMPV4)
         .srcAddr(
            (Inet4Address)InetAddress.getByAddress(
              new byte[] { (byte)192, (byte)0, (byte)2, (byte)1 }
            )
          )
        .dstAddr(
           (Inet4Address)InetAddress.getByAddress(
             new byte[] { (byte)192, (byte)0, (byte)2, (byte)2 }
           )
         )
        .payloadBuilder(packet.getBuilder().correctChecksumAtBuild(true))
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true);

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
      .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
      .type(EtherType.IPV4)
      .payloadBuilder(ipv4b)
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
