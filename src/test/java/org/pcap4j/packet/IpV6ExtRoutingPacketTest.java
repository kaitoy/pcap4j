package org.pcap4j.packet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;
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
import java.util.ArrayList;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV6ExtRoutingPacket.IpV6ExtRoutingHeader;
import org.pcap4j.packet.IpV6ExtRoutingPacket.IpV6RoutingData;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpV6RoutingHeaderType;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito
 *
 */
public class IpV6ExtRoutingPacketTest {

  private static final Logger logger
    = LoggerFactory.getLogger(IpV6ExtRoutingPacketTest.class);

  private final IpNumber nextHeader;
  private final byte hdrExtLen;
  private final IpV6RoutingHeaderType routingType;
  private final byte segmentsLeft;
  private final IpV6RoutingData data;
  private final IpV6ExtRoutingPacket packet;

  private final Inet6Address srcAddr;
  private final Inet6Address dstAddr;

  public IpV6ExtRoutingPacketTest() throws Exception {
    this.nextHeader = IpNumber.UDP;
    this.hdrExtLen = (byte)6;
    this.routingType = IpV6RoutingHeaderType.SOURCE_ROUTE;
    this.segmentsLeft = (byte)2;

    try {
      srcAddr
        = (Inet6Address)InetAddress.getByName("aa:bb:cc::3:2:1");
      dstAddr
        = (Inet6Address)InetAddress.getByName("aa:bb:cc::3:2:2");
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    ArrayList<Inet6Address> addresses = new ArrayList<Inet6Address>(3);
    addresses.add((Inet6Address)Inet6Address.getByName("abcd:ef::1:1:1"));
    addresses.add((Inet6Address)Inet6Address.getByName("abcd:ef::2:2:2"));
    addresses.add(dstAddr);
    this.data = new IpV6RoutingSourceRouteData(54321, addresses);

    UnknownPacket.Builder anonb = new UnknownPacket.Builder();
    anonb.rawData(new byte[] { (byte)0, (byte)1, (byte)2, (byte)3 });

    UdpPacket.Builder udpb = new UdpPacket.Builder();
    udpb.dstPort(UdpPort.getInstance((short)0))
        .srcPort(UdpPort.SNMP_TRAP)
        .dstAddr(dstAddr)
        .srcAddr(srcAddr)
        .payloadBuilder(anonb)
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true);

    IpV6ExtRoutingPacket.Builder b
      = new IpV6ExtRoutingPacket.Builder();
    b.nextHeader(nextHeader)
     .hdrExtLen(hdrExtLen)
     .routingType(routingType)
     .segmentsLeft(segmentsLeft)
     .data(data)
     .correctLengthAtBuild(false)
     .payloadBuilder(udpb);

    this.packet = b.build();
  }

  /**
   * @throws java.lang.Exception
   */
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
      "########## " + IpV6ExtRoutingPacketTest.class.getSimpleName() + " START ##########"
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
   * {@link org.pcap4j.packet.IpV6ExtRoutingPacket#getBuilder()} のためのテスト・メソッド。
   */
  @Test
  public void testGetBuilder() {
    IpV6ExtRoutingPacket.Builder builder = packet.getBuilder();
    assertEquals(packet, builder.build());
  }

  /**
   * {@link org.pcap4j.packet.IpV6ExtRoutingPacket#newPacket(byte[])} のためのテスト・メソッド。
   */
  @Test
  public void testNewPacket() {
    IpV6ExtRoutingPacket p
      = IpV6ExtRoutingPacket.newPacket(packet.getRawData());
    assertEquals(packet, p);
  }

  /**
   * {@link org.pcap4j.packet.IpV6ExtRoutingPacket#getHeader()} のためのテスト・メソッド。
   */
  @Test
  public void testGetHeader() {
    IpV6ExtRoutingHeader h = packet.getHeader();
    assertEquals(nextHeader, h.getNextHeader());
    assertEquals(routingType, h.getRoutingType());
    assertEquals(segmentsLeft, h.getSegmentsLeft());
    assertEquals(data, h.getData());

    IpV6ExtRoutingPacket.Builder b = packet.getBuilder();
    IpV6ExtRoutingPacket p;

    b.hdrExtLen((byte)0);
    b.segmentsLeft((byte)0);
    p = b.build();
    assertEquals((byte)0, (byte)p.getHeader().getHdrExtLenAsInt());
    assertEquals((byte)0, (byte)p.getHeader().getSegmentsLeftAsInt());

    b.hdrExtLen((byte)-1);
    b.segmentsLeft((byte)-1);
    p = b.build();
    assertEquals((byte)-1, (byte)p.getHeader().getHdrExtLenAsInt());
    assertEquals((byte)-1, (byte)p.getHeader().getSegmentsLeftAsInt());

    b.hdrExtLen((byte)127);
    b.segmentsLeft((byte)127);
    p = b.build();
    assertEquals((byte)127, (byte)p.getHeader().getHdrExtLenAsInt());
    assertEquals((byte)127, (byte)p.getHeader().getSegmentsLeftAsInt());

    b.hdrExtLen((byte)-128);
    b.segmentsLeft((byte)-128);
    p = b.build();
    assertEquals((byte)-128, (byte)p.getHeader().getHdrExtLenAsInt());
    assertEquals((byte)-128, (byte)p.getHeader().getSegmentsLeftAsInt());
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
         .nextHeader(IpNumber.IPV6_ROUTE)
         .hopLimit((byte)100)
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
