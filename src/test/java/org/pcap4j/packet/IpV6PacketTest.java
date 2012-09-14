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
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV6Packet.IpV6FlowLabel;
import org.pcap4j.packet.IpV6Packet.IpV6Header;
import org.pcap4j.packet.IpV6Packet.IpV6TrafficClass;
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
public class IpV6PacketTest {

  private static final Logger logger
    = LoggerFactory.getLogger(IpV6PacketTest.class);

  private final IpVersion version;
  private final IpV6TrafficClass trafficClass;
  private final IpV6FlowLabel flowLabel;
  private final short payloadLength;
  private final IpNumber nextHeader;
  private final byte hopLimit;
  private final Inet6Address srcAddr;
  private final Inet6Address dstAddr;
  private final IpV6Packet packet;

  public IpV6PacketTest() throws Exception {
    this.version = IpVersion.IPV6;
    this.trafficClass = IpV6SimpleTrafficClass.newInstance((byte)0x12);
    this.flowLabel = IpV6SimpleFlowLabel.newInstance(0x12345);
    this.payloadLength = (short)12;
    this.nextHeader = IpNumber.UDP;
    this.hopLimit = (byte)100;
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

    UdpPacket.Builder udpb = new UdpPacket.Builder();
    udpb.dstPort(UdpPort.getInstance((short)0))
        .srcPort(UdpPort.SNMP_TRAP)
        .dstAddr(dstAddr)
        .srcAddr(srcAddr)
        .payloadBuilder(unknownb)
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true);

    IpV6Packet.Builder b = new IpV6Packet.Builder();
    b.version(version)
     .trafficClass(trafficClass)
     .flowLabel(flowLabel)
     .payloadLength(payloadLength)
     .nextHeader(nextHeader)
     .hopLimit(hopLimit)
     .srcAddr(srcAddr)
     .dstAddr(dstAddr)
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
      "########## " + IpV6PacketTest.class.getSimpleName() + " START ##########"
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
   * {@link org.pcap4j.packet.IpV6Packet#getBuilder()} のためのテスト・メソッド。
   */
  @Test
  public void testGetBuilder() {
    IpV6Packet.Builder builder = packet.getBuilder();
    assertEquals(packet, builder.build());
  }

  /**
   * {@link org.pcap4j.packet.IpV6Packet#newPacket(byte[])} のためのテスト・メソッド。
   */
  @Test
  public void testNewPacket() {
    IpV6Packet p = IpV6Packet.newPacket(packet.getRawData());
    assertEquals(packet, p);
  }

  /**
   * {@link org.pcap4j.packet.IpV6Packet#getHeader()} のためのテスト・メソッド。
   */
  @Test
  public void testGetHeader() {
    IpV6Header h = packet.getHeader();
    assertEquals(version, h.getVersion());
    assertEquals(trafficClass, h.getTrafficClass());
    assertEquals(flowLabel, h.getFlowLabel());
    assertEquals(payloadLength, h.getPayloadLength());
    assertEquals(nextHeader, h.getNextHeader());
    assertEquals(hopLimit, h.getHopLimit());
    assertEquals(srcAddr, h.getSrcAddr());
    assertEquals(dstAddr, h.getDstAddr());

    IpV6Packet.Builder b = packet.getBuilder();
    IpV6Packet p;

    b.payloadLength((short)0);
    b.hopLimit((byte)0);
    p = b.build();
    assertEquals((short)0, (short)p.getHeader().getPayloadLengthAsInt());
    assertEquals((byte)0, (byte)p.getHeader().getHopLimitAsInt());

    b.payloadLength((short)-1);
    b.hopLimit((byte)-1);
    p = b.build();
    assertEquals((short)-1, (short)p.getHeader().getPayloadLengthAsInt());
    assertEquals((byte)-1, (byte)p.getHeader().getHopLimitAsInt());

    b.payloadLength((short)32767);
    b.hopLimit((byte)127);
    p = b.build();
    assertEquals((short)32767, (short)p.getHeader().getPayloadLengthAsInt());
    assertEquals((byte)127, (byte)p.getHeader().getHopLimitAsInt());

    b.payloadLength((short)-32768);
    b.hopLimit((byte)-128);
    p = b.build();
    assertEquals((short)-32768, (short)p.getHeader().getPayloadLengthAsInt());
    assertEquals((byte)-128, (byte)p.getHeader().getHopLimitAsInt());
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
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
      .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
      .type(EtherType.IPV6)
      .payloadBuilder(packet.getBuilder())
      .paddingAtBuild(true);

    eb.get(UdpPacket.Builder.class)
      .dstAddr(packet.getHeader().getDstAddr())
      .srcAddr(packet.getHeader().getSrcAddr());

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
