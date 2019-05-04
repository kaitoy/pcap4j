package org.pcap4j.test.packet;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.StringReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.FragmentedPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4EndOfOptionList;
import org.pcap4j.packet.IpV4LooseSourceRouteOption.Builder;
import org.pcap4j.packet.IpV4NoOperationOption;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.IpV4Helper;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class IpV4PacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(IpV4PacketTest.class);

  private final IpVersion version;
  private final byte ihl;
  private final IpV4Tos tos;
  private final short totalLength;
  private final short identification;
  private final boolean reservedFlag;
  private final boolean dontFragmentFlag;
  private final boolean moreFragmentFlag;
  private final short fragmentOffset;
  private final byte ttl;
  private final IpNumber protocol;
  private final short headerChecksum;
  private final Inet4Address srcAddr;
  private final Inet4Address dstAddr;
  private final List<IpV4Option> options = new ArrayList<IpV4Option>();
  private final byte[] padding;
  private final IpV4Packet packet1;
  private final IpV4Packet packet2;

  public IpV4PacketTest() throws Exception {
    this.version = IpVersion.IPV4;
    this.ihl = (byte) 9;
    this.tos = IpV4Rfc1349Tos.newInstance((byte) 0x75);
    this.totalLength = (short) 44;
    this.identification = (short) 123;
    this.reservedFlag = true;
    this.dontFragmentFlag = false;
    this.moreFragmentFlag = true;
    this.fragmentOffset = (short) 0;
    this.ttl = 111;
    this.protocol = IpNumber.UDP;
    this.headerChecksum = (short) 0xEEEE;
    try {
      this.srcAddr =
          (Inet4Address)
              InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 0, (byte) 2, (byte) 1});
      this.dstAddr =
          (Inet4Address)
              InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 0, (byte) 2, (byte) 2});
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    List<Inet4Address> routeData = new ArrayList<Inet4Address>();
    routeData.add((Inet4Address) InetAddress.getByName("192.168.1.1"));
    routeData.add((Inet4Address) InetAddress.getByName("192.168.1.2"));
    Builder lsrrb = new Builder();
    lsrrb.pointer((byte) 8).routeData(routeData).correctLengthAtBuild(true);
    this.options.add(lsrrb.build());
    this.options.add(IpV4NoOperationOption.getInstance());
    this.options.add(IpV4NoOperationOption.getInstance());
    this.options.add(IpV4NoOperationOption.getInstance());
    this.options.add(IpV4EndOfOptionList.getInstance());

    this.padding = new byte[] {(byte) 0xAA};

    UnknownPacket.Builder unknownb = new UnknownPacket.Builder();
    unknownb.rawData(
        new byte[] {
          (byte) 0, (byte) 1, (byte) 2, (byte) 3,
          (byte) 0, (byte) 1, (byte) 2, (byte) 3
        });

    UdpPacket.Builder udpb = new UdpPacket.Builder();
    udpb.srcPort(UdpPort.SNMP)
        .dstPort(UdpPort.getInstance((short) 0))
        .srcAddr(srcAddr)
        .dstAddr(dstAddr)
        .payloadBuilder(unknownb)
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true);

    byte[] rawPayload = udpb.build().getRawData();

    IpV4Packet.Builder b = new IpV4Packet.Builder();
    b.version(version)
        .ihl(ihl)
        .tos(tos)
        .totalLength(totalLength)
        .identification(identification)
        .reservedFlag(reservedFlag)
        .dontFragmentFlag(dontFragmentFlag)
        .moreFragmentFlag(moreFragmentFlag)
        .fragmentOffset(fragmentOffset)
        .ttl(ttl)
        .protocol(protocol)
        .headerChecksum(headerChecksum)
        .srcAddr(srcAddr)
        .dstAddr(dstAddr)
        .options(options)
        .padding(padding)
        .correctChecksumAtBuild(false)
        .correctLengthAtBuild(false)
        .paddingAtBuild(false)
        .payloadBuilder(
            new FragmentedPacket.Builder().rawData(ByteArrays.getSubArray(rawPayload, 0, 8)));
    this.packet1 = b.build();

    b.fragmentOffset((short) 1)
        .moreFragmentFlag(false)
        .payloadBuilder(
            new FragmentedPacket.Builder().rawData(ByteArrays.getSubArray(rawPayload, 8, 8)));
    this.packet2 = b.build();
  }

  @Override
  protected Packet getPacket() {
    return packet1;
  }

  @Override
  protected Packet getWholePacket() {
    throw new UnsupportedOperationException();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info("########## " + IpV4PacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      IpV4Packet p = IpV4Packet.newPacket(packet1.getRawData(), 0, packet1.getRawData().length);
      assertEquals(packet1, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testNewPacketRandom() {
    RandomPacketTester.testClass(IpV4Packet.class, packet1);
  }

  @Test
  public void testGetHeader() {
    IpV4Header h = packet1.getHeader();
    assertEquals(version, h.getVersion());
    assertEquals(ihl, h.getIhl());
    assertEquals(tos, h.getTos());
    assertEquals(totalLength, h.getTotalLength());
    assertEquals(identification, h.getIdentification());
    assertEquals(reservedFlag, h.getReservedFlag());
    assertEquals(dontFragmentFlag, h.getDontFragmentFlag());
    assertEquals(moreFragmentFlag, h.getMoreFragmentFlag());
    assertEquals(fragmentOffset, h.getFragmentOffset());
    assertEquals(ttl, h.getTtl());
    assertEquals(protocol, h.getProtocol());
    assertEquals(headerChecksum, h.getHeaderChecksum());
    assertEquals(srcAddr, h.getSrcAddr());
    assertEquals(dstAddr, h.getDstAddr());
    assertEquals(options.size(), h.getOptions().size());

    Iterator<IpV4Option> iter = h.getOptions().iterator();
    for (IpV4Option expected : options) {
      IpV4Option actual = iter.next();
      assertEquals(expected, actual);
    }

    assertArrayEquals(padding, h.getPadding());

    IpV4Packet.Builder b = packet1.getBuilder();
    IpV4Packet p;

    b.ihl((byte) 0);
    p = b.build();
    assertEquals((byte) 0, p.getHeader().getIhl());

    b.ihl((byte) 15);
    p = b.build();
    assertEquals((byte) 15, p.getHeader().getIhl());

    b.ihl((byte) 16);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }

    b.ihl((byte) -1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }

    b.ihl((byte) 1);

    b.fragmentOffset((short) 0);
    p = b.build();
    assertEquals((short) 0, p.getHeader().getFragmentOffset());

    b.fragmentOffset((short) 8191);
    p = b.build();
    assertEquals((short) 8191, p.getHeader().getFragmentOffset());

    b.fragmentOffset((short) 8192);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }

    b.fragmentOffset((short) -1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }

    b.fragmentOffset((short) 0);

    b.totalLength((short) 0);
    b.identification((short) 0);
    b.ttl((byte) 0);
    p = b.build();
    assertEquals((short) 0, (short) p.getHeader().getTotalLengthAsInt());
    assertEquals((short) 0, (short) p.getHeader().getIdentificationAsInt());
    assertEquals((byte) 0, (byte) p.getHeader().getTtlAsInt());

    b.totalLength((short) 32767);
    b.identification((short) 32767);
    b.ttl((byte) 127);
    p = b.build();
    assertEquals((short) 32767, (short) p.getHeader().getTotalLengthAsInt());
    assertEquals((short) 32767, (short) p.getHeader().getIdentificationAsInt());
    assertEquals((byte) 127, (byte) p.getHeader().getTtlAsInt());

    b.totalLength((short) -1);
    b.identification((short) -1);
    b.ttl((byte) 0);
    p = b.build();
    assertEquals((short) -1, (short) p.getHeader().getTotalLengthAsInt());
    assertEquals((short) -1, (short) p.getHeader().getIdentificationAsInt());
    assertEquals((byte) 0, (byte) p.getHeader().getTtlAsInt());

    b.totalLength((short) -32768);
    b.identification((short) -32768);
    b.ttl((byte) -128);
    p = b.build();
    assertEquals((short) -32768, (short) p.getHeader().getTotalLengthAsInt());
    assertEquals((short) -32768, (short) p.getHeader().getIdentificationAsInt());
    assertEquals((byte) -128, (byte) p.getHeader().getTtlAsInt());
  }

  @Test
  public void testHasValidChecksum() {
    assertFalse(packet1.getHeader().hasValidChecksum(false));
    assertFalse(packet1.getHeader().hasValidChecksum(true));

    IpV4Packet.Builder b = packet1.getBuilder();
    IpV4Packet p;

    b.headerChecksum((short) 0).correctChecksumAtBuild(false);
    p = b.build();
    assertFalse(p.getHeader().hasValidChecksum(false));
    assertTrue(p.getHeader().hasValidChecksum(true));

    b.correctChecksumAtBuild(true);
    p = b.build();
    assertTrue(p.getHeader().hasValidChecksum(false));
    assertTrue(p.getHeader().hasValidChecksum(true));
  }

  @Override
  @Test
  public void testLength() {
    assertEquals(packet1.getRawData().length, packet1.length());
  }

  @Test
  @Override
  public void testToString() throws Exception {
    FileReader fr =
        new FileReader(
            new StringBuilder()
                .append(resourceDirPath)
                .append("/")
                .append(getClass().getSimpleName())
                .append(".log")
                .toString());
    BufferedReader fbr = new BufferedReader(fr);
    StringReader sr = new StringReader(packet1.toString());
    BufferedReader sbr = new BufferedReader(sr);

    String line;
    while ((line = sbr.readLine()) != null) {
      assertEquals(fbr.readLine(), line);
    }

    sr.close();
    sbr.close();

    sr = new StringReader(packet2.toString());
    sbr = new BufferedReader(sr);

    while ((line = sbr.readLine()) != null) {
      assertEquals(fbr.readLine(), line);
    }

    sr.close();
    sbr.close();

    List<IpV4Packet> list = new ArrayList<IpV4Packet>();
    list.add(packet1);
    list.add(packet2);
    sr = new StringReader(IpV4Helper.defragment(list).toString());
    sbr = new BufferedReader(sr);

    while ((line = sbr.readLine()) != null) {
      assertEquals(fbr.readLine(), line);
    }

    assertNull(sbr.readLine());

    fbr.close();
    fr.close();
    sr.close();
    sbr.close();
  }

  @Test
  @Override
  public void testDump() throws Exception {
    String dumpFile =
        new StringBuilder()
            .append(tmpDirPath)
            .append("/")
            .append(getClass().getSimpleName())
            .append(".pcap")
            .toString();

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
        .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
        .type(EtherType.IPV4)
        .payloadBuilder(
            packet1
                .getBuilder()
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .paddingAtBuild(true))
        .paddingAtBuild(true);
    EthernetPacket ep1 = eb.build();

    EthernetPacket ep2 =
        eb.payloadBuilder(
                packet2.getBuilder().correctChecksumAtBuild(true).correctLengthAtBuild(true))
            .build();

    PcapHandle handle = Pcaps.openDead(DataLinkType.EN10MB, 65536);
    PcapDumper dumper = handle.dumpOpen(dumpFile);
    Timestamp ts = new Timestamp(0);
    dumper.dump(ep1, ts);
    dumper.dump(ep2, ts);
    dumper.close();
    handle.close();

    PcapHandle reader = Pcaps.openOffline(dumpFile);
    assertEquals(ep1, reader.getNextPacket());
    assertEquals(ep2, reader.getNextPacket());
    reader.close();

    FileInputStream in1 =
        new FileInputStream(
            new StringBuilder()
                .append(resourceDirPath)
                .append("/")
                .append(getClass().getSimpleName())
                .append(".pcap")
                .toString());
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
}
