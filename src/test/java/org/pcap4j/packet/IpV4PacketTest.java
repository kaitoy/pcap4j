package org.pcap4j.packet;

import static org.junit.Assert.*;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.StringReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.IpV4Packet.IpV4Tos;
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

  private static final Logger logger
    = LoggerFactory.getLogger(IpV4PacketTest.class);

  private final IpVersion version;
  private final byte ihl;
  private final IpV4Tos tos;
  private final short totalLength;
  private final short identification;
  private final boolean reservedFlag;
  private final boolean dontFragmentFlag;
  private final boolean moreFragmentFlag;
  private final short flagmentOffset;
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
    this.ihl = (byte)9;
    this.tos = IpV4Rfc1349Tos.newInstance((byte)0x75);
    this.totalLength = (short)44;
    this.identification = (short)123;
    this.reservedFlag = true;
    this.dontFragmentFlag = false;
    this.moreFragmentFlag = true;
    this.flagmentOffset = (short)0;
    this.ttl = 111;
    this.protocol = IpNumber.UDP;
    this.headerChecksum = (short)0xEEEE;
    try {
      this.srcAddr
        = (Inet4Address)InetAddress.getByAddress(
            new byte[] { (byte)192, (byte)0, (byte)2, (byte)1 }
          );
      this.dstAddr
        = (Inet4Address)InetAddress.getByAddress(
            new byte[] { (byte)192, (byte)0, (byte)2, (byte)2 }
          );
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    List<Inet4Address> routeData = new ArrayList<Inet4Address>();
    routeData.add((Inet4Address)InetAddress.getByName("192.168.1.1"));
    routeData.add((Inet4Address)InetAddress.getByName("192.168.1.2"));
    IpV4LooseSourceRouteOption.Builder lsrrb = new IpV4LooseSourceRouteOption.Builder();
    lsrrb.pointer((byte)8)
         .routeData(routeData)
         .correctLengthAtBuild(true);
    this.options.add(lsrrb.build());
    this.options.add(IpV4NoOperationOption.getInstance());
    this.options.add(IpV4NoOperationOption.getInstance());
    this.options.add(IpV4NoOperationOption.getInstance());
    this.options.add(IpV4EndOfOptionList.getInstance());

    this.padding = new byte[] { (byte)0xAA };

    UnknownPacket.Builder unknownb = new UnknownPacket.Builder();
    unknownb.rawData(
      new byte[] {
        (byte)0, (byte)1, (byte)2, (byte)3,
        (byte)0, (byte)1, (byte)2, (byte)3
      }
    );

    UdpPacket.Builder udpb = new UdpPacket.Builder();
    udpb.srcPort(UdpPort.SNMP)
        .dstPort(UdpPort.getInstance((short)0))
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
     .flagmentOffset(flagmentOffset)
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
        new FragmentedPacket.Builder()
          .rawData(ByteArrays.getSubArray(rawPayload, 0, 8))
      );
    this.packet1 = b.build();

    b.flagmentOffset((short)1)
     .moreFragmentFlag(false)
     .payloadBuilder(
        new FragmentedPacket.Builder()
          .rawData(ByteArrays.getSubArray(rawPayload, 8, 8))
      );
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
    logger.info(
      "########## " + IpV4PacketTest.class.getSimpleName() + " START ##########"
    );
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
  }

  @Test
  public void testNewPacket() {
    IpV4Packet p = IpV4Packet.newPacket(packet1.getRawData());
    assertEquals(packet1, p);
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
    assertEquals(flagmentOffset, h.getFlagmentOffset());
    assertEquals(ttl, h.getTtl());
    assertEquals(protocol, h.getProtocol());
    assertEquals(headerChecksum, h.getHeaderChecksum());
    assertEquals(srcAddr, h.getSrcAddr());
    assertEquals(dstAddr, h.getDstAddr());
    assertEquals(options.size(), h.getOptions().size());

    Iterator<IpV4Option> iter = h.getOptions().iterator();
    for (IpV4Option expected: options) {
      IpV4Option actual = iter.next();
      assertEquals(expected, actual);
    }

    assertArrayEquals(padding, h.getPadding());

    IpV4Packet.Builder b = packet1.getBuilder();
    IpV4Packet p;

    b.ihl((byte)0);
    p = b.build();
    assertEquals((byte)0, p.getHeader().getIhl());

    b.ihl((byte)15);
    p = b.build();
    assertEquals((byte)15, p.getHeader().getIhl());

    b.ihl((byte)16);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {}

    b.ihl((byte)-1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {}

    b.ihl((byte)1);

    b.flagmentOffset((short)0);
    p = b.build();
    assertEquals((short)0, p.getHeader().getFlagmentOffset());

    b.flagmentOffset((short)8191);
    p = b.build();
    assertEquals((short)8191, p.getHeader().getFlagmentOffset());

    b.flagmentOffset((short)8192);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {}

    b.flagmentOffset((short)-1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {}

    b.flagmentOffset((short)0);

    b.totalLength((short)0);
    b.identification((short)0);
    b.ttl((byte)0);
    p = b.build();
    assertEquals((short)0, (short)p.getHeader().getTotalLengthAsInt());
    assertEquals((short)0, (short)p.getHeader().getIdentificationAsInt());
    assertEquals((byte)0, (byte)p.getHeader().getTtlAsInt());

    b.totalLength((short)32767);
    b.identification((short)32767);
    b.ttl((byte)127);
    p = b.build();
    assertEquals((short)32767, (short)p.getHeader().getTotalLengthAsInt());
    assertEquals((short)32767, (short)p.getHeader().getIdentificationAsInt());
    assertEquals((byte)127, (byte)p.getHeader().getTtlAsInt());

    b.totalLength((short)-1);
    b.identification((short)-1);
    b.ttl((byte)0);
    p = b.build();
    assertEquals((short)-1, (short)p.getHeader().getTotalLengthAsInt());
    assertEquals((short)-1, (short)p.getHeader().getIdentificationAsInt());
    assertEquals((byte)0, (byte)p.getHeader().getTtlAsInt());

    b.totalLength((short)-32768);
    b.identification((short)-32768);
    b.ttl((byte)-128);
    p = b.build();
    assertEquals((short)-32768, (short)p.getHeader().getTotalLengthAsInt());
    assertEquals((short)-32768, (short)p.getHeader().getIdentificationAsInt());
    assertEquals((byte)-128, (byte)p.getHeader().getTtlAsInt());
  }

  @Test
  public void testHasValidChecksum() {
    assertFalse(packet1.getHeader().hasValidChecksum(false));
    assertFalse(packet1.getHeader().hasValidChecksum(true));


    IpV4Packet.Builder b = packet1.getBuilder();
    IpV4Packet p;

    b.headerChecksum((short)0)
     .correctChecksumAtBuild(false);
    p = b.build();
    assertFalse(p.getHeader().hasValidChecksum(false));
    assertTrue(p.getHeader().hasValidChecksum(true));

    b.correctChecksumAtBuild(true);
    p = b.build();
    assertTrue(p.getHeader().hasValidChecksum(false));
    assertTrue(p.getHeader().hasValidChecksum(true));
  }

  @Test
  public void testLength() {
    assertEquals(packet1.getRawData().length, packet1.length());
  }

  @Test
  @Override
  public void testToString() throws Exception {
    FileReader fr
      = new FileReader(
          "src/test/resources/" + getClass().getSimpleName() + ".log"
        );
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
    String dumpFile = "test/" + this.getClass().getSimpleName() + ".pcap";

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
      .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
      .type(EtherType.IPV4)
      .payloadBuilder(
         packet1.getBuilder()
           .correctChecksumAtBuild(true)
           .correctLengthAtBuild(true)
           .paddingAtBuild(true)
       )
      .paddingAtBuild(true);
    EthernetPacket ep1 = eb.build();

    EthernetPacket ep2
      = eb.payloadBuilder(
             packet2.getBuilder()
               .correctChecksumAtBuild(true)
               .correctLengthAtBuild(true)
           )
          .build();

    PcapHandle handle = Pcaps.openDead(DataLinkType.EN10MB, 65536);
    PcapDumper dumper = handle.dumpOpen(dumpFile);
    dumper.dump(ep1, 0, 0);
    dumper.dump(ep2, 0, 0);
    dumper.close();
    handle.close();

    PcapHandle reader = Pcaps.openOffline(dumpFile);
    assertEquals(ep1, reader.getNextPacket());
    assertEquals(ep2, reader.getNextPacket());
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

}
