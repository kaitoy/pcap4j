package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtDestinationOptionsPacket;
import org.pcap4j.packet.IpV6ExtDestinationOptionsPacket.IpV6ExtDestinationOptionsHeader;
import org.pcap4j.packet.IpV6ExtOptionsPacket.IpV6Option;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.IpV6Pad1Option;
import org.pcap4j.packet.IpV6PadNOption.Builder;
import org.pcap4j.packet.IpV6SimpleFlowLabel;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class IpV6ExtDestinationOptionsPacketTest extends AbstractPacketTest {

  private static final Logger logger =
      LoggerFactory.getLogger(IpV6ExtDestinationOptionsPacketTest.class);

  private final IpNumber nextHeader;
  private final byte hdrExtLen;
  private final List<IpV6Option> options;
  private final IpV6ExtDestinationOptionsPacket packet;

  private final Inet6Address srcAddr;
  private final Inet6Address dstAddr;

  public IpV6ExtDestinationOptionsPacketTest() throws Exception {
    this.nextHeader = IpNumber.UDP;
    this.hdrExtLen = (byte) 0;
    this.options = new ArrayList<IpV6Option>();
    options.add(IpV6Pad1Option.getInstance());
    options.add(new Builder().data(new byte[] {0, 0, 0}).dataLen((byte) 3).build());

    try {
      srcAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:1");
      dstAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:2");
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    UnknownPacket.Builder anonb = new UnknownPacket.Builder();
    anonb.rawData(new byte[] {(byte) 0, (byte) 1, (byte) 2, (byte) 3});

    UdpPacket.Builder udpb = new UdpPacket.Builder();
    udpb.dstPort(UdpPort.getInstance((short) 0))
        .srcPort(UdpPort.SNMP_TRAP)
        .dstAddr(dstAddr)
        .srcAddr(srcAddr)
        .payloadBuilder(anonb)
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true);

    IpV6ExtDestinationOptionsPacket.Builder b = new IpV6ExtDestinationOptionsPacket.Builder();
    b.nextHeader(nextHeader)
        .hdrExtLen(hdrExtLen)
        .options(options)
        .correctLengthAtBuild(false)
        .payloadBuilder(udpb);

    this.packet = b.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    IpV6Packet.Builder IpV6b = new IpV6Packet.Builder();
    IpV6b.version(IpVersion.IPV6)
        .trafficClass(IpV6SimpleTrafficClass.newInstance((byte) 0x12))
        .flowLabel(IpV6SimpleFlowLabel.newInstance(0x12345))
        .nextHeader(IpNumber.IPV6_DST_OPTS)
        .hopLimit((byte) 100)
        .srcAddr(srcAddr)
        .dstAddr(dstAddr)
        .payloadBuilder(packet.getBuilder().correctLengthAtBuild(true))
        .correctLengthAtBuild(true);

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
        .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
        .type(EtherType.IPV6)
        .payloadBuilder(IpV6b)
        .paddingAtBuild(true);

    eb.get(UdpPacket.Builder.class).dstAddr(dstAddr).srcAddr(srcAddr);
    return eb.build();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
        "########## "
            + IpV6ExtDestinationOptionsPacketTest.class.getSimpleName()
            + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      IpV6ExtDestinationOptionsPacket p =
          IpV6ExtDestinationOptionsPacket.newPacket(
              packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testGetHeader() {
    IpV6ExtDestinationOptionsHeader h = packet.getHeader();
    assertEquals(nextHeader, h.getNextHeader());
    assertEquals(hdrExtLen, h.getHdrExtLen());
    assertEquals(options.size(), h.getOptions().size());
    Iterator<IpV6Option> iter = h.getOptions().iterator();
    for (IpV6Option opt : options) {
      assertEquals(opt, iter.next());
    }

    IpV6ExtDestinationOptionsPacket.Builder b = packet.getBuilder();
    IpV6ExtDestinationOptionsPacket p;

    b.hdrExtLen((byte) 0);
    p = b.build();
    assertEquals((byte) 0, (byte) p.getHeader().getHdrExtLenAsInt());

    b.hdrExtLen((byte) -1);
    p = b.build();
    assertEquals((byte) -1, (byte) p.getHeader().getHdrExtLenAsInt());

    b.hdrExtLen((byte) 127);
    p = b.build();
    assertEquals((byte) 127, (byte) p.getHeader().getHdrExtLenAsInt());

    b.hdrExtLen((byte) -128);
    p = b.build();
    assertEquals((byte) -128, (byte) p.getHeader().getHdrExtLenAsInt());
  }
}
