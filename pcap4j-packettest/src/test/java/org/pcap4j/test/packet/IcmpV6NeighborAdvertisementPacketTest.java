package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

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
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket.IpV6NeighborDiscoveryOption;
import org.pcap4j.packet.IcmpV6NeighborAdvertisementPacket;
import org.pcap4j.packet.IcmpV6NeighborAdvertisementPacket.IcmpV6NeighborAdvertisementHeader;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6NeighborDiscoveryTargetLinkLayerAddressOption.Builder;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.IpV6SimpleFlowLabel;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SimpleBuilder;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV6Code;
import org.pcap4j.packet.namednumber.IcmpV6Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class IcmpV6NeighborAdvertisementPacketTest extends AbstractPacketTest {

  private static final Logger logger =
      LoggerFactory.getLogger(IcmpV6NeighborAdvertisementPacketTest.class);

  private final IcmpV6NeighborAdvertisementPacket packet;
  private final boolean routerFlag; // R field
  private final boolean solicitedFlag; // S field
  private final boolean overrideFlag; // O field
  private final int reserved;
  private final Inet6Address targetAddress;
  private final List<IpV6NeighborDiscoveryOption> options =
      new ArrayList<IpV6NeighborDiscoveryOption>();

  public IcmpV6NeighborAdvertisementPacketTest() throws UnknownHostException {
    this.routerFlag = true;
    this.solicitedFlag = false;
    this.overrideFlag = true;
    this.reserved = 123454321;
    this.targetAddress = (Inet6Address) InetAddress.getByName("2001:db8::aaaa:bbbb:0:0");

    Builder opt = new Builder();
    opt.linkLayerAddress(
            new byte[] {
              (byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xee, (byte) 0xdd
            })
        .correctLengthAtBuild(true);
    this.options.add(opt.build());

    IcmpV6NeighborAdvertisementPacket.Builder b = new IcmpV6NeighborAdvertisementPacket.Builder();
    b.reserved(reserved)
        .routerFlag(routerFlag)
        .solicitedFlag(solicitedFlag)
        .overrideFlag(overrideFlag)
        .targetAddress(targetAddress)
        .options(options);
    this.packet = b.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    Inet6Address srcAddr;
    Inet6Address dstAddr;
    try {
      srcAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:1");
      dstAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:2");
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }
    IcmpV6CommonPacket.Builder icmpV6b = new IcmpV6CommonPacket.Builder();
    icmpV6b
        .type(IcmpV6Type.NEIGHBOR_ADVERTISEMENT)
        .code(IcmpV6Code.NO_CODE)
        .srcAddr(srcAddr)
        .dstAddr(dstAddr)
        .payloadBuilder(new SimpleBuilder(packet))
        .correctChecksumAtBuild(true);

    IpV6Packet.Builder ipv6b = new IpV6Packet.Builder();
    ipv6b
        .version(IpVersion.IPV6)
        .trafficClass(IpV6SimpleTrafficClass.newInstance((byte) 0x12))
        .flowLabel(IpV6SimpleFlowLabel.newInstance(0x12345))
        .nextHeader(IpNumber.ICMPV6)
        .hopLimit((byte) 100)
        .srcAddr(srcAddr)
        .dstAddr(dstAddr)
        .correctLengthAtBuild(true)
        .payloadBuilder(icmpV6b);

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
        .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
        .type(EtherType.IPV6)
        .payloadBuilder(ipv6b)
        .paddingAtBuild(true);
    return eb.build();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
        "########## "
            + IcmpV6NeighborAdvertisementPacketTest.class.getSimpleName()
            + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      IcmpV6NeighborAdvertisementPacket p =
          IcmpV6NeighborAdvertisementPacket.newPacket(
              packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testGetHeader() {
    IcmpV6NeighborAdvertisementHeader h = packet.getHeader();
    assertEquals(targetAddress, h.getTargetAddress());
    assertEquals(reserved, h.getReserved());
    Iterator<IpV6NeighborDiscoveryOption> iter = h.getOptions().iterator();
    for (IpV6NeighborDiscoveryOption expected : options) {
      IpV6NeighborDiscoveryOption actual = iter.next();
      assertEquals(expected, actual);
    }

    IcmpV6NeighborAdvertisementPacket.Builder b = packet.getBuilder();
    IcmpV6NeighborAdvertisementPacket p;

    b.reserved(0);
    p = b.build();
    assertEquals(0, p.getHeader().getReserved());

    b.reserved(536870911);
    p = b.build();
    assertEquals(536870911, p.getHeader().getReserved());

    b.reserved(536870912);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }

    b.reserved(-1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }
  }
}
