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
import org.pcap4j.packet.IcmpV6RouterAdvertisementPacket;
import org.pcap4j.packet.IcmpV6RouterAdvertisementPacket.IcmpV6RouterAdvertisementHeader;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6NeighborDiscoveryMtuOption;
import org.pcap4j.packet.IpV6NeighborDiscoveryPrefixInformationOption;
import org.pcap4j.packet.IpV6NeighborDiscoverySourceLinkLayerAddressOption.Builder;
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
public class IcmpV6RouterAdvertisementPacketTest extends AbstractPacketTest {

  private static final Logger logger =
      LoggerFactory.getLogger(IcmpV6RouterAdvertisementPacketTest.class);

  private final IcmpV6RouterAdvertisementPacket packet;
  private final byte curHopLimit;
  private final boolean managedAddressConfigurationFlag;
  private final boolean otherConfigurationFlag;
  private final byte reserved;
  private final short routerLifetime;
  private final int reachableTime;
  private final int retransTimer;
  private final List<IpV6NeighborDiscoveryOption> options =
      new ArrayList<IpV6NeighborDiscoveryOption>();

  public IcmpV6RouterAdvertisementPacketTest() throws UnknownHostException {
    this.curHopLimit = (byte) 123;
    this.managedAddressConfigurationFlag = true;
    this.otherConfigurationFlag = false;
    this.reserved = (byte) 10;
    this.routerLifetime = (short) 55555;
    this.reachableTime = 3333333;
    this.retransTimer = 111111;

    Builder opt1 = new Builder();
    opt1.linkLayerAddress(
            new byte[] {
              (byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03
            })
        .correctLengthAtBuild(true);
    this.options.add(opt1.build());

    IpV6NeighborDiscoveryMtuOption.Builder opt2 = new IpV6NeighborDiscoveryMtuOption.Builder();
    opt2.reserved((byte) 222).mtu(9999999).correctLengthAtBuild(true);
    this.options.add(opt2.build());

    IpV6NeighborDiscoveryPrefixInformationOption.Builder opt3 =
        new IpV6NeighborDiscoveryPrefixInformationOption.Builder();
    opt3.prefixLength((byte) 96)
        .onLinkFlag(true)
        .addressConfigurationFlag(false)
        .reserved1((byte) 22)
        .validLifetime(2222222)
        .preferredLifetime(777777777)
        .reserved2(1212121212)
        .prefix((Inet6Address) InetAddress.getByName("2001:db8::aaaa:bbbb:0:0"))
        .correctLengthAtBuild(true);
    this.options.add(opt3.build());

    IcmpV6RouterAdvertisementPacket.Builder b = new IcmpV6RouterAdvertisementPacket.Builder();
    b.curHopLimit(curHopLimit)
        .managedAddressConfigurationFlag(managedAddressConfigurationFlag)
        .otherConfigurationFlag(otherConfigurationFlag)
        .reserved(reserved)
        .routerLifetime(routerLifetime)
        .reachableTime(reachableTime)
        .retransTimer(retransTimer)
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
        .type(IcmpV6Type.ROUTER_ADVERTISEMENT)
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
            + IcmpV6RouterAdvertisementPacketTest.class.getSimpleName()
            + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      IcmpV6RouterAdvertisementPacket p =
          IcmpV6RouterAdvertisementPacket.newPacket(
              packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testGetHeader() {
    IcmpV6RouterAdvertisementHeader h = packet.getHeader();
    assertEquals(curHopLimit, h.getCurHopLimit());
    assertEquals(managedAddressConfigurationFlag, h.getManagedAddressConfigurationFlag());
    assertEquals(otherConfigurationFlag, h.getOtherConfigurationFlag());
    assertEquals(reserved, h.getReserved());
    assertEquals(routerLifetime, h.getRouterLifetime());
    assertEquals(reachableTime, h.getReachableTime());
    assertEquals(retransTimer, h.getRetransTimer());
    Iterator<IpV6NeighborDiscoveryOption> iter = h.getOptions().iterator();
    for (IpV6NeighborDiscoveryOption expected : options) {
      IpV6NeighborDiscoveryOption actual = iter.next();
      assertEquals(expected, actual);
    }

    IcmpV6RouterAdvertisementPacket.Builder b = packet.getBuilder();
    IcmpV6RouterAdvertisementPacket p;

    b.reserved((byte) 0);
    p = b.build();
    assertEquals((byte) 0, p.getHeader().getReserved());

    b.reserved((byte) 63);
    p = b.build();
    assertEquals((byte) 63, p.getHeader().getReserved());

    b.reserved((byte) 64);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }

    b.reserved((byte) -1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }

    b.reserved((byte) 1);

    b.curHopLimit((byte) 0);
    b.routerLifetime((short) 0);
    b.reachableTime(0);
    b.retransTimer(0);
    p = b.build();
    assertEquals((byte) 0, (byte) p.getHeader().getCurHopLimitAsInt());
    assertEquals((short) 0, (short) p.getHeader().getRouterLifetimeAsInt());
    assertEquals(0, (int) p.getHeader().getReachableTimeAsLong());
    assertEquals(0, (int) p.getHeader().getRetransTimerAsLong());

    b.curHopLimit((byte) 127);
    b.routerLifetime((short) 32767);
    b.reachableTime(2147483647);
    b.retransTimer(2147483647);
    p = b.build();
    assertEquals((byte) 127, (byte) p.getHeader().getCurHopLimitAsInt());
    assertEquals((short) 32767, (short) p.getHeader().getRouterLifetimeAsInt());
    assertEquals(2147483647, (int) p.getHeader().getReachableTimeAsLong());
    assertEquals(2147483647, (int) p.getHeader().getRetransTimerAsLong());

    b.curHopLimit((byte) -1);
    b.routerLifetime((short) -1);
    b.reachableTime(-1);
    b.retransTimer(-1);
    p = b.build();
    assertEquals((byte) -1, (byte) p.getHeader().getCurHopLimitAsInt());
    assertEquals((short) -1, (short) p.getHeader().getRouterLifetimeAsInt());
    assertEquals(-1, (int) p.getHeader().getReachableTimeAsLong());
    assertEquals(-1, (int) p.getHeader().getRetransTimerAsLong());

    b.curHopLimit((byte) -128);
    b.routerLifetime((short) -32768);
    b.reachableTime(-2147483648);
    b.retransTimer(-2147483648);
    p = b.build();
    assertEquals((byte) -128, (byte) p.getHeader().getCurHopLimitAsInt());
    assertEquals((short) -32768, (short) p.getHeader().getRouterLifetimeAsInt());
    assertEquals(-2147483648, (int) p.getHeader().getReachableTimeAsLong());
    assertEquals(-2147483648, (int) p.getHeader().getRetransTimerAsLong());
  }
}
