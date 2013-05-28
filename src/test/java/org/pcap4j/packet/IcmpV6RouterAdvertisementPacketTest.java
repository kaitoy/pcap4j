package org.pcap4j.packet;

import static org.junit.Assert.*;
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
import java.util.Iterator;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IcmpV6CommonPacket.IpV6NeighborDiscoveryOption;
import org.pcap4j.packet.IcmpV6RouterAdvertisementPacket.IcmpV6RouterAdvertisementHeader;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV6Code;
import org.pcap4j.packet.namednumber.IcmpV6Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class IcmpV6RouterAdvertisementPacketTest {

  private static final Logger logger
    = LoggerFactory.getLogger(IcmpV6RouterAdvertisementPacketTest.class);

  private final IcmpV6RouterAdvertisementPacket packet;
  private final byte curHopLimit;
  private final boolean managedAddressConfigurationFlag;
  private final boolean otherConfigurationFlag;
  private final byte reserved;
  private final short routerLifetime;
  private final int reachableTime;
  private final int retransTimer;
  private final List<IpV6NeighborDiscoveryOption> options
    = new ArrayList<IpV6NeighborDiscoveryOption>();

  public IcmpV6RouterAdvertisementPacketTest() throws UnknownHostException {
    this.curHopLimit = (byte)123;
    this.managedAddressConfigurationFlag = true;
    this.otherConfigurationFlag = false;
    this.reserved = (byte)10;
    this.routerLifetime = (short)55555;
    this.reachableTime = 3333333;
    this.retransTimer = 111111;

    IpV6NeighborDiscoverySourceLinkLayerAddressOption.Builder opt1
      = new IpV6NeighborDiscoverySourceLinkLayerAddressOption.Builder();
    opt1.linkLayerAddress(
          new byte[] {
            (byte)0xff, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03
          }
        )
       .correctLengthAtBuild(true);
    this.options.add(opt1.build());

    IpV6NeighborDiscoveryMtuOption.Builder opt2
      = new IpV6NeighborDiscoveryMtuOption.Builder();
    opt2.reserved((byte)222)
        .mtu(9999999)
        .correctLengthAtBuild(true);
    this.options.add(opt2.build());

    IpV6NeighborDiscoveryPrefixInformationOption.Builder opt3
      = new IpV6NeighborDiscoveryPrefixInformationOption.Builder();
    opt3.prefixLength((byte)96)
        .onLinkFlag(true)
        .addressConfigurationFlag(false)
        .reserved1((byte)22)
        .validLifetime(2222222)
        .preferredLifetime(777777777)
        .reserved2(1212121212)
        .prefix((Inet6Address)InetAddress.getByName("fe80::aaaa:bbbb:0:0"))
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

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
      "########## " + IcmpV6RouterAdvertisementPacketTest.class.getSimpleName() + " START ##########"
    );
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
  }

  @Before
  public void setUp() throws Exception {
  }

  @After
  public void tearDown() throws Exception {
    logger.info(
      "=================================================="
    );
  }

  @Test
  public void testGetBuilder() {
    IcmpV6RouterAdvertisementPacket.Builder b = packet.getBuilder();
    assertEquals(packet, b.build());
  }

  @Test
  public void testNewPacket() {
    IcmpV6RouterAdvertisementPacket p
      = IcmpV6RouterAdvertisementPacket.newPacket(packet.getRawData());
    assertEquals(packet, p);
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
    for (IpV6NeighborDiscoveryOption expected: options) {
      IpV6NeighborDiscoveryOption actual = iter.next();
      assertEquals(expected, actual);
    }

    IcmpV6RouterAdvertisementPacket.Builder b = packet.getBuilder();
    IcmpV6RouterAdvertisementPacket p;

    b.reserved((byte)0);
    p = b.build();
    assertEquals((byte)0, p.getHeader().getReserved());

    b.reserved((byte)63);
    p = b.build();
    assertEquals((byte)63, p.getHeader().getReserved());

    b.reserved((byte)64);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {}

    b.reserved((byte)-1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {}

    b.reserved((byte)1);

    b.curHopLimit((byte)0);
    b.routerLifetime((short)0);
    b.reachableTime(0);
    b.retransTimer(0);
    p = b.build();
    assertEquals((byte)0, (byte)p.getHeader().getCurHopLimitAsInt());
    assertEquals((short)0, (short)p.getHeader().getRouterLifetimeAsInt());
    assertEquals(0, (int)p.getHeader().getReachableTimeAsLong());
    assertEquals(0, (int)p.getHeader().getRetransTimerAsLong());

    b.curHopLimit((byte)127);
    b.routerLifetime((short)32767);
    b.reachableTime(2147483647);
    b.retransTimer(2147483647);
    p = b.build();
    assertEquals((byte)127, (byte)p.getHeader().getCurHopLimitAsInt());
    assertEquals((short)32767, (short)p.getHeader().getRouterLifetimeAsInt());
    assertEquals(2147483647, (int)p.getHeader().getReachableTimeAsLong());
    assertEquals(2147483647, (int)p.getHeader().getRetransTimerAsLong());

    b.curHopLimit((byte)-1);
    b.routerLifetime((short)-1);
    b.reachableTime(-1);
    b.retransTimer(-1);
    p = b.build();
    assertEquals((byte)-1, (byte)p.getHeader().getCurHopLimitAsInt());
    assertEquals((short)-1, (short)p.getHeader().getRouterLifetimeAsInt());
    assertEquals(-1, (int)p.getHeader().getReachableTimeAsLong());
    assertEquals(-1, (int)p.getHeader().getRetransTimerAsLong());

    b.curHopLimit((byte)-128);
    b.routerLifetime((short)-32768);
    b.reachableTime(-2147483648);
    b.retransTimer(-2147483648);
    p = b.build();
    assertEquals((byte)-128, (byte)p.getHeader().getCurHopLimitAsInt());
    assertEquals((short)-32768, (short)p.getHeader().getRouterLifetimeAsInt());
    assertEquals(-2147483648, (int)p.getHeader().getReachableTimeAsLong());
    assertEquals(-2147483648, (int)p.getHeader().getRetransTimerAsLong());
  }

  @Test
  public void testLength() {
    assertEquals(packet.getRawData().length, packet.length());
  }

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

    Inet6Address srcAddr;
    Inet6Address dstAddr;
    try {
      srcAddr = (Inet6Address)InetAddress.getByName("aa:bb:cc::3:2:1");
      dstAddr = (Inet6Address)InetAddress.getByName("aa:bb:cc::3:2:2");
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }
    IcmpV6CommonPacket.Builder icmpV6b = new IcmpV6CommonPacket.Builder();
    icmpV6b.type(IcmpV6Type.ROUTER_ADVERTISEMENT)
           .code(IcmpV6Code.NO_CODE)
           .srcAddr(srcAddr)
           .dstAddr(dstAddr)
           .payloadBuilder(new SimpleBuilder(packet))
           .correctChecksumAtBuild(true);

    IpV6Packet.Builder ipv6b = new IpV6Packet.Builder();
    ipv6b.version(IpVersion.IPV6)
         .trafficClass(IpV6SimpleTrafficClass.newInstance((byte)0x12))
         .flowLabel(IpV6SimpleFlowLabel.newInstance(0x12345))
         .nextHeader(IpNumber.ICMPV6)
         .hopLimit((byte)100)
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
