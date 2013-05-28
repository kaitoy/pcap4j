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
import org.pcap4j.packet.IcmpV6NeighborAdvertisementPacket.IcmpV6NeighborAdvertisementHeader;
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
public class IcmpV6NeighborAdvertisementPacketTest {

  private static final Logger logger
    = LoggerFactory.getLogger(IcmpV6NeighborAdvertisementPacketTest.class);

  private final IcmpV6NeighborAdvertisementPacket packet;
  private final boolean routerFlag; // R field
  private final boolean solicitedFlag; // S field
  private final boolean overrideFlag; // O field
  private final int reserved;
  private final Inet6Address targetAddress;
  private final List<IpV6NeighborDiscoveryOption> options
    = new ArrayList<IpV6NeighborDiscoveryOption>();

  public IcmpV6NeighborAdvertisementPacketTest() throws UnknownHostException {
    this.routerFlag = true;
    this.solicitedFlag = false;
    this.overrideFlag = true;
    this.reserved = 123454321;
    this.targetAddress = (Inet6Address)InetAddress.getByName("fe80::aaaa:bbbb:0:0");

    IpV6NeighborDiscoveryTargetLinkLayerAddressOption.Builder opt
      = new IpV6NeighborDiscoveryTargetLinkLayerAddressOption.Builder();
    opt.linkLayerAddress(
          new byte[] {
            (byte)0xff, (byte)0x00, (byte)0x00, (byte)0xff, (byte)0xee, (byte)0xdd
          }
        )
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

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
      "########## " + IcmpV6NeighborAdvertisementPacketTest.class.getSimpleName() + " START ##########"
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
    IcmpV6NeighborAdvertisementPacket.Builder b = packet.getBuilder();
    assertEquals(packet, b.build());
  }

  @Test
  public void testNewPacket() {
    IcmpV6NeighborAdvertisementPacket p
      = IcmpV6NeighborAdvertisementPacket.newPacket(packet.getRawData());
    assertEquals(packet, p);
  }

  @Test
  public void testGetHeader() {
    IcmpV6NeighborAdvertisementHeader h = packet.getHeader();
    assertEquals(targetAddress, h.getTargetAddress());
    assertEquals(reserved, h.getReserved());
    Iterator<IpV6NeighborDiscoveryOption> iter = h.getOptions().iterator();
    for (IpV6NeighborDiscoveryOption expected: options) {
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
    } catch (IllegalArgumentException e) {}

    b.reserved(-1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {}
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
    icmpV6b.type(IcmpV6Type.NEIGHBOR_ADVERTISEMENT)
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
