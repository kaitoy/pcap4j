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
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IcmpV6ParameterProblemPacket.IcmpV6ParameterProblemHeader;
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
public class IcmpV6ParameterProblemPacketTest {

  private static final Logger logger
    = LoggerFactory.getLogger(IcmpV6ParameterProblemPacketTest.class);

  private final IcmpV6ParameterProblemPacket packet;
  private final int pointer;

  public IcmpV6ParameterProblemPacketTest() {
    this.pointer = 12345;

    IcmpV6EchoRequestPacket.Builder echob = new IcmpV6EchoRequestPacket.Builder();
    echob.identifier((short)100)
         .sequenceNumber((short)10)
         .payloadBuilder(
            new UnknownPacket.Builder()
              .rawData((new byte[] { (byte)0, (byte)1, (byte)2 }))
          );

    Inet6Address srcAddr;
    Inet6Address dstAddr;
    try {
      srcAddr = (Inet6Address)InetAddress.getByName("aa:bb:cc::3:2:1");
      dstAddr = (Inet6Address)InetAddress.getByName("aa:bb:cc::3:2:2");
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }
    IcmpV6CommonPacket.Builder icmpV6b = new IcmpV6CommonPacket.Builder();
    icmpV6b.type(IcmpV6Type.ECHO_REQUEST)
           .code(IcmpV6Code.NO_CODE)
           .srcAddr(srcAddr)
           .dstAddr(dstAddr)
           .payloadBuilder(echob)
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

    IcmpV6ParameterProblemPacket.Builder b
      = new IcmpV6ParameterProblemPacket.Builder();
    b.pointer(pointer)
     .payload(ipv6b.build());
    this.packet = b.build();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
      "########## " + IcmpV6ParameterProblemPacketTest.class.getSimpleName() + " START ##########"
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
    IcmpV6ParameterProblemPacket.Builder builder = packet.getBuilder();
    assertEquals(packet, builder.build());
  }

  @Test
  public void testNewPacket() {
    IcmpV6ParameterProblemPacket p
      = IcmpV6ParameterProblemPacket.newPacket(packet.getRawData());
    assertEquals(packet, p);

    assertTrue(p.getPayload().contains(IpV6Packet.class));
    assertTrue(p.getPayload().contains(IcmpV6CommonPacket.class));
    assertTrue(p.getPayload().contains(IcmpV6EchoRequestPacket.class));
    assertTrue(p.getPayload().contains(UnknownPacket.class));
    assertEquals(p.getPayload().get(UnknownPacket.class).length(), 3);
    assertFalse(p.getPayload().contains(IllegalPacket.class));
  }

  @Test
  public void testGetHeader() {
    IcmpV6ParameterProblemHeader h = packet.getHeader();
    assertEquals(pointer, h.getPointer());

    IcmpV6ParameterProblemPacket.Builder b = packet.getBuilder();
    IcmpV6ParameterProblemPacket p;

    b.pointer(0);
    p = b.build();
    assertEquals(0, (int)p.getHeader().getPointerAsLong());

    b.pointer(2147483647);
    p = b.build();
    assertEquals(2147483647, (int)p.getHeader().getPointerAsLong());

    b.pointer(-1);
    p = b.build();
    assertEquals(-1, (int)p.getHeader().getPointerAsLong());

    b.pointer(-2147483648);
    p = b.build();
    assertEquals(-2147483648, (int)p.getHeader().getPointerAsLong());
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
      srcAddr = (Inet6Address)InetAddress.getByName("aa:bb:cc::3:2:2");
      dstAddr = (Inet6Address)InetAddress.getByName("aa:bb:cc::3:2:1");
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }
    IcmpV6CommonPacket.Builder icmpV6b = new IcmpV6CommonPacket.Builder();
    icmpV6b.type(IcmpV6Type.PARAMETER_PROBLEM)
           .code(IcmpV6Code.UNRECOGNIZED_IP_V6_OPT)
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
