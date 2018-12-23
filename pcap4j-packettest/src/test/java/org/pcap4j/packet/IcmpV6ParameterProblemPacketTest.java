package org.pcap4j.packet;

import static org.junit.Assert.*;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.IcmpV6ParameterProblemPacket.IcmpV6ParameterProblemHeader;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV6Code;
import org.pcap4j.packet.namednumber.IcmpV6Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class IcmpV6ParameterProblemPacketTest extends AbstractPacketTest {

  private static final Logger logger =
      LoggerFactory.getLogger(IcmpV6ParameterProblemPacketTest.class);

  private final IcmpV6ParameterProblemPacket packet;
  private final int pointer;

  public IcmpV6ParameterProblemPacketTest() {
    this.pointer = 12345;

    IcmpV6EchoRequestPacket.Builder echob = new IcmpV6EchoRequestPacket.Builder();
    echob
        .identifier((short) 100)
        .sequenceNumber((short) 10)
        .payloadBuilder(
            new UnknownPacket.Builder().rawData((new byte[] {(byte) 0, (byte) 1, (byte) 2})));

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
        .type(IcmpV6Type.ECHO_REQUEST)
        .code(IcmpV6Code.NO_CODE)
        .srcAddr(srcAddr)
        .dstAddr(dstAddr)
        .payloadBuilder(echob)
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

    IcmpV6ParameterProblemPacket.Builder b = new IcmpV6ParameterProblemPacket.Builder();
    b.pointer(pointer).payload(ipv6b.build());
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
      srcAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:2");
      dstAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:1");
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }
    IcmpV6CommonPacket.Builder icmpV6b = new IcmpV6CommonPacket.Builder();
    icmpV6b
        .type(IcmpV6Type.PARAMETER_PROBLEM)
        .code(IcmpV6Code.UNRECOGNIZED_IP_V6_OPT)
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
            + IcmpV6ParameterProblemPacketTest.class.getSimpleName()
            + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    IcmpV6ParameterProblemPacket p;
    try {
      p =
          IcmpV6ParameterProblemPacket.newPacket(
              packet.getRawData(), 0, packet.getRawData().length);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
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
    assertEquals(0, (int) p.getHeader().getPointerAsLong());

    b.pointer(2147483647);
    p = b.build();
    assertEquals(2147483647, (int) p.getHeader().getPointerAsLong());

    b.pointer(-1);
    p = b.build();
    assertEquals(-1, (int) p.getHeader().getPointerAsLong());

    b.pointer(-2147483648);
    p = b.build();
    assertEquals(-2147483648, (int) p.getHeader().getPointerAsLong());
  }
}
