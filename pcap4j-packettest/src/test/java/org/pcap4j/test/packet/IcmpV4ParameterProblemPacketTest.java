package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IcmpV4EchoPacket.Builder;
import org.pcap4j.packet.IcmpV4ParameterProblemPacket;
import org.pcap4j.packet.IcmpV4ParameterProblemPacket.IcmpV4ParameterProblemHeader;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SimpleBuilder;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.IcmpV4Helper;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class IcmpV4ParameterProblemPacketTest extends AbstractPacketTest {

  private static final Logger logger =
      LoggerFactory.getLogger(IcmpV4ParameterProblemPacketTest.class);

  private final IcmpV4ParameterProblemPacket packet;
  private final byte pointer;
  private final int unused;

  public IcmpV4ParameterProblemPacketTest() {
    this.pointer = (byte) 123;
    this.unused = 321;

    Builder echob = new Builder();
    echob
        .identifier((short) 100)
        .sequenceNumber((short) 10)
        .payloadBuilder(
            new UnknownPacket.Builder().rawData((new byte[] {(byte) 0, (byte) 1, (byte) 2})));

    IcmpV4CommonPacket.Builder icmpV4b = new IcmpV4CommonPacket.Builder();
    icmpV4b
        .type(IcmpV4Type.ECHO)
        .code(IcmpV4Code.NO_CODE)
        .payloadBuilder(echob)
        .correctChecksumAtBuild(true);

    IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
    try {
      ipv4b
          .version(IpVersion.IPV4)
          .tos(IpV4Rfc1349Tos.newInstance((byte) 0))
          .identification((short) 100)
          .ttl((byte) 100)
          .protocol(IpNumber.ICMPV4)
          .srcAddr(
              (Inet4Address)
                  InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 0, (byte) 2, (byte) 2}))
          .dstAddr(
              (Inet4Address)
                  InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 0, (byte) 2, (byte) 1}))
          .payloadBuilder(icmpV4b)
          .correctChecksumAtBuild(true)
          .correctLengthAtBuild(true);
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    IcmpV4ParameterProblemPacket.Builder b = new IcmpV4ParameterProblemPacket.Builder();
    b.pointer(pointer)
        .unused(unused)
        .payload(IcmpV4Helper.makePacketForInvokingPacketField(ipv4b.build()));
    this.packet = b.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() throws UnknownHostException {
    IcmpV4CommonPacket.Builder icmpV4b = new IcmpV4CommonPacket.Builder();
    icmpV4b
        .type(IcmpV4Type.PARAMETER_PROBLEM)
        .code(IcmpV4Code.POINTER_INDICATES_ERROR)
        .payloadBuilder(new SimpleBuilder(packet))
        .correctChecksumAtBuild(true);

    IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
    ipv4b
        .version(IpVersion.IPV4)
        .tos(IpV4Rfc1349Tos.newInstance((byte) 0))
        .identification((short) 100)
        .ttl((byte) 100)
        .protocol(IpNumber.ICMPV4)
        .srcAddr(
            (Inet4Address)
                InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 0, (byte) 2, (byte) 1}))
        .dstAddr(
            (Inet4Address)
                InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 0, (byte) 2, (byte) 2}))
        .payloadBuilder(icmpV4b)
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true);

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
        .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
        .type(EtherType.IPV4)
        .payloadBuilder(ipv4b)
        .paddingAtBuild(true);
    return eb.build();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
        "########## "
            + IcmpV4ParameterProblemPacketTest.class.getSimpleName()
            + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    IcmpV4ParameterProblemPacket p;
    try {
      p =
          IcmpV4ParameterProblemPacket.newPacket(
              packet.getRawData(), 0, packet.getRawData().length);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
    assertEquals(packet, p);

    assertTrue(p.getPayload().contains(IpV4Packet.class));
    assertTrue(p.getPayload().contains(IcmpV4CommonPacket.class));
    assertTrue(p.getPayload().contains(IcmpV4EchoPacket.class));
    assertFalse(p.getPayload().contains(UnknownPacket.class));
    assertFalse(p.getPayload().contains(IllegalPacket.class));
  }

  @Test
  public void testGetHeader() {
    IcmpV4ParameterProblemHeader h = packet.getHeader();
    assertEquals(pointer, h.getPointer());
    assertEquals(unused, h.getUnused());

    IcmpV4ParameterProblemPacket.Builder b = packet.getBuilder();
    IcmpV4ParameterProblemPacket p;

    b.pointer((byte) 0);
    p = b.build();
    assertEquals((byte) 0, (byte) p.getHeader().getPointerAsInt());

    b.pointer((byte) 50);
    p = b.build();
    assertEquals((byte) 50, (byte) p.getHeader().getPointerAsInt());

    b.pointer((byte) 127);
    p = b.build();
    assertEquals((byte) 127, (byte) p.getHeader().getPointerAsInt());

    b.pointer((byte) -1);
    p = b.build();
    assertEquals((byte) -1, (byte) p.getHeader().getPointerAsInt());

    b.pointer((byte) -128);
    p = b.build();
    assertEquals((byte) -128, (byte) p.getHeader().getPointerAsInt());

    b.unused(0);
    p = b.build();
    assertEquals(0, p.getHeader().getUnused());

    b.unused(1000000);
    p = b.build();
    assertEquals(1000000, p.getHeader().getUnused());

    b.unused(16777215);
    p = b.build();
    assertEquals(16777215, p.getHeader().getUnused());

    b.unused(16777216);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }

    b.unused(-1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }
  }
}
