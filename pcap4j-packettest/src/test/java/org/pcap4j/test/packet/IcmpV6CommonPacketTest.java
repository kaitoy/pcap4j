package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket.IcmpV6CommonHeader;
import org.pcap4j.packet.IcmpV6EchoRequestPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.IpV6SimpleFlowLabel;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket.Builder;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV6Code;
import org.pcap4j.packet.namednumber.IcmpV6Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class IcmpV6CommonPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(IcmpV6CommonPacketTest.class);

  private final IcmpV6CommonPacket packet;
  private final IcmpV6Type type;
  private final IcmpV6Code code;
  private final short checksum;
  private final Inet6Address srcAddr;
  private final Inet6Address dstAddr;

  public IcmpV6CommonPacketTest() {
    Builder unknownb = new Builder();
    unknownb.rawData(new byte[] {(byte) 0, (byte) 1, (byte) 2, (byte) 3});

    IcmpV6EchoRequestPacket.Builder echob = new IcmpV6EchoRequestPacket.Builder();
    echob.identifier((short) 100).sequenceNumber((short) 10).payloadBuilder(unknownb);

    this.type = IcmpV6Type.ECHO_REQUEST;
    this.code = IcmpV6Code.NO_CODE;
    this.checksum = (short) 0x1234;
    try {
      this.srcAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:1");
      this.dstAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:2");
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    IcmpV6CommonPacket.Builder b = new IcmpV6CommonPacket.Builder();
    b.type(type)
        .code(code)
        .checksum(checksum)
        .srcAddr(srcAddr)
        .dstAddr(dstAddr)
        .correctChecksumAtBuild(false)
        .payloadBuilder(echob);
    this.packet = b.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
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
        .payloadBuilder(
            packet.getBuilder().srcAddr(srcAddr).dstAddr(dstAddr).correctChecksumAtBuild(true));

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
    logger.info("########## " + IcmpV6CommonPacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      IcmpV6CommonPacket p =
          IcmpV6CommonPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testNewPacketRandom() {
    RandomPacketTester.testClass(IcmpV6CommonPacket.class, packet);
  }

  @Test
  public void testGetHeader() {
    IcmpV6CommonHeader h = packet.getHeader();
    assertEquals(type, h.getType());
    assertEquals(code, h.getCode());
    assertEquals(checksum, h.getChecksum());
  }

  @Test
  public void testHasValidChecksum() {
    IcmpV6CommonPacket.Builder b = packet.getBuilder();
    b.srcAddr(srcAddr).dstAddr(dstAddr);
    IcmpV6CommonPacket p = b.correctChecksumAtBuild(false).build();

    assertFalse(packet.hasValidChecksum(srcAddr, dstAddr, false));
    assertFalse(packet.hasValidChecksum(srcAddr, dstAddr, true));

    b.checksum((short) 0).correctChecksumAtBuild(false);
    p = b.build();
    assertFalse(p.hasValidChecksum(srcAddr, dstAddr, false));
    assertTrue(p.hasValidChecksum(srcAddr, dstAddr, true));

    b.checksum((short) 1234).correctChecksumAtBuild(true);
    p = b.build();
    assertTrue(p.hasValidChecksum(srcAddr, dstAddr, false));
    assertTrue(p.hasValidChecksum(srcAddr, dstAddr, true));
  }
}
