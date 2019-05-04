package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IcmpV6EchoRequestPacket;
import org.pcap4j.packet.IcmpV6EchoRequestPacket.IcmpV6EchoRequestHeader;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.IpV6SimpleFlowLabel;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SimpleBuilder;
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
public class IcmpV6EchoRequestPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(IcmpV6EchoRequestPacketTest.class);

  private final IcmpV6EchoRequestPacket packet;
  private final short identifier;
  private final short sequenceNumber;

  public IcmpV6EchoRequestPacketTest() {
    this.identifier = (short) 1234;
    this.sequenceNumber = (short) 4321;

    Builder unknownb = new Builder();
    unknownb.rawData(new byte[] {(byte) 0, (byte) 1, (byte) 2, (byte) 3});

    IcmpV6EchoRequestPacket.Builder b = new IcmpV6EchoRequestPacket.Builder();
    b.identifier(identifier).sequenceNumber(sequenceNumber).payloadBuilder(unknownb);
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
        .type(IcmpV6Type.ECHO_REQUEST)
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
        "########## " + IcmpV6EchoRequestPacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      IcmpV6EchoRequestPacket p =
          IcmpV6EchoRequestPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testGetHeader() {
    IcmpV6EchoRequestHeader h = packet.getHeader();
    assertEquals(identifier, h.getIdentifier());
    assertEquals(sequenceNumber, h.getSequenceNumber());

    IcmpV6EchoRequestPacket.Builder b = packet.getBuilder();
    IcmpV6EchoRequestPacket p;

    b.identifier((short) 0);
    b.sequenceNumber((short) 0);
    p = b.build();
    assertEquals((short) 0, (short) p.getHeader().getIdentifierAsInt());
    assertEquals((short) 0, (short) p.getHeader().getSequenceNumberAsInt());

    b.identifier((short) 10000);
    b.sequenceNumber((short) 10000);
    p = b.build();
    assertEquals((short) 10000, (short) p.getHeader().getIdentifierAsInt());
    assertEquals((short) 10000, (short) p.getHeader().getSequenceNumberAsInt());

    b.identifier((short) 32767);
    b.sequenceNumber((short) 32767);
    p = b.build();
    assertEquals((short) 32767, (short) p.getHeader().getIdentifierAsInt());
    assertEquals((short) 32767, (short) p.getHeader().getSequenceNumberAsInt());

    b.identifier((short) -1);
    b.sequenceNumber((short) -1);
    p = b.build();
    assertEquals((short) -1, (short) p.getHeader().getIdentifierAsInt());
    assertEquals((short) -1, (short) p.getHeader().getSequenceNumberAsInt());

    b.identifier((short) -32768);
    b.sequenceNumber((short) -32768);
    p = b.build();
    assertEquals((short) -32768, (short) p.getHeader().getIdentifierAsInt());
    assertEquals((short) -32768, (short) p.getHeader().getSequenceNumberAsInt());
  }
}
