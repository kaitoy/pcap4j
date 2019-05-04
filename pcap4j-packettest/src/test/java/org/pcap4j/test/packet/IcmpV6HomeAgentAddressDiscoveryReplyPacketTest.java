package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IcmpV6HomeAgentAddressDiscoveryReplyPacket;
import org.pcap4j.packet.IcmpV6HomeAgentAddressDiscoveryReplyPacket.Builder;
import org.pcap4j.packet.IcmpV6HomeAgentAddressDiscoveryReplyPacket.IcmpV6HomeAgentAddressDiscoveryReplyHeader;
import org.pcap4j.packet.IllegalRawDataException;
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
public class IcmpV6HomeAgentAddressDiscoveryReplyPacketTest extends AbstractPacketTest {

  private static final Logger logger =
      LoggerFactory.getLogger(IcmpV6HomeAgentAddressDiscoveryReplyPacketTest.class);

  private final IcmpV6HomeAgentAddressDiscoveryReplyPacket packet;
  private final short identifier;
  private final short reserved;
  private final List<Inet6Address> homeAgentAddresses = new ArrayList<Inet6Address>();

  public IcmpV6HomeAgentAddressDiscoveryReplyPacketTest() throws UnknownHostException {
    this.identifier = (short) 1234;
    this.reserved = (short) 12345;
    this.homeAgentAddresses.add((Inet6Address) InetAddress.getByName("2001:db8::aaaa:bbbb:0:0"));
    this.homeAgentAddresses.add((Inet6Address) InetAddress.getByName("2001:db8::aaaa:bbbb:0:1"));

    IcmpV6HomeAgentAddressDiscoveryReplyPacket.Builder b =
        new IcmpV6HomeAgentAddressDiscoveryReplyPacket.Builder();
    b.identifier(identifier).reserved(reserved).homeAgentAddresses(homeAgentAddresses);
    this.packet = b.build();
  }

  @Override
  public Packet getPacket() {
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
        .type(IcmpV6Type.HOME_AGENT_ADDRESS_DISCOVERY_REPLY)
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
            + IcmpV6HomeAgentAddressDiscoveryReplyPacketTest.class.getSimpleName()
            + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    IcmpV6HomeAgentAddressDiscoveryReplyPacket p;
    try {
      p =
          IcmpV6HomeAgentAddressDiscoveryReplyPacket.newPacket(
              packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testGetHeader() {
    IcmpV6HomeAgentAddressDiscoveryReplyHeader h = packet.getHeader();
    assertEquals(identifier, h.getIdentifier());
    assertEquals(reserved, h.getReserved());
    assertEquals(homeAgentAddresses, h.getHomeAgentAddresses());

    Builder b = packet.getBuilder();
    IcmpV6HomeAgentAddressDiscoveryReplyPacket p;

    b.identifier((short) 0);
    p = b.build();
    assertEquals((short) 0, (short) p.getHeader().getIdentifierAsInt());

    b.identifier((short) 10000);
    p = b.build();
    assertEquals((short) 10000, (short) p.getHeader().getIdentifierAsInt());

    b.identifier((short) 32767);
    p = b.build();
    assertEquals((short) 32767, (short) p.getHeader().getIdentifierAsInt());

    b.identifier((short) -1);
    p = b.build();
    assertEquals((short) -1, (short) p.getHeader().getIdentifierAsInt());

    b.identifier((short) -32768);
    p = b.build();
    assertEquals((short) -32768, (short) p.getHeader().getIdentifierAsInt());
  }
}
