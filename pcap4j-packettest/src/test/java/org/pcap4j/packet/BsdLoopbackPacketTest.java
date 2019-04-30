package org.pcap4j.packet;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.BsdLoopbackPacket.BsdLoopbackHeader;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.ProtocolFamily;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class BsdLoopbackPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(BsdLoopbackPacketTest.class);

  private final BsdLoopbackPacket packet;
  private final ProtocolFamily protocolFamily;

  public BsdLoopbackPacketTest() throws UnknownHostException {
    this.protocolFamily = ProtocolFamily.PF_INET;

    UnknownPacket.Builder unknownb =
        new UnknownPacket.Builder().rawData(new byte[] {(byte) 0, (byte) 1, (byte) 2, (byte) 3});

    IcmpV4EchoPacket.Builder echob =
        new IcmpV4EchoPacket.Builder()
            .identifier((short) 1234)
            .sequenceNumber((short) 4321)
            .payloadBuilder(unknownb);

    IcmpV4CommonPacket.Builder icmpV4b =
        new IcmpV4CommonPacket.Builder()
            .type(IcmpV4Type.ECHO)
            .code(IcmpV4Code.NO_CODE)
            .payloadBuilder(echob)
            .correctChecksumAtBuild(true);

    IpV4Packet.Builder ipv4b =
        new IpV4Packet.Builder()
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

    BsdLoopbackPacket.Builder eb =
        new BsdLoopbackPacket.Builder().protocolFamily(protocolFamily).payloadBuilder(ipv4b);

    this.packet = eb.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    return packet;
  }

  @Override
  protected DataLinkType getDataLinkType() {
    return DataLinkType.NULL;
  }

  @BeforeAll
  public static void setUpBeforeClass() throws Exception {
    logger.info("########## " + BsdLoopbackPacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterAll
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      BsdLoopbackPacket p =
          BsdLoopbackPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testGetHeader() {
    BsdLoopbackHeader h = packet.getHeader();
    assertEquals(protocolFamily, h.getProtocolFamily());
  }
}
