/*_##########################################################################
  _##
  _##  Copyright (C) 2015 Pcap4J.org
  _##
  _##########################################################################
*/
package org.pcap4j.test.packet;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.net.Inet4Address;
import java.net.InetAddress;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.PppPacket;
import org.pcap4j.packet.PppPacket.PppHeader;
import org.pcap4j.packet.UnknownPacket.Builder;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.PppDllProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class PppPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(PppPacketTest.class);

  private final PppDllProtocol protocol;
  private final byte[] pad;
  private final PppPacket packet;

  public PppPacketTest() throws Exception {
    this.protocol = PppDllProtocol.IPV4;
    this.pad =
        new byte[] {
          (byte) 0, (byte) 1, (byte) 0, (byte) 1, (byte) 0, (byte) 1,
          (byte) 0, (byte) 1, (byte) 0, (byte) 1, (byte) 0, (byte) 1,
          (byte) 0, (byte) 1, (byte) 0, (byte) 1, (byte) 0, (byte) 1,
          (byte) 0, (byte) 1, (byte) 0, (byte) 1, (byte) 0, (byte) 1,
          (byte) 0, (byte) 1, (byte) 0, (byte) 1, (byte) 0, (byte) 1,
        };

    Builder unknownb = new Builder().rawData(new byte[] {(byte) 0, (byte) 1, (byte) 2, (byte) 3});

    IcmpV4EchoPacket.Builder echob =
        new IcmpV4EchoPacket.Builder()
            .identifier((short) 1234)
            .sequenceNumber((short) 4321)
            .payloadBuilder(unknownb);

    IcmpV4CommonPacket.Builder icmpb =
        new IcmpV4CommonPacket.Builder()
            .type(IcmpV4Type.ECHO)
            .code(IcmpV4Code.NO_CODE)
            .correctChecksumAtBuild(true)
            .payloadBuilder(echob);

    IpV4Packet.Builder ipb =
        new IpV4Packet.Builder()
            .version(IpVersion.IPV4)
            .tos(IpV4Rfc1349Tos.newInstance((byte) 0x75))
            .identification((short) 123)
            .reservedFlag(false)
            .dontFragmentFlag(false)
            .moreFragmentFlag(false)
            .fragmentOffset((short) 0)
            .ttl((byte) 111)
            .protocol(IpNumber.ICMPV4)
            .srcAddr((Inet4Address) InetAddress.getByName("192.0.2.1"))
            .dstAddr((Inet4Address) InetAddress.getByName("192.0.2.2"))
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true)
            .paddingAtBuild(true)
            .payloadBuilder(icmpb);

    PppPacket.Builder b = new PppPacket.Builder().protocol(protocol).payloadBuilder(ipb).pad(pad);
    this.packet = b.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    return packet;
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info("########## " + PppPacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      PppPacket p = PppPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testGetHeader() {
    PppHeader h = packet.getHeader();
    assertEquals(protocol, h.getProtocol());
    assertArrayEquals(pad, packet.getPad());
  }

  @Override
  protected DataLinkType getDataLinkType() {
    return DataLinkType.PPP;
  }
}
