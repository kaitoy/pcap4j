package org.pcap4j.packet;

import static org.junit.Assert.*;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.IcmpV4RedirectPacket.IcmpV4RedirectHeader;
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
public class IcmpV4RedirectPacketTest extends AbstractPacketTest {

  private static final Logger logger
    = LoggerFactory.getLogger(IcmpV4RedirectPacketTest.class);

  private final IcmpV4RedirectPacket packet;
  private final Inet4Address gatewayInternetAddress;

  public IcmpV4RedirectPacketTest() {
    try {
      this.gatewayInternetAddress
        = (Inet4Address)InetAddress.getByAddress(
            new byte[] { (byte)192, (byte)0, (byte)2, (byte)254 }
          );
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    IcmpV4EchoPacket.Builder echob = new IcmpV4EchoPacket.Builder();
    echob.identifier((short)100)
         .sequenceNumber((short)10)
         .payloadBuilder(
            new UnknownPacket.Builder()
              .rawData((new byte[] { (byte)0, (byte)1, (byte)2 }))
          );

    IcmpV4CommonPacket.Builder icmpV4b = new IcmpV4CommonPacket.Builder();
    icmpV4b.type(IcmpV4Type.ECHO)
           .code(IcmpV4Code.NO_CODE)
           .payloadBuilder(echob)
           .correctChecksumAtBuild(true);

    IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
    try {
      ipv4b.version(IpVersion.IPV4)
           .tos(IpV4Rfc791Tos.newInstance((byte)0))
           .identification((short)100)
           .ttl((byte)100)
           .protocol(IpNumber.ICMPV4)
           .srcAddr(
              (Inet4Address)InetAddress.getByAddress(
                new byte[] { (byte)192, (byte)0, (byte)2, (byte)2 }
              )
            )
          .dstAddr(
             (Inet4Address)InetAddress.getByAddress(
               new byte[] { (byte)192, (byte)0, (byte)2, (byte)1 }
             )
           )
          .payloadBuilder(icmpV4b)
          .correctChecksumAtBuild(true)
          .correctLengthAtBuild(true);
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    IcmpV4RedirectPacket.Builder b
      = new IcmpV4RedirectPacket.Builder();
    b.gatewayInternetAddress(gatewayInternetAddress)
     .payload(
        IcmpV4Helper.makePacketForInvokingPacketField(ipv4b.build())
      );
    this.packet = b.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() throws UnknownHostException {
    IcmpV4CommonPacket.Builder icmpV4b = new IcmpV4CommonPacket.Builder();
    icmpV4b.type(IcmpV4Type.REDIRECT)
           .code(IcmpV4Code.REDIRECT_DATAGRAMS_FOR_HOST)
           .payloadBuilder(new SimpleBuilder(packet))
           .correctChecksumAtBuild(true);

    IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
    ipv4b.version(IpVersion.IPV4)
         .tos(IpV4Rfc791Tos.newInstance((byte)0))
         .identification((short)100)
         .ttl((byte)100)
         .protocol(IpNumber.ICMPV4)
         .srcAddr(
            (Inet4Address)InetAddress.getByAddress(
              new byte[] { (byte)192, (byte)0, (byte)2, (byte)1 }
            )
          )
        .dstAddr(
           (Inet4Address)InetAddress.getByAddress(
             new byte[] { (byte)192, (byte)0, (byte)2, (byte)2 }
           )
         )
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
      "########## " + IcmpV4RedirectPacketTest.class.getSimpleName() + " START ##########"
    );
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
  }

  @Test
  public void testNewPacket() {
    IcmpV4RedirectPacket p;
    try {
      p = IcmpV4RedirectPacket.newPacket(packet.getRawData());
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
    assertEquals(packet, p);

    assertTrue(p.getPayload().contains(IpV4Packet.class));
    assertTrue(p.getPayload().contains(IcmpV4CommonPacket.class));
    assertTrue(p.getPayload().contains(IcmpV4EchoPacket.class));
    assertTrue(p.getPayload().contains(UnknownPacket.class));
    assertEquals(p.getPayload().get(UnknownPacket.class).length(), 0);
    assertFalse(p.getPayload().contains(IllegalPacket.class));
  }

  @Test
  public void testGetHeader() {
    IcmpV4RedirectHeader h = packet.getHeader();
    assertEquals(gatewayInternetAddress, h.getGatewayInternetAddress());
  }

}
