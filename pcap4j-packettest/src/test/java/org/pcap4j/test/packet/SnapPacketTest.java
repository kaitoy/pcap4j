package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.ArpPacket.Builder;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.LlcControlUnnumbered;
import org.pcap4j.packet.LlcPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SimpleBuilder;
import org.pcap4j.packet.SnapPacket;
import org.pcap4j.packet.SnapPacket.SnapHeader;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.LlcControlModifierFunction;
import org.pcap4j.packet.namednumber.LlcNumber;
import org.pcap4j.packet.namednumber.Oui;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class SnapPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(SnapPacketTest.class);

  private final SnapPacket packet;
  private final Oui oui;
  private final EtherType protocolId;

  public SnapPacketTest() {
    Builder ab = new Builder();
    try {
      ab.hardwareType(ArpHardwareType.ETHERNET)
          .protocolType(EtherType.IPV4)
          .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
          .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
          .srcHardwareAddr(MacAddress.getByName("fe:00:00:00:00:01"))
          .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
          .srcProtocolAddr(
              InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 0, (byte) 2, (byte) 1}))
          .dstProtocolAddr(
              InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 0, (byte) 2, (byte) 2}))
          .operation(ArpOperation.REQUEST);
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    this.oui = Oui.CISCO_00000C;
    this.protocolId = EtherType.ARP;

    SnapPacket.Builder db = new SnapPacket.Builder();
    db.oui(oui).protocolId(protocolId).payloadBuilder(ab);
    this.packet = db.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    LlcPacket llc =
        new LlcPacket.Builder()
            .dsap(LlcNumber.SNAP)
            .ssap(LlcNumber.SNAP)
            .control(
                new LlcControlUnnumbered.Builder()
                    .modifierFunction(LlcControlModifierFunction.UI)
                    .pfBit(false)
                    .build())
            .payloadBuilder(new SimpleBuilder(packet))
            .build();
    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(((ArpPacket) packet.getPayload()).getHeader().getDstHardwareAddr())
        .srcAddr(((ArpPacket) packet.getPayload()).getHeader().getSrcHardwareAddr())
        .type(EtherType.getInstance((short) llc.length()))
        .payloadBuilder(new SimpleBuilder(llc))
        .paddingAtBuild(true);
    return eb.build();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info("########## " + SnapPacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      SnapPacket p = SnapPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testGetHeader() {
    SnapHeader h = packet.getHeader();
    assertEquals(oui, h.getOui());
    assertEquals(protocolId, h.getProtocolId());
  }
}
