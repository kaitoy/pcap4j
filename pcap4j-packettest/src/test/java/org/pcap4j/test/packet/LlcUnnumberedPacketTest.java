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
import org.pcap4j.packet.LlcPacket.LlcControl;
import org.pcap4j.packet.LlcPacket.LlcHeader;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SimpleBuilder;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.LlcControlModifierFunction;
import org.pcap4j.packet.namednumber.LlcNumber;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class LlcUnnumberedPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(LlcUnnumberedPacketTest.class);

  private final LlcPacket packet;
  private final LlcNumber dsap;
  private final LlcNumber ssap;
  private final LlcControl control;

  public LlcUnnumberedPacketTest() {
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

    this.dsap = this.ssap = LlcNumber.ARP;
    this.control =
        new LlcControlUnnumbered.Builder()
            .modifierFunction(LlcControlModifierFunction.UI)
            .pfBit(false)
            .build();

    LlcPacket.Builder db = new LlcPacket.Builder();
    db.dsap(dsap).ssap(ssap).control(control).payloadBuilder(ab);
    this.packet = db.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(((ArpPacket) packet.getPayload()).getHeader().getDstHardwareAddr())
        .srcAddr(((ArpPacket) packet.getPayload()).getHeader().getSrcHardwareAddr())
        .type(EtherType.getInstance((short) packet.length()))
        .payloadBuilder(new SimpleBuilder(packet))
        .paddingAtBuild(true);
    return eb.build();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
        "########## " + LlcUnnumberedPacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      LlcPacket p = LlcPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testGetHeader() {
    LlcHeader h = packet.getHeader();
    assertEquals(dsap, h.getDsap());
    assertEquals(ssap, h.getSsap());
    assertEquals(control, h.getControl());
  }
}
