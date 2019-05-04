package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.LlcControlInformation.Builder;
import org.pcap4j.packet.LlcPacket;
import org.pcap4j.packet.LlcPacket.LlcControl;
import org.pcap4j.packet.LlcPacket.LlcHeader;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SimpleBuilder;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.LlcNumber;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class LlcInformationPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(LlcInformationPacketTest.class);

  private final LlcPacket packet;
  private final LlcNumber dsap;
  private final LlcNumber ssap;
  private final LlcControl control;

  public LlcInformationPacketTest() {
    this.dsap = this.ssap = LlcNumber.NULL_LSAP;
    this.control =
        new Builder()
            .receiveSequenceNumber((byte) 10)
            .sendSequenceNumber((byte) 100)
            .pfBit(false)
            .build();

    LlcPacket.Builder db = new LlcPacket.Builder();
    db.dsap(dsap).ssap(ssap).control(control);
    this.packet = db.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("aa:bb:cc:dd:ee:ff"))
        .srcAddr(MacAddress.getByName("11:22:33:44:55:66"))
        .type(EtherType.getInstance((short) packet.length()))
        .payloadBuilder(new SimpleBuilder(packet))
        .paddingAtBuild(true);
    return eb.build();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
        "########## " + LlcInformationPacketTest.class.getSimpleName() + " START ##########");
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
