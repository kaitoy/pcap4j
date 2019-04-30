package org.pcap4j.packet;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.LlcPacket.LlcControl;
import org.pcap4j.packet.LlcPacket.LlcHeader;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.LlcControlSupervisoryFunction;
import org.pcap4j.packet.namednumber.LlcNumber;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class LlcSupervisoryPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(LlcSupervisoryPacketTest.class);

  private final LlcPacket packet;
  private final LlcNumber dsap;
  private final LlcNumber ssap;
  private final LlcControl control;

  public LlcSupervisoryPacketTest() {
    this.dsap = this.ssap = LlcNumber.NULL_LSAP;
    this.control =
        new LlcControlSupervisory.Builder()
            .receiveSequenceNumber((byte) 127)
            .reserved((byte) 10)
            .supervisoryFunction(LlcControlSupervisoryFunction.REJ)
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

  @BeforeAll
  public static void setUpBeforeClass() throws Exception {
    logger.info(
        "########## " + LlcSupervisoryPacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterAll
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
