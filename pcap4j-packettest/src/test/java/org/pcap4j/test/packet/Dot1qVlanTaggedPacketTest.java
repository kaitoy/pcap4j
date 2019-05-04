package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.ArpPacket.Builder;
import org.pcap4j.packet.Dot1qVlanTagPacket;
import org.pcap4j.packet.Dot1qVlanTagPacket.Dot1qVlanTagHeader;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SimpleBuilder;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class Dot1qVlanTaggedPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(Dot1qVlanTaggedPacketTest.class);

  private final Dot1qVlanTagPacket packet;
  private final byte priority;
  private final boolean cfi;
  private final short vid;
  private final EtherType type;

  public Dot1qVlanTaggedPacketTest() {
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

    this.priority = (byte) 3;
    this.cfi = false;
    this.vid = (short) 123;
    this.type = EtherType.ARP;

    Dot1qVlanTagPacket.Builder db = new Dot1qVlanTagPacket.Builder();
    db.priority(priority).cfi(cfi).vid(vid).type(type).payloadBuilder(ab);
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
        .type(EtherType.DOT1Q_VLAN_TAGGED_FRAMES)
        .payloadBuilder(new SimpleBuilder(packet))
        .paddingAtBuild(true);
    return eb.build();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
        "########## " + Dot1qVlanTaggedPacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      Dot1qVlanTagPacket p =
          Dot1qVlanTagPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testNewPacketRandom() {
    RandomPacketTester.testClass(Dot1qVlanTagPacket.class, packet);
  }

  @Test
  public void testGetHeader() {
    Dot1qVlanTagHeader h = packet.getHeader();
    assertEquals(priority, h.getPriority());
    assertEquals(cfi, h.getCfi());
    assertEquals(vid, h.getVid());
    assertEquals(type, h.getType());

    Dot1qVlanTagPacket.Builder b = packet.getBuilder();
    Dot1qVlanTagPacket p;

    b.vid((short) 0);
    p = b.build();
    assertEquals((short) 0, (short) p.getHeader().getVidAsInt());

    b.vid((short) 1000);
    p = b.build();
    assertEquals((short) 1000, (short) p.getHeader().getVidAsInt());

    b.vid((short) 4095);
    p = b.build();
    assertEquals((short) 4095, (short) p.getHeader().getVidAsInt());

    b.vid((short) 4096);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }

    b.vid((short) -1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }

    b.vid((short) 100);

    b.priority((byte) -1);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }

    b.priority((byte) 0);
    try {
      p = b.build();
    } catch (IllegalArgumentException e) {
      fail();
    }

    b.priority((byte) 7);
    try {
      p = b.build();
    } catch (IllegalArgumentException e) {
      fail();
    }

    b.priority((byte) 8);
    try {
      p = b.build();
      fail();
    } catch (IllegalArgumentException e) {
    }
  }
}
