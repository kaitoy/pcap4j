package org.pcap4j.packet;

import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.ArpPacket.ArpHeader;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class ArpPacketTest extends AbstractPacketTest {

  private static final Logger logger
    = LoggerFactory.getLogger(ArpPacketTest.class);

  private final ArpPacket packet;
  private final ArpHardwareType hardwareType;
  private final EtherType protocolType;
  private final byte hardwareLength;
  private final byte protocolLength;
  private final MacAddress srcHardwareAddr;
  private final MacAddress dstHardwareAddr;
  private final InetAddress srcProtocolAddr;
  private final InetAddress dstProtocolAddr;
  private final ArpOperation operation;

  public ArpPacketTest() {
    this.hardwareType = ArpHardwareType.ETHERNET;
    this.protocolType = EtherType.IPV4;
    this.hardwareLength = (byte)MacAddress.SIZE_IN_BYTES;
    this.protocolLength = (byte)ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES;
    this.srcHardwareAddr = MacAddress.getByName("fe:00:00:00:00:01");
    this.dstHardwareAddr = MacAddress.ETHER_BROADCAST_ADDRESS;
    try {
      this.srcProtocolAddr
        = InetAddress.getByAddress(
            new byte[] { (byte)192, (byte)0, (byte)2, (byte)1 }
          );
      this.dstProtocolAddr
        = InetAddress.getByAddress(
            new byte[] { (byte)192, (byte)0, (byte)2, (byte)2 }
          );
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }
    this.operation = ArpOperation.REQUEST;

    ArpPacket.Builder ab = new ArpPacket.Builder();
    ab.hardwareType(hardwareType)
      .protocolType(protocolType)
      .hardwareLength(hardwareLength)
      .protocolLength(protocolLength)
      .srcHardwareAddr(srcHardwareAddr)
      .dstHardwareAddr(dstHardwareAddr)
      .srcProtocolAddr(srcProtocolAddr)
      .dstProtocolAddr(dstProtocolAddr)
      .operation(operation);
    this.packet = ab.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(packet.getHeader().getDstHardwareAddr())
      .srcAddr(packet.getHeader().getSrcHardwareAddr())
      .type(EtherType.ARP)
      .payloadBuilder(new SimpleBuilder(packet))
      .paddingAtBuild(true);
    return eb.build();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
      "########## " + ArpPacketTest.class.getSimpleName() + " START ##########"
    );
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
    logger.info(
      "########## " + ArpPacketTest.class.getSimpleName() + " END ##########"
    );
  }

  @Test
  public void testGetHeader() {
    ArpHeader h = packet.getHeader();
    assertEquals(hardwareType, h.getHardwareType());
    assertEquals(protocolType, h.getProtocolType());
    assertEquals(hardwareLength, h.getHardwareLength());
    assertEquals(hardwareLength, (byte)h.getHardwareLengthAsInt());
    assertEquals(protocolLength, h.getProtocolLength());
    assertEquals(protocolLength, (byte)h.getProtocolLengthAsInt());
    assertEquals(dstHardwareAddr, h.getDstHardwareAddr());
    assertEquals(srcHardwareAddr, h.getSrcHardwareAddr());
    assertEquals(dstProtocolAddr, h.getDstProtocolAddr());
    assertEquals(srcProtocolAddr, h.getSrcProtocolAddr());
    assertEquals(operation, h.getOperation());

    ArpPacket.Builder ab = packet.getBuilder();
    ArpPacket p;

    ab.hardwareLength((byte)0);
    ab.protocolLength((byte)0);
    p = ab.build();
    assertEquals((byte)0, (byte)p.getHeader().getHardwareLengthAsInt());
    assertEquals((byte)0, (byte)p.getHeader().getProtocolLengthAsInt());

    ab.hardwareLength((byte)50);
    ab.protocolLength((byte)50);
    p = ab.build();
    assertEquals((byte)50, (byte)p.getHeader().getHardwareLengthAsInt());
    assertEquals((byte)50, (byte)p.getHeader().getProtocolLengthAsInt());

    ab.hardwareLength((byte)127);
    ab.protocolLength((byte)127);
    p = ab.build();
    assertEquals((byte)127, (byte)p.getHeader().getHardwareLengthAsInt());
    assertEquals((byte)127, (byte)p.getHeader().getProtocolLengthAsInt());

    ab.hardwareLength((byte)-1);
    ab.protocolLength((byte)-1);
    p = ab.build();
    assertEquals((byte)-1, (byte)p.getHeader().getHardwareLengthAsInt());
    assertEquals((byte)-1, (byte)p.getHeader().getProtocolLengthAsInt());

    ab.hardwareLength((byte)-128);
    ab.protocolLength((byte)-128);
    p = ab.build();
    assertEquals((byte)-128, (byte)p.getHeader().getHardwareLengthAsInt());
    assertEquals((byte)-128, (byte)p.getHeader().getProtocolLengthAsInt());
  }

  @Test
  public void testNewPacket() {
    try {
      ArpPacket p = ArpPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }

  }

  @Test
  public void testNewPacketRandom() {
      RandomPacketTester.testClass(ArpPacket.class, packet);
  }



}
