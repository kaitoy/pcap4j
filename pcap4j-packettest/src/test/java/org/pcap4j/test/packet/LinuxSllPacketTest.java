package org.pcap4j.test.packet;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.ArpPacket.Builder;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.LinuxSllPacket;
import org.pcap4j.packet.LinuxSllPacket.LinuxSllHeader;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.LinuxSllPacketType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.LinkLayerAddress;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class LinuxSllPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(LinuxSllPacketTest.class);

  private final LinuxSllPacket packet;
  private final LinuxSllPacketType packetType;
  private final ArpHardwareType hardwareType;
  private final short hardwareLength;
  private final byte[] addressField;
  private final LinkLayerAddress address;
  private final EtherType protocol;

  public LinuxSllPacketTest() {
    this.packetType = LinuxSllPacketType.LINUX_SLL_HOST;
    this.hardwareType = ArpHardwareType.ETHERNET;
    this.hardwareLength = 4;
    this.addressField =
        new byte[] {(byte) 0xFF, (byte) 0xEE, (byte) 0xDD, (byte) 0xCC, 0x11, 0x22, 0x33, 0x44};
    this.address =
        LinkLayerAddress.getByAddress(
            new byte[] {(byte) 0xFF, (byte) 0xEE, (byte) 0xDD, (byte) 0xCC});
    this.protocol = EtherType.ARP;

    Builder ab = new Builder();
    try {
      ab.hardwareType(ArpHardwareType.ETHERNET)
          .protocolType(EtherType.IPV4)
          .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
          .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
          .srcHardwareAddr(MacAddress.getByName("aa:bb:cc:dd:ee:ff"))
          .dstHardwareAddr(MacAddress.getByName("11:22:33:44:55:66"))
          .srcProtocolAddr(
              InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 0, (byte) 2, (byte) 1}))
          .dstProtocolAddr(
              InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 0, (byte) 2, (byte) 2}))
          .operation(ArpOperation.REQUEST);
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    LinuxSllPacket.Builder eb = new LinuxSllPacket.Builder();
    eb.packetType(packetType)
        .addressType(hardwareType)
        .addressLength(hardwareLength)
        .address(addressField)
        .protocol(protocol)
        .payloadBuilder(ab);
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
    return DataLinkType.LINUX_SLL;
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info("########## " + LinuxSllPacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      LinuxSllPacket p =
          LinuxSllPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testGetHeader() {
    LinuxSllHeader h = packet.getHeader();
    assertEquals(packetType, h.getPacketType());
    assertEquals(hardwareType, h.getAddressType());
    assertEquals(hardwareLength, h.getAddressLength());
    assertEquals(address, h.getAddress());
    assertArrayEquals(addressField, h.getAddressField());
    assertEquals(protocol, h.getProtocol());
  }
}
