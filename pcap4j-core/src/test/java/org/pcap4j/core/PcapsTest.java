package org.pcap4j.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.net.InetAddress;
import java.time.Instant;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.test.Constants;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class PcapsTest {

  private static final Logger logger = LoggerFactory.getLogger(PcapsTest.class);

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {}

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Before
  public void setUp() throws Exception {}

  @After
  public void tearDown() throws Exception {}

  @Test
  public void testFindAllDevs() throws Exception {
    List<PcapNetworkInterface> devs = Pcaps.findAllDevs();
    assertNotNull(devs);
    assertTrue(devs.size() != 0 || !System.getProperty("user.name").equals("root"));

    for (PcapNetworkInterface dev : devs) {
      logger.info(dev.toString());
    }
  }

  @Test
  public void testGetNifByInetAddress() {
    // TODO fail("not yet implemented");
  }

  @Test
  public void testGetNifByString() {
    // TODO fail("not yet implemented");
  }

  @Test
  public void testLookupDev() throws Exception {
    String dev;
    try {
      dev = Pcaps.lookupDev();
    } catch (PcapNativeException e) {
      logger.info("Pcaps.lookupDev() said {}", e.getMessage());
      return;
    }
    assertNotNull(dev);
    assertTrue(dev.length() != 0);
  }

  @Test
  public void testOpenOffline() {
    // TODO fail("not yet implemented");
  }

  @Test
  public void testOpenOfflineWithTimestampPrecision() throws Exception {
    if (!Boolean.getBoolean(Constants.ENABLE_TIMESTAMP_PRECISION_TESTS_KEY)) {
      return;
    }

    PcapHandle phNano =
        Pcaps.openOffline(
            "src/test/resources/org/pcap4j/core/"
                + "PcapsTest.testOpenOfflineWithTimestampPrecision.pcap",
            TimestampPrecision.NANO);
    PcapPacket packet = phNano.getNextPacket();
    assertEquals(1434220771L, packet.getTimestamp().getEpochSecond());
    assertEquals(517995677, packet.getTimestamp().getNano());
    phNano.close();

    PcapHandle phMicro =
        Pcaps.openOffline(
            "src/test/resources/org/pcap4j/core/"
                + "PcapsTest.testOpenOfflineWithTimestampPrecision.pcap",
            TimestampPrecision.MICRO);
    packet = phMicro.getNextPacket();
    System.out.println(packet.getTimestamp().getEpochSecond());
    System.out.println(packet.getTimestamp().getNano());
    assertEquals(1434220771L, packet.getTimestamp().getEpochSecond());
    assertEquals(517995000, packet.getTimestamp().getNano());
    phMicro.close();
  }

  @Test
  public void testOpenDead() {
    // TODO fail("not yet implemented");
  }

  @Test
  public void testOpenDeadWithTimestampPrecision() throws Exception {
    if (!Boolean.getBoolean(Constants.ENABLE_TIMESTAMP_PRECISION_TESTS_KEY)) {
      return;
    }

    MacAddress dstAddr = MacAddress.ETHER_BROADCAST_ADDRESS;
    MacAddress srcAddr = MacAddress.getByName("fe:00:00:00:00:01");

    ArpPacket.Builder ab =
        new ArpPacket.Builder()
            .hardwareType(ArpHardwareType.ETHERNET)
            .protocolType(EtherType.IPV4)
            .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
            .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
            .srcHardwareAddr(srcAddr)
            .dstHardwareAddr(dstAddr)
            .srcProtocolAddr(
                InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 0, (byte) 2, (byte) 1}))
            .dstProtocolAddr(
                InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 0, (byte) 2, (byte) 2}))
            .operation(ArpOperation.REQUEST);
    EthernetPacket.Builder eb =
        new EthernetPacket.Builder()
            .dstAddr(dstAddr)
            .srcAddr(srcAddr)
            .type(EtherType.ARP)
            .payloadBuilder(ab)
            .paddingAtBuild(true);
    Packet packet = eb.build();
    Instant ts = Instant.ofEpochSecond(1234567890L, 123456789L);

    PcapHandle phdMicro = Pcaps.openDead(DataLinkType.EN10MB, 65536, TimestampPrecision.MICRO);
    String tmpFile1 = File.createTempFile("pcap4jTest_", ".pcap").getAbsolutePath();
    PcapDumper dumperMicro = phdMicro.dumpOpen(tmpFile1);
    dumperMicro.dump(packet, ts);
    dumperMicro.close();
    phdMicro.close();
    PcapHandle phNano1 = Pcaps.openOffline(tmpFile1, TimestampPrecision.NANO);
    PcapPacket ppacket = phNano1.getNextPacket();
    assertEquals(1234567890L, ppacket.getTimestamp().getEpochSecond());
    assertEquals(123456000, ppacket.getTimestamp().getNano());
    phNano1.close();

    PcapHandle phdNano = Pcaps.openDead(DataLinkType.EN10MB, 65536, TimestampPrecision.NANO);
    String tmpFile2 = File.createTempFile("pcap4jTest_", ".pcap").getAbsolutePath();
    PcapDumper dumperNano = phdNano.dumpOpen(tmpFile2);
    dumperNano.dump(packet, ts);
    dumperNano.close();
    phdNano.close();
    PcapHandle phNano2 = Pcaps.openOffline(tmpFile2, TimestampPrecision.NANO);
    ppacket = phNano2.getNextPacket();
    assertEquals(1234567890L, ppacket.getTimestamp().getEpochSecond());
    assertEquals(123456789, ppacket.getTimestamp().getNano());
    phNano2.close();
  }

  @Test
  public void testDataLinkNameToVal() throws Exception {
    DataLinkType dlt = Pcaps.dataLinkNameToVal("EN10MB");
    assertEquals(DataLinkType.EN10MB, dlt);

    dlt = Pcaps.dataLinkNameToVal("PPP");
    assertEquals(DataLinkType.PPP, dlt);
  }

  @Test
  public void testDataLinkTypeToName() throws Exception {
    String name = Pcaps.dataLinkTypeToName(DataLinkType.EN10MB);
    logger.info(DataLinkType.EN10MB + " name: " + name);
    assertNotNull(name);
    assertFalse(name.length() == 0);
  }

  @Test
  public void testDataLinkValToName() throws Exception {
    String name = Pcaps.dataLinkValToName(DataLinkType.PPP.value());
    logger.info(DataLinkType.PPP + " name: " + name);
    assertNotNull(name);
    assertFalse(name.length() == 0);
  }

  @Test
  public void testDataLinkTypeToDescription() throws Exception {
    String descr = Pcaps.dataLinkTypeToDescription(DataLinkType.EN10MB);
    logger.info(DataLinkType.EN10MB + " descr: " + descr);
    assertNotNull(descr);
    assertFalse(descr.length() == 0);
  }

  @Test
  public void testDataLinkValToDescription() throws Exception {
    String descr = Pcaps.dataLinkValToDescription(DataLinkType.PPP.value());
    logger.info(DataLinkType.PPP + " descr: " + descr);
    assertNotNull(descr);
    assertFalse(descr.length() == 0);
  }

  @Test
  public void testStrError() throws Exception {
    String err = Pcaps.strError(1);
    logger.info("err: " + err);
    assertNotNull(err);
    assertFalse(err.length() == 0);
  }

  @Test
  public void testLibVersion() throws Exception {
    String ver = Pcaps.libVersion();
    logger.info("ver: " + ver);
    assertNotNull(ver);
    assertFalse(ver.length() == 0);
  }

  @Test
  public void testToBpfStringInetAddress() {
    // TODO fail("not yet implemented");
  }

  @Test
  public void testToBpfStringMacAddress() {
    // TODO fail("not yet implemented");
  }
}
