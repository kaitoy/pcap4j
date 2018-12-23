package org.pcap4j.core;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
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
public class PcapDumperTest {

  private static final Logger logger = LoggerFactory.getLogger(PcapDumperTest.class);

  private static final String TMP_DIR_PROP = PcapDumperTest.class.getName() + ".tmpDir";

  private String tmpDirPath;
  private File dumpFile;
  private static final Packet packet;
  private PcapHandle handle;
  private PcapDumper dumper;

  static {
    try {
      ArpPacket.Builder ab = new ArpPacket.Builder();
      ab.hardwareType(ArpHardwareType.ETHERNET)
          .protocolType(EtherType.IPV4)
          .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
          .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
          .srcHardwareAddr(MacAddress.getByName("fe:00:00:00:00:01"))
          .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
          .srcProtocolAddr(InetAddress.getByName("192.0.2.1"))
          .dstProtocolAddr(InetAddress.getByName("192.0.2.2"))
          .operation(ArpOperation.REQUEST);
      EthernetPacket.Builder eb = new EthernetPacket.Builder();
      eb.dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
          .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
          .type(EtherType.ARP)
          .payloadBuilder(ab)
          .paddingAtBuild(true);
      packet = eb.build();
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {}

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Before
  public void setUp() throws Exception {
    tmpDirPath = System.getProperty(TMP_DIR_PROP, "testdata");

    File tmpDir = new File(tmpDirPath);
    if (!tmpDir.exists()) {
      if (!tmpDir.mkdirs()) {
        throw new IOException("Failed to make a test diectory: " + tmpDirPath);
      }
    }

    dumpFile = new File(tmpDirPath + "/" + PcapDumperTest.class.getSimpleName() + ".pcap");

    dumpFile.delete();
    handle = Pcaps.openDead(DataLinkType.EN10MB, 65536);
    dumper = handle.dumpOpen(dumpFile.getAbsolutePath());
  }

  @After
  public void tearDown() throws Exception {
    if (dumper != null) {
      dumper.close();
    }
    if (handle != null) {
      handle.close();
    }
    dumpFile.delete();
  }

  @Test
  public void testDump() throws Exception {
    dumper.dump(packet);
    dumper.flush();
    assertTrue(dumpFile.exists());
    assertTrue(dumpFile.length() >= packet.length());
  }

  @Test
  public void testFtell() throws Exception {
    long initialPosition = dumper.ftell();
    logger.info("initialPosition: " + initialPosition);

    dumper.dump(packet);
    long position = dumper.ftell();
    logger.info("position: " + position);
    assertTrue(position >= initialPosition);
    assertTrue(position >= packet.length());
  }
}
