package org.pcap4j.core;

import static org.junit.Assert.*;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class PcapsTest {

  private static final Logger logger
    = LoggerFactory.getLogger(PcapsTest.class);

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
  }

  @Before
  public void setUp() throws Exception {
  }

  @After
  public void tearDown() throws Exception {
  }

  @Test
  public void testFindAllDevs() throws Exception {
    List<PcapNetworkInterface> devs = Pcaps.findAllDevs();
    assertNotNull(devs);
    assertTrue(devs.size() != 0);

    for (PcapNetworkInterface dev: devs) {
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
    String dev = Pcaps.lookupDev();
    assertNotNull(dev);
    assertTrue(dev.length() != 0);
    logger.info(Pcaps.lookupDev());
  }

  @Test
  public void testOpenOffline() {
    // TODO fail("not yet implemented");
  }

  @Test
  public void testOpenDead() {
    // TODO fail("not yet implemented");
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
