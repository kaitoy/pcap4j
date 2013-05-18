package org.pcap4j.core;

import static org.junit.Assert.*;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
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
  public void testToBpfStringInetAddress() {
    // TODO fail("not yet implemented");
  }

  @Test
  public void testToBpfStringMacAddress() {
    // TODO fail("not yet implemented");
  }

}
