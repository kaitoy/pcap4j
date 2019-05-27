package org.pcap4j.core;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class PcapNetworkInterfaceTest {

  private static final Logger logger = LoggerFactory.getLogger(PcapNetworkInterfaceTest.class);

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {}

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Before
  public void setUp() throws Exception {}

  @After
  public void tearDown() throws Exception {}

  @Test
  public void testOpenLive() throws Exception {
    PcapHandle handle;
    try {
      handle = Pcaps.findAllDevs().get(0).openLive(55555, PromiscuousMode.PROMISCUOUS, 100);
    } catch (IndexOutOfBoundsException e) {
      return;
    } catch (PcapNativeException e) {
      assertTrue(
          "The exception should complain about permission to capture.",
          e.getMessage().contains("You don't have permission to capture on that device"));
      return;
    }

    assertNotNull(handle);
    assertTrue(handle.isOpen());

    logger.info(handle.toString());
  }
}
