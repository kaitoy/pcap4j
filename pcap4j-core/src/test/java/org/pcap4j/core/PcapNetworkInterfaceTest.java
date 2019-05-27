package org.pcap4j.core;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class PcapNetworkInterfaceTest {

  private static final Logger logger = LoggerFactory.getLogger(PcapNetworkInterfaceTest.class);

  @BeforeAll
  public static void setUpBeforeClass() throws Exception {}

  @AfterAll
  public static void tearDownAfterClass() throws Exception {}

  @BeforeEach
  public void setUp() throws Exception {}

  @AfterEach
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
          e.getMessage().contains("You don't have permission to capture on that device"),
          "The exception should complain about permission to capture.");
      return;
    }

    assertNotNull(handle);
    assertTrue(handle.isOpen());

    logger.info(handle.toString());
  }
}
