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

/**
 * @author Kaito
 *
 */
public class PcapNetworkInterfaceTest {

  private static final Logger logger
    = LoggerFactory.getLogger(PcapNetworkInterfaceTest.class);

  /**
   * @throws java.lang.Exception
   */
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
  }

  /**
   * @throws java.lang.Exception
   */
  @AfterClass
  public static void tearDownAfterClass() throws Exception {
  }

  /**
   * @throws java.lang.Exception
   */
  @Before
  public void setUp() throws Exception {
  }

  /**
   * @throws java.lang.Exception
   */
  @After
  public void tearDown() throws Exception {
  }

  /**
   * {@link org.pcap4j.core.PcapNetworkInterface#openLive(int, org.pcap4j.core.PcapNetworkInterface.PromiscuousMode, int)} のためのテスト・メソッド。
   */
  @Test
  public void testOpenLive() throws Exception {
    PcapHandle handle =
      Pcaps.findAllDevs().get(0)
        .openLive(55555, PromiscuousMode.PROMISCUOUS, 100);

    assertNotNull(handle);
    assertTrue(handle.isOpening());

    logger.info(handle.toString());
  }

}
