package org.pcap4j.core;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito
 *
 */
public class PcapsTest {

  private static final Logger logger
    = LoggerFactory.getLogger(PcapsTest.class);

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
   * {@link org.pcap4j.core.Pcaps#findAllDevs()} のためのテスト・メソッド。
   */
  @Test
  public void testFindAllDevs() throws Exception {
    List<PcapNetworkInterface> devs = Pcaps.findAllDevs();
    assertNotNull(devs);
    assertTrue(devs.size() != 0);

    for (PcapNetworkInterface dev: devs) {
      logger.info(dev.toString());
    }
  }

  /**
   * {@link org.pcap4j.core.Pcaps#getNifByAddress(java.net.InetAddress)} のためのテスト・メソッド。
   */
  @Test
  public void testGetNifByInetAddress() {
    // TODO fail("まだ実装されていません");
  }

  /**
   * {@link org.pcap4j.core.Pcaps#getNifByName(java.lang.String)} のためのテスト・メソッド。
   */
  @Test
  public void testGetNifByString() {
     // TODO fail("まだ実装されていません");
  }

  /**
   * {@link org.pcap4j.core.Pcaps#lookupDev()} のためのテスト・メソッド。
   */
  @Test
  public void testLookupDev() throws Exception {
    String dev = Pcaps.lookupDev();
    assertNotNull(dev);
    assertTrue(dev.length() != 0);
    logger.info(Pcaps.lookupDev());
  }

  /**
   * {@link org.pcap4j.core.Pcaps#openOffline(java.lang.String)} のためのテスト・メソッド。
   */
  @Test
  public void testOpenOffline() {
    // TODO fail("まだ実装されていません");
  }

  /**
   * {@link org.pcap4j.core.Pcaps#openDead(org.pcap4j.packet.namednumber.DataLinkType, int)} のためのテスト・メソッド。
   */
  @Test
  public void testOpenDead() {
    // TODO fail("まだ実装されていません");
  }

  /**
   * {@link org.pcap4j.core.Pcaps#toBpfString(java.net.InetAddress)} のためのテスト・メソッド。
   */
  @Test
  public void testToBpfStringInetAddress() {
    // TODO fail("まだ実装されていません");
  }

  /**
   * {@link org.pcap4j.core.Pcaps#toBpfString(org.pcap4j.util.MacAddress)} のためのテスト・メソッド。
   */
  @Test
  public void testToBpfStringMacAddress() {
    // TODO fail("まだ実装されていません");
  }

}
