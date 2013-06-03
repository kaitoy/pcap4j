package org.pcap4j.core;

import static org.junit.Assert.*;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class PcapHandleTest {

  private static final Logger logger
    = LoggerFactory.getLogger(PcapHandleTest.class);

  private PcapHandle ph;

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
  }

  @Before
  public void setUp() throws Exception {
    ph = Pcaps.findAllDevs().get(0)
           .openLive(55555, PromiscuousMode.PROMISCUOUS, 100);
  }

  @After
  public void tearDown() throws Exception {
    if (ph != null) {
      ph.close();
    }
  }

  @Test
  public void testGetStat() throws Exception {
    PcapStat ps = ph.getStat();
    assertNotNull(ps);
  }

  @Test
  public void testListDatalinks() throws Exception {
    List<DataLinkType> list = ph.listDatalinks();
    assertNotNull(list);
    for (DataLinkType type: list) {
      logger.info("A DLT supported by " + ph + ": " + type.toString());
    }
  }

  @Test
  public void testSetDlt() throws Exception {
    ph.setDlt(ph.getDlt());
  }

}
