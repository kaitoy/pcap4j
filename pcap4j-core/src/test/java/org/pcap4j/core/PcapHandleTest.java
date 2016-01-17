package org.pcap4j.core;

import static org.junit.Assert.*;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.DataLinkType;

@SuppressWarnings("javadoc")
public class PcapHandleTest {

  private PcapHandle ph;

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
  }

  @Before
  public void setUp() throws Exception {
    ph = Pcaps.openOffline(
           "src/test/resources/org/pcap4j/core/PcapHandleTest.pcap"
         );
  }

  @After
  public void tearDown() throws Exception {
    if (ph != null) {
      ph.close();
    }
  }

  @Test
  public void testGetStats() throws Exception {
    if (ph != null) {
      ph.close();
    }

    List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();
    if (nifs.isEmpty()) {
      ph = Pcaps.openDead(DataLinkType.EN10MB, 2048);
      try {
        ph.getStats();
        fail("getStats on a pcap_open_dead pcap_t should throw a PcapNativeException.");
      } catch (PcapNativeException e) {
        assertEquals("Statistics aren't available from a pcap_open_dead pcap_t", e.getMessage());
      }
    }
    else {
      ph = nifs.get(0).openLive(55555, PromiscuousMode.PROMISCUOUS, 100);
      PcapStat ps = ph.getStats();
      assertNotNull(ps);
    }
  }

  @Test
  public void testListDatalinks() throws Exception {
    List<DataLinkType> list = ph.listDatalinks();
    assertNotNull(list);
    assertEquals(1, list.size());
    assertEquals(DataLinkType.EN10MB, list.get(0));
  }

  @Test
  public void testSetDlt() throws Exception {
    ph.setDlt(ph.getDlt());
  }

  @Test
  public void testGetTimestamp() throws Exception {
    assertNull(ph.getTimestamp());
    ph.getNextPacket();
    assertEquals(1434220771517L, ph.getTimestamp().getTime());
  }

  @Test
  public void testGetTimestampEx() throws Exception {
    assertNull(ph.getTimestamp());
    ph.getNextPacketEx();
    assertEquals(1434220771517L, ph.getTimestamp().getTime());
  }

  @Test
  public void testGetTimestampRaw() throws Exception {
    assertNull(ph.getTimestamp());
    ph.getNextRawPacket();
    assertEquals(1434220771517L, ph.getTimestamp().getTime());
  }

  @Test
  public void testGetTimestampLoop() throws Exception {
    assertNull(ph.getTimestamp());
    ph.loop(1, new PacketListener() {
      @Override
      public void gotPacket(Packet packet) {
        assertEquals(1434220771517L, ph.getTimestamp().getTime());
      }
    });
  }

  @Test
  public void testGetTimestampLoopRaw() throws Exception {
    assertNull(ph.getTimestamp());
    ph.loop(1, new RawPacketListener() {
      @Override
      public void gotPacket(byte[] packet) {
        assertEquals(1434220771517L, ph.getTimestamp().getTime());
      }
    });
  }

  @Test
  public void testGetTimestampRawEx() throws Exception {
    assertNull(ph.getTimestamp());
    ph.getNextRawPacketEx();
    assertEquals(1434220771517L, ph.getTimestamp().getTime());
  }

  @Test
  public void testGetOriginalLength() throws Exception {
    assertNull(ph.getOriginalLength());
    Packet packet = ph.getNextPacket();
    assertEquals(new Integer(74), ph.getOriginalLength());
    assertEquals(packet.length(), ph.getOriginalLength().intValue());
  }

  @Test
  public void testGetOriginalLengthEx() throws Exception {
    assertNull(ph.getOriginalLength());
    Packet packet = ph.getNextPacketEx();
    assertEquals(new Integer(74), ph.getOriginalLength());
    assertEquals(packet.length(), ph.getOriginalLength().intValue());
  }

  @Test
  public void testGetOriginalLengthRaw() throws Exception {
    assertNull(ph.getOriginalLength());
    byte[] packet = ph.getNextRawPacket();
    assertEquals(new Integer(74), ph.getOriginalLength());
    assertEquals(packet.length, ph.getOriginalLength().intValue());
  }

  @Test
  public void testGetOriginalLengthRawEx() throws Exception {
    assertNull(ph.getOriginalLength());
    byte[] packet = ph.getNextRawPacketEx();
    assertEquals(new Integer(74), ph.getOriginalLength());
    assertEquals(packet.length, ph.getOriginalLength().intValue());
  }

  @Test
  public void testGetOriginalLengthLoop() throws Exception {
    assertNull(ph.getOriginalLength());
    ph.loop(1, new PacketListener() {
      @Override
      public void gotPacket(Packet packet) {
        assertEquals(new Integer(74), ph.getOriginalLength());
        assertEquals(packet.length(), ph.getOriginalLength().intValue());
      }
    });
  }

  @Test
  public void testGetOriginalLengthLoopRaw() throws Exception {
    assertNull(ph.getOriginalLength());
    ph.loop(1, new RawPacketListener() {
      @Override
      public void gotPacket(byte[] packet) {
        assertEquals(new Integer(74), ph.getOriginalLength());
        assertEquals(packet.length, ph.getOriginalLength().intValue());
      }
    });
  }

}
