package org.pcap4j;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.sun.jna.Platform;
import org.junit.Before;
import org.junit.Test;

@SuppressWarnings("javadoc")
public class Pcap4jPropertiesLoaderTest {

  private Pcap4jPropertiesLoader propertiesLoader;

  @Before
  public void setUp() {
    this.propertiesLoader = Pcap4jPropertiesLoader.getInstance();
  }

  @Test
  public void testHasDefaultAfInet() {
    assertNotNull(propertiesLoader.getAfInet());
    assertEquals(2, (int) propertiesLoader.getAfInet());
  }

  @Test
  public void testHasDefaultAfInet6() {
    assertNotNull(propertiesLoader.getAfInet6());
    assertEquals(getExpectedDefaultAfInet6(), (int) propertiesLoader.getAfInet6());
  }

  @Test
  public void testHasDefaultAfPacket() {
    assertNotNull(propertiesLoader.getAfPacket());
    assertEquals(17, (int) propertiesLoader.getAfPacket());
  }

  @Test
  public void testHasDefaultAfLink() {
    assertNotNull(propertiesLoader.getAfLink());
    assertEquals(18, (int) propertiesLoader.getAfLink());
  }

  @Test
  public void testHasDefaultDltRaw() {
    assertNotNull(propertiesLoader.getDltRaw());
    assertEquals(getExpectedDefaultDltRaw(), (int) propertiesLoader.getDltRaw());
  }

  private int getExpectedDefaultAfInet6() {
    switch (Platform.getOSType()) {
      case Platform.MAC:
        return 30;
      case Platform.FREEBSD:
      case Platform.KFREEBSD:
        return 28;
      case Platform.LINUX:
      case Platform.ANDROID:
        return 10;
      default:
        return 23;
    }
  }

  private int getExpectedDefaultDltRaw() {
    switch (Platform.getOSType()) {
      case Platform.OPENBSD:
        return 14;
      default:
        return 12;
    }
  }
}
