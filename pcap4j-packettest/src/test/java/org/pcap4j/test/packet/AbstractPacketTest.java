package org.pcap4j.test.packet;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringReader;
import java.sql.Timestamp;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public abstract class AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(AbstractPacketTest.class);

  public static final String RESOURCE_DIR_PROP =
      AbstractPacketTest.class.getName() + ".resourceDir";
  public static final String TMP_DIR_PROP = AbstractPacketTest.class.getName() + ".tmpDir";

  private String originalLineSeparator;
  protected String resourceDirPath;
  protected String tmpDirPath;

  @Before
  public void setUp() throws Exception {
    originalLineSeparator = System.setProperty("line.separator", "\r\n");
    resourceDirPath = System.getProperty(RESOURCE_DIR_PROP, "src/test/resources");
    tmpDirPath = System.getProperty(TMP_DIR_PROP, "testdata");

    File tmpDir = new File(tmpDirPath);
    if (!tmpDir.exists()) {
      if (!tmpDir.mkdirs()) {
        throw new IOException("Failed to make a test diectory: " + tmpDirPath);
      }
    }
  }

  @After
  public void tearDown() throws Exception {
    System.setProperty("line.separator", originalLineSeparator);
    logger.info("==================================================");
  }

  protected abstract Packet getPacket() throws Exception;

  protected abstract Packet getWholePacket() throws Exception;

  @Test
  public void testGetBuilder() throws Exception {
    Packet.Builder ab = getPacket().getBuilder();
    assertEquals(getPacket(), ab.build());
  }

  @Test
  public void testLength() throws Exception {
    assertEquals(getPacket().getRawData().length, getPacket().length());
  }

  @Test
  public void testToString() throws Exception {
    FileReader fr =
        new FileReader(
            new StringBuilder()
                .append(resourceDirPath)
                .append("/")
                .append(getClass().getSimpleName())
                .append(".log")
                .toString());
    BufferedReader fbr = new BufferedReader(fr);
    StringReader sr = new StringReader(getPacket().toString());
    BufferedReader sbr = new BufferedReader(sr);

    String line;
    while ((line = fbr.readLine()) != null) {
      assertEquals(line, sbr.readLine());
    }

    assertNull(sbr.readLine());

    fbr.close();
    fr.close();
    sr.close();
    sbr.close();
  }

  @Test
  public void testDump() throws Exception {
    String dumpFile =
        new StringBuilder()
            .append(tmpDirPath)
            .append("/")
            .append(getClass().getSimpleName())
            .append(".pcap")
            .toString();
    Packet p = getWholePacket();

    PcapHandle handle = Pcaps.openDead(getDataLinkType(), 65536);
    PcapDumper dumper = handle.dumpOpen(dumpFile);
    dumper.dump(p, new Timestamp(0));
    dumper.close();
    handle.close();

    PcapHandle reader = Pcaps.openOffline(dumpFile);
    assertEquals(p, reader.getNextPacket());
    reader.close();

    FileInputStream in1 =
        new FileInputStream(
            new StringBuilder()
                .append(resourceDirPath)
                .append("/")
                .append(getClass().getSimpleName())
                .append(".pcap")
                .toString());
    FileInputStream in2 = new FileInputStream(dumpFile);

    byte[] buffer1 = new byte[100];
    byte[] buffer2 = new byte[100];
    int size;
    while ((size = in1.read(buffer1)) != -1) {
      assertEquals(size, in2.read(buffer2));
      assertArrayEquals(buffer1, buffer2);
    }

    in1.close();
    in2.close();
  }

  protected DataLinkType getDataLinkType() {
    return DataLinkType.EN10MB;
  }

  @Test
  public void testWriteRead() throws Exception {
    String objFile =
        new StringBuilder()
            .append(tmpDirPath)
            .append("/")
            .append(getClass().getSimpleName())
            .append(".obj")
            .toString();

    ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File(objFile)));
    oos.writeObject(getPacket());
    oos.close();

    ObjectInputStream ois1 = new ObjectInputStream(new FileInputStream(new File(objFile)));
    assertEquals(getPacket(), ois1.readObject());
    ois1.close();

    ObjectInputStream ois2 =
        new ObjectInputStream(
            new FileInputStream(
                new File(
                    new StringBuilder()
                        .append(resourceDirPath)
                        .append("/")
                        .append(getClass().getSimpleName())
                        .append(".obj")
                        .toString())));
    assertEquals(getPacket(), ois2.readObject());
    ois2.close();
  }
}
