package org.pcap4j;

import com.sun.jna.Platform;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.pcap4j.util.PropertiesLoader;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.rule.PowerMockRule;
import org.powermock.reflect.Whitebox;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.pcap4j.Pcap4jPropertiesLoader.PCAP4J_PROPERTIES_PATH_KEY;

@RunWith(Parameterized.class)
@PrepareForTest(Platform.class)
public class Pcap4jPropertiesLoaderTest {

    private Pcap4jPropertiesLoader propertiesLoader;

    private final int osType;

    @Rule
    public PowerMockRule powerMockRule = new PowerMockRule();

    public Pcap4jPropertiesLoaderTest(int osType) {
        this.osType = osType;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> osType() {
        return Arrays.asList(new Object[][]{
                {Platform.WINDOWS},
                {Platform.MAC},
                {Platform.LINUX},
                {Platform.FREEBSD},
                {Platform.OPENBSD}
        });
    }

    @Before
    public void setUp() throws Exception {
        PowerMockito.mockStatic(Platform.class);
        PowerMockito.when(Platform.getOSType()).thenReturn(osType);

        this.propertiesLoader = Pcap4jPropertiesLoader.getInstance();

        Whitebox.setInternalState(propertiesLoader, "loader",
                new PropertiesLoader("org/pcap4j/pcap4j-test.properties", false, false));
    }

    @Test
    public void testHasDefaultAfInet() {
        assertNotNull(propertiesLoader.getAfInet());
        assertEquals(2, (int)propertiesLoader.getAfInet());
    }

    @Test
    public void testHasDefaultAfInet6() {
        assertNotNull(propertiesLoader.getAfInet6());
        assertEquals(getExpectedDefaultAfInet6(), (int)propertiesLoader.getAfInet6());
    }

    @Test
    public void testHasDefaultAfPacket() {
        assertNotNull(propertiesLoader.getAfPacket());
        assertEquals(17, (int)propertiesLoader.getAfPacket());
    }

    @Test
    public void testHasDefaultAfLink() {
        assertNotNull(propertiesLoader.getAfLink());
        assertEquals(18, (int)propertiesLoader.getAfLink());
    }

    @Test
    public void testHasDefaultDltRaw() {
        assertNotNull(propertiesLoader.getDltRaw());
        assertEquals(getExpectedDefaultDltRaw(), (int)propertiesLoader.getDltRaw());
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
