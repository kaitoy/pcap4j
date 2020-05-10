package org.pcap4j.test.packet;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.tls.*;
import org.pcap4j.packet.tls.extensions.TlsExtension;
import org.pcap4j.packet.tls.extensions.UnimplementedTlsExtension;
import org.pcap4j.packet.tls.extensions.keyshare.KeyShareEntry;
import org.pcap4j.packet.tls.extensions.keyshare.ServerKeyShareExtension;
import org.pcap4j.packet.tls.records.AlertRecord;
import org.pcap4j.packet.tls.records.ApplicationDataRecord;
import org.pcap4j.packet.tls.records.HandshakeRecord;
import org.pcap4j.packet.tls.records.TlsRecord;
import org.pcap4j.packet.tls.records.handshakes.HandshakeRecordContent;
import org.pcap4j.packet.tls.records.handshakes.ServerHelloHandshakeRecordContent;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class TlsPacketTest extends AbstractPacketTest {

    private static final Logger logger = LoggerFactory.getLogger(TlsPacketTest.class);

    private final TlsPacket packet;

    public TlsPacketTest() {
        TlsPacket.Builder b = new TlsPacket.Builder();
        byte[] random = new byte[32];
        byte[] sessionId = new byte[32];
        Arrays.fill(random, (byte) 0x11);
        Arrays.fill(sessionId, (byte) 0x22);

        TlsExtension paddingExtension = new UnimplementedTlsExtension(
                ExtensionType.PADDING,
                (short) 3,
                new byte[]{0, 0, 0});

        TlsExtension keyShareExtension = new ServerKeyShareExtension(
                ExtensionType.KEY_SHARE,
                (short) 8,
                Collections.singletonList(new KeyShareEntry(KeyGroup.X25519, (short) 4, new byte[]{1, 2, 3, 4}))
        );

        HandshakeRecordContent handshakeRecordContent = new ServerHelloHandshakeRecordContent(
                TlsVersion.TLS_1_0,
                random,
                sessionId,
                (short) 19,
                Arrays.asList(keyShareExtension, paddingExtension),
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                CompressionMethod.NULL
        );

        TlsRecord handshakeRecord = new HandshakeRecord(
                HandshakeType.SERVER_HELLO,
                91,
                handshakeRecordContent);

        TlsRecord dataRecord = new ApplicationDataRecord(new byte[]{1, 2, 3, 4, 5});

        TlsRecord alertRecord = new AlertRecord(AlertLevel.WARNING, AlertDescription.unknown_ca);

        b.contentType(ContentType.HANDSHAKE)
                .version(TlsVersion.TLS_1_2)
                .recordLength((short) 95)
                .record(handshakeRecord)
                .payloadBuilder(new TlsPacket.Builder()
                        .version(TlsVersion.TLS_1_2)
                        .contentType(ContentType.APPLICATION_DATA)
                        .recordLength((short) 5)
                        .record(dataRecord)
                        .payloadBuilder(new TlsPacket.Builder()
                                .version(TlsVersion.TLS_1_2)
                                .contentType(ContentType.ALERT)
                                .recordLength((short) 2)
                                .record(alertRecord)));

        this.packet = b.build();
    }

    @Test
    public void testNewPacket() {
        try {
            TlsPacket p = TlsPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
            assertEquals(packet, p);
        } catch (IllegalRawDataException e) {
            throw new AssertionError(e);
        }
    }

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        logger.info("########## " + TlsPacketTest.class.getSimpleName() + " START ##########");
    }

    @AfterClass
    public static void tearDownAfterClass() throws Exception {
        logger.info("########## " + TlsPacketTest.class.getSimpleName() + " END ##########");
    }

    @Override
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
        assertEquals(p, prepareWholePacket(reader.getNextPacket()));
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

    private Packet prepareWholePacket(Packet p) throws IllegalRawDataException {
        TcpPacket tcpPacket = p.get(TcpPacket.class);
        byte[] tcpData = tcpPacket.getPayload().getRawData();
        TlsPacket tlsPacket = TlsPacket.newPacket(tcpData, 0, tcpData.length);
        TcpPacket.Builder newTcpPacketB = tcpPacket.getBuilder()
                .payloadBuilder(tlsPacket.getBuilder());
        IpV4Packet.Builder newIpv4PacketB = p.get(IpV4Packet.class).getBuilder()
                .payloadBuilder(newTcpPacketB);
        return p.get(EthernetPacket.class).getBuilder()
                .payloadBuilder(newIpv4PacketB)
                .build();
    }

    @Override
    protected Packet getPacket() throws Exception {
        return packet;
    }

    @Override
    protected Packet getWholePacket() throws Exception {
        Inet4Address srcAddr;
        Inet4Address dstAddr;
        try {
            srcAddr = (Inet4Address) InetAddress.getByName("192.168.0.1");
            dstAddr = (Inet4Address) InetAddress.getByName("192.168.0.2");
        } catch (Exception e) {
            throw new AssertionError("Never get here.");
        }

        TcpPacket.Builder b = new TcpPacket.Builder();
        b.dstPort(TcpPort.HTTPS)
                .srcPort(TcpPort.getInstance((short) 12345))
                .srcAddr(srcAddr)
                .dstAddr(dstAddr)
                .sequenceNumber(0)
                .acknowledgmentNumber(0)
                .dataOffset((byte) 0)
                .reserved((byte) 0)
                .urg(false)
                .ack(false)
                .psh(false)
                .rst(false)
                .syn(false)
                .fin(false)
                .window((short) 0)
                .checksum((short) 0)
                .urgentPointer((short) 0)
                .options(Collections.<TcpPacket.TcpOption>emptyList())
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .paddingAtBuild(true)
                .payloadBuilder(packet.getBuilder());

        IpV4Packet.Builder IpV4b = new IpV4Packet.Builder();
        IpV4b.version(IpVersion.IPV4)
                .tos(IpV4Rfc1349Tos.newInstance((byte) 0))
                .identification((short) 100)
                .ttl((byte) 100)
                .protocol(IpNumber.TCP)
                .srcAddr(srcAddr)
                .dstAddr(dstAddr)
                .payloadBuilder(b)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .paddingAtBuild(true);

        EthernetPacket.Builder eb = new EthernetPacket.Builder();
        eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
                .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
                .type(EtherType.IPV4)
                .payloadBuilder(IpV4b)
                .paddingAtBuild(true);

        return eb.build();
    }
}
