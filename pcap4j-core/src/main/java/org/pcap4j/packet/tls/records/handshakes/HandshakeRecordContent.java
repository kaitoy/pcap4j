package org.pcap4j.packet.tls.records.handshakes;

import java.io.Serializable;

public interface HandshakeRecordContent extends Serializable {

    byte[] toByteArray();

}
