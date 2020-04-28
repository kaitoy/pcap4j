package org.pcap4j.packet.tls.records;

import java.io.Serializable;

public interface TlsRecord extends Serializable {

    byte[] toByteArray();

}
