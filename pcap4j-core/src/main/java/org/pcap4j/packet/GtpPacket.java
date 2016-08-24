/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.ChecksumBuilder;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.namednumber.GtpVersion;
import org.pcap4j.packet.namednumber.GtpCode;
import org.pcap4j.packet.namednumber.GtpMSGType;
import org.pcap4j.packet.IncorrectGTPVersionException;
import org.pcap4j.packet.IncorrectGTPCodeException;
import org.pcap4j.packet.IncorrectMSGTypeException;
import org.pcap4j.packet.LengthBuilder;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.PacketPropertiesLoader;
import org.pcap4j.packet.factory.PacketFactories;

import org.pcap4j.util.ByteArrays;

/**
 * @author Waveform
 *
 */
public final class GtpPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 4638029542367352625L;

  private final GtpHeader header;
  private final Packet payload;

  /**
   * A static factory method.
   * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
   * which may throw exceprotocol_typeions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new GtpPacket object.
   * @throws IllegalRawDataExceprotocol_typeion if parsing the raw data fails.
   */
  public static GtpPacket newPacket(
    byte[] rawData, int offset, int length
  ) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new GtpPacket(rawData, offset, length);
  }

  private GtpPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new GtpHeader(rawData, offset, length);

    int payloadLength = header.getLengthAsInt() - header.length();
    if (payloadLength < 0) {
      throw new IllegalRawDataException(
              "The value of length field seems to be wrong: "
                + header.getLengthAsInt()
            );
    }

    if (payloadLength > length - header.length()) {
      payloadLength = length - header.length();
    }

    if (payloadLength != 0) { 
      this.payload = null;
      
    }
    else {
      this.payload = null;
    }
  }

  private GtpPacket(Builder builder) {
    if (
         builder == null
    
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder);
        
      throw new NullPointerException(sb.toString());
    }

 

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new GtpHeader(
                    builder,
                    payload != null ? payload.getRawData() : new byte[0]
                  );
  }

  @Override
  public GtpHeader getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  /**
   *
   * 
   *
   * @param srcAddr srcAddr
   * @param dstAddr dstAddr
   * @param acceprotocol_typeZero acceprotocol_typeZero
   * @return true if the packet represented by this object has a valid checksum;
   *         false otherwise.
   */
  

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Waveform
   *
   */
  public static final
  class Builder extends AbstractBuilder
  implements LengthBuilder<GtpPacket> {

	private GtpVersion version;
    private GtpCode protocol_type;
    private boolean reserved_x;
    private boolean seq;
    private boolean ext;
    private boolean pn;
    private GtpMSGType message_type;
    private short length;
    private int te_id;
    private short seq_num;
    private byte npd_num;
    private byte nxt_ext;
    private boolean correctLengthAtBuild;
    private Packet.Builder payloadBuilder;
 

    /**
     *
     */
    public Builder() {}

    /**
     *
     * @param packet packet
     */
    public Builder(GtpPacket packet) {
      this.protocol_type = packet.header.protocol_type;
      this.version = packet.header.version;
      this.reserved_x = packet.header.reserved_x;
      this.length = packet.header.length;
      this.message_type= packet.header.message_type;
      this.pn = packet.header.pn;
      this.seq_num = packet.header.seq_num;
      this.npd_num = packet.header.npd_num;
      this.nxt_ext = packet.header.nxt_ext;
      this.seq = packet.header.seq;
      this.te_id = packet.header.te_id;
      this.ext = packet.header.ext;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     *
     * @param protocol_type protocol_type
     * @return this Builder object for method chaining.
     */
    public Builder protocol_type(GtpCode protocol_type) {
      this.protocol_type = GtpCode.getInstance(version, protocol_type.value());
      return this;
    }

    /**
     *
     * @param reserved_x reserved_x
     * @return this Builder object for method chaining.
     */
    public Builder reserverd_x(boolean reserved_x) {
      this.reserved_x = reserved_x;;
      return this;
    }

    /**
     *
     * @param length length
     * @return this Builder object for method chaining.
     */
    public Builder length(short length) {
      this.length = length;
      return this;
    }

    /**
     *
     * @param ext ext
     * @return this Builder object for method chaining.
     */
    public Builder ext(boolean ext) {
      this.ext = ext;
      return this;
    }
    
    /**
     *
     * @param seq seq
     * @return this Builder object for method chaining.
     */
    public Builder seq(boolean seq) {
      this.seq = seq;
      return this;
    }
    
    /**
     *
     * @param pn pn
     * @return this Builder object for method chaining.
     */
    public Builder pn(boolean pn) {
      this.pn = pn;
      return this;
    }
    
    /**
     *
     * @param message_type message_type
     * @return this Builder object for method chaining.
     */
    public Builder message_type(GtpMSGType message_type) {
     
      this.message_type = GtpMSGType.getInstance(this.protocol_type,message_type.value());
      return this;
    }

    /**
     *
     * @param te_id te_id
     * @return this Builder object for method chaining.
     */
    public Builder te_id(int te_id) {
      this.te_id = te_id;
      return this;
    }

    /**
     *
     * @param seq_num seq_num
     * @return this Builder object for method chaining.
     */
    public Builder seq_num(short seq_num) {
      this.seq_num = seq_num;
      return this;
    }

    /**
     *
     * @param npd_num npd_num
     * @return this Builder object for method chaining.
     */
    public Builder npd_num(byte npd_num) {
      this.npd_num= npd_num;
      return this;
    }

    /**
     *
     * @param nxt_ext nxt_ext
     * @return this Builder object for method chaining.
     */
    public Builder nxt_ext(byte nxt_ext) {
      this.nxt_ext = nxt_ext;
      return this;
    }
    
    /**
    *
    * @param version version
    * @return this Builder object for method chaining.
    */
   public Builder version(GtpVersion version) {
     this.version = GtpVersion.getInstance(version.value());
     return this;
   }

    @Override
    public Builder payloadBuilder(Packet.Builder payloadBuilder) {
      this.payloadBuilder = payloadBuilder;
      return this;
    }

    @Override
    public Packet.Builder getPayloadBuilder() {
      return payloadBuilder;
    }

       @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }


    @Override
    public GtpPacket build() {
      return new GtpPacket(this);
    }

  }

  /**
   * @author Waveform
   *
   */
  public static final class GtpHeader extends AbstractHeader {
	  
	  

    /*
     *                  GTP-U Header format
     * 
     *   8     7     6     5     4     3     2     1                  
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |    Version    |  PT  | (*) |  E  |  S  |  PN  |        
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                 Message Type                  |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |              Length (1st Octet)               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |              Length (2nd Octet)               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |    Tunnel Endpoint Identifier (1st Octet)     |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |    Tunnel Endpoint Identifier (2nd Octet)     |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |    Tunnel Endpoint Identifier (3rd Octet)     |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |    Tunnel Endpoint Identifier (4th Octet)     |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |          Sequence Number (1st Octet)          |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |          Sequence Number (2nd Octet)          |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                 N-PDU Number                  |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |          Next Extension Header Type           |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    /*
     *             Extension Header Format
     *
     * 8                                               1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |           Extension Header Length             |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |           Extension Header Content            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |             Next Extension Header             |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     *           UDP Extension Pseudo Header
     *                      
     * 8                                               1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                     0x40                      |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |            UDP Source Port Number             |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |             Next Extension Header             |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
    
     */

    /**
     *
     */
    private static final long serialVersionUID = -1746545325551976324L;

    private static final int FIRST_OCTET_OFFSET
      = 0;
    private static final int FIRST_OCTET_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int MSG_TYPE_OFFSET
      = FIRST_OCTET_OFFSET + FIRST_OCTET_SIZE;
    private static final int MSG_TYPE_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int LENGTH_OFFSET
      = MSG_TYPE_OFFSET + MSG_TYPE_SIZE;
    private static final int LENGTH_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int TUNNEL_ID_OFFSET
      = LENGTH_OFFSET + LENGTH_SIZE;
    private static final int TUNNEL_ID_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int SEQ_OFFSET
    = TUNNEL_ID_OFFSET + TUNNEL_ID_SIZE;
    private static final int SEQ_SIZE
    = SHORT_SIZE_IN_BYTES;
    private static final int NPDU_OFFSET
    = SEQ_OFFSET + SEQ_SIZE;
    private static final int NPDU_SIZE
    = BYTE_SIZE_IN_BYTES;
    private static final int NEXT_HEADER_OFFSET
    = NPDU_OFFSET + NPDU_SIZE;
    private static final int NEXT_HEADER_SIZE
    = BYTE_SIZE_IN_BYTES;
    private static final int GTP_HEADER_SIZE
      = NEXT_HEADER_OFFSET + NEXT_HEADER_SIZE;

    private static final int IPV4_PSEUDO_HEADER_SIZE = 12;
    private static final int IPV6_PSEUDO_HEADER_SIZE = 40;

    private final GtpVersion version;
    private final GtpCode protocol_type;
    private final boolean reserved_x;
    private final boolean seq;
    private final boolean ext;
    private final boolean pn;
    private final GtpMSGType message_type;
    private final short length;
    private final int te_id;
    private final short seq_num;
    private final byte npd_num;
    private final byte nxt_ext;
    

    private GtpHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      if (length < GTP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build a GTP header(")
          .append(GTP_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
        throw new IllegalRawDataException(sb.toString());
      }
      byte first_octet_flags=ByteArrays.getByte(rawData, FIRST_OCTET_OFFSET+offset);
      this.version = GtpVersion.getInstance((byte) ((first_octet_flags & 0x0e0)>>5));
      this.protocol_type = GtpCode.getInstance(version,(byte)((first_octet_flags & 0x10)>>4));
      this.reserved_x = ((first_octet_flags & 0x08)>>3)!=0;
      this.ext = ((first_octet_flags & 0x04)>>2)!=0;
      this.seq = ((first_octet_flags & 0x02)>>1)!=0;
      this.pn = (first_octet_flags & 0x01)!=0;
      
      this.message_type=GtpMSGType.getInstance(protocol_type,ByteArrays.getByte(rawData, MSG_TYPE_OFFSET+offset));
      
      this.length = ByteArrays.getShort(rawData, LENGTH_OFFSET+offset);
      
      this.te_id = ByteArrays.getInt(rawData, TUNNEL_ID_OFFSET+offset);
      
      this.seq_num = ByteArrays.getShort(rawData, SEQ_OFFSET+offset);
      
      this.npd_num = ByteArrays.getByte(rawData, NPDU_OFFSET+offset);
      
      this.nxt_ext = ByteArrays.getByte(rawData, NEXT_HEADER_OFFSET+offset);
      
    }

    private GtpHeader(Builder builder, byte[] payload) {
    	this.protocol_type = builder.protocol_type;
    	this.version = builder.version;
        this.reserved_x = builder.reserved_x;
        this.message_type= builder.message_type;
        this.pn = builder.pn;
        this.seq_num = builder.seq_num;
        this.npd_num = builder.npd_num;
        this.nxt_ext = builder.nxt_ext;
        this.seq = builder.seq;
        this.te_id = builder.te_id;
        this.ext = builder.ext;

      if (builder.correctLengthAtBuild) 
      {
        this.length = (short)((payload.length + getLength()));
       
      }
      else 
      {
        this.length = builder.length;
      }

   
      
    }

 

    /**
     *
     * @return protocol_type
     */
    public GtpCode getprotocol_type() {
      return protocol_type;
    }

    /**
     *
     * @return reserved_x
     */
    public boolean getreserved_x() {
      return reserved_x;
    }
    
    /**
    *
    * @return ext
    */
   public boolean getext() {
     return ext;
   }

   /**
    *
    * @return seq
    */
   public boolean getseq() {
     return seq;
   }

   /**
    *
    * @return pn
    */
   public boolean getpn() {
     return pn;
   }

   /**
    *
    * @return message_type
    */
   public GtpMSGType getmsgtype() {
     return message_type;
   }

   /**
    *
    * @return te_id
    */
   public int getteid() {
     return te_id;
   }
   

   /**
    *
    * @return seq_num
    */
   public short getseqnum() {
     return seq_num;
   }

   /**
    *
    * @return npd_num
    */
   public byte getnpdnum() {
     return npd_num;
   }
   

   /**
    *
    * @return nxt_ext
    */
   public byte getnxtext() {
     return nxt_ext;
   }

   /**
    *
    * @return version
    */
   public GtpVersion getversion() {
     return version;
   }
   
    /**
     *
     * @return length
     */
    public short getLength() {
      return SEQ_SIZE+NPDU_SIZE+NEXT_HEADER_SIZE;
    }

    /**
     *
     * @return length
     */
    public int getLengthAsInt() {
      return 0xFFFF & length;
    }

    @Override
    protected List<byte[]> getRawFields()
    {
    	byte flags=(byte)0;
      
    	  try{
    		  
    		  illegal_gtp_version(version);
    		  flags = (byte) (flags | (version.value() << 5));
    		
    	  }catch(IncorrectGTPVersionException e){
    		  System.err.println(e.getMessage());
    	  }
    	  try{
    		  
    		  illegal_gtp_code(protocol_type);
    		  flags = (byte) (flags | (protocol_type.value()<<4));
    		  
    	  }catch(IncorrectGTPCodeException e){
    		  System.err.println(e.getMessage());
    		 
    	  }
    	  if(reserved_x){flags = (byte) (flags | 0x08);}
          if(ext){flags =(byte) (flags | 0x04);}
          if(seq){flags = (byte) (flags | 0x02);}
          if(pn){flags = (byte) (flags | 0x01);}
          List<byte[]> rawFields = new ArrayList<byte[]>();
          rawFields.add(ByteArrays.toByteArray(flags));
    	  try{
    		  
    		  illegal_gtp_msg(message_type);
    		  rawFields.add(ByteArrays.toByteArray(message_type.value()));
    		  
    	  }catch(IncorrectMSGTypeException e){
    		  System.err.println(e.getMessage());
    	  }
    	  rawFields.add(ByteArrays.toByteArray(length));
          rawFields.add(ByteArrays.toByteArray(te_id));
          rawFields.add(ByteArrays.toByteArray(seq_num));
          rawFields.add(ByteArrays.toByteArray(npd_num));
          rawFields.add(ByteArrays.toByteArray(nxt_ext));
          return rawFields;
    }
    
    private void illegal_gtp_version(GtpVersion version)throws IncorrectGTPVersionException
    {
    	if(version ==null)
    	{
    		throw new IncorrectGTPVersionException("Incorrect GTP version "+version);
    	}
    }
    
    private void illegal_gtp_code(GtpCode code)throws IncorrectGTPCodeException
    {
    	if(code ==null)
    	{
    		throw new IncorrectGTPCodeException("GTP code type not supported by "+version);
    	}
    }
    
    private void illegal_gtp_msg(GtpMSGType msgtype)throws IncorrectMSGTypeException
    {
    	if(msgtype ==null)
    	{
    		throw new IncorrectMSGTypeException("GTP message type not supported by "+protocol_type);
    	}
    }
      
      
     
      
      
      
     
     
     
      
    

    @Override
    public int length() {
      return GTP_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[GTP Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Version: ")
        .append(getversion())
        .append(ls);
      sb.append("  Protocol Type: ")
        .append(getprotocol_type())
        .append(ls);
      sb.append("  Reserved Flag: ")
      	.append(getreserved_x())
      	.append(ls);
      sb.append("  Extension Flag: ")
      	.append(getext())
      	.append(ls);

      sb.append("  Sequence Flag: ")
        .append(getseq())
        .append(ls);
      
      sb.append("  NPDU Flag: ")
        .append(getpn())
        .append(ls);

      sb.append("  Message Type: ")
        .append(getmsgtype())
        .append(ls);

      sb.append("  Length: ")
        .append(getLengthAsInt())
        .append(" [bytes]")
        .append(ls);

      sb.append("  Tunnel ID: ")
        .append(getteid())
        .append(ls);

      sb.append("  Sequence Number: ")
        .append(getseqnum())
        .append(ls);

      sb.append("  NPDU Number: ")
        .append(getnpdnum())
        .append(ls);

      sb.append("  Next Extension Header: ")
        .append(getnxtext())
        .append(ls);

      return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) { return true; }
      if (!this.getClass().isInstance(obj)) { return false; }

      GtpHeader other = (GtpHeader)obj;
      return
          
           length == other.length
        && version == other.version
        && protocol_type == other.protocol_type
        && reserved_x == other.reserved_x
        && ext == other.ext
        && seq == other.seq
        && pn == other.pn
        && message_type == other.message_type
        && te_id == other.te_id
        && seq_num == other.seq_num
        && npd_num == other.npd_num
        && nxt_ext == other.nxt_ext;
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + version.hashCode();
      result = 31 * result + protocol_type.hashCode();
      result = 31 * result + (reserved_x?1231:1237);
      result = 31 * result + (ext?1231:1237);
      result = 31 * result + (seq?1231:1237);
      result = 31 * result + (pn?1231:1237);
      result = 31 * result + message_type.hashCode();
      result = 31 * result + seq_num;
      result = 31 * result + npd_num;
      result = 31 * result + nxt_ext;
      result = 31 * result + length;
      return result;
    }

  }

}
