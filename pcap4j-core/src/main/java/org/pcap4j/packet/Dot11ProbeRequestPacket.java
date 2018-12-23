/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.packet.namednumber.Dot11InformationElementId.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

/**
 * IEEE802.11 Probe Request
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11ProbeRequestPacket extends Dot11ManagementPacket {

  /** */
  private static final long serialVersionUID = -2305355759191727871L;

  private final Dot11ProbeRequestHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11ProbeRequestPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11ProbeRequestPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    Dot11ProbeRequestHeader h = new Dot11ProbeRequestHeader(rawData, offset, length);
    return new Dot11ProbeRequestPacket(rawData, offset, length, h);
  }

  private Dot11ProbeRequestPacket(
      byte[] rawData, int offset, int length, Dot11ProbeRequestHeader h) {
    super(rawData, offset, length, h.length());
    this.header = h;
  }

  private static Dot11ProbeRequestPacket newPacket(Builder builder) {
    Dot11ProbeRequestHeader h = new Dot11ProbeRequestHeader(builder);
    return new Dot11ProbeRequestPacket(builder, h);
  }

  private Dot11ProbeRequestPacket(Builder builder, Dot11ProbeRequestHeader h) {
    super(builder, h);
    this.header = h;
  }

  @Override
  public Dot11ProbeRequestHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder extends Dot11ManagementPacket.Builder {

    private Dot11SsidElement ssid;
    private Dot11SupportedRatesElement supportedRates;
    private Dot11RequestElement request;
    private Dot11ExtendedSupportedRatesElement extendedSupportedRates;
    private Dot11DsssParameterSetElement dsssParameterSet;
    private Dot11SupportedOperatingClassesElement supportedOperatingClasses;
    private Dot11HTCapabilitiesElement htCapabilities;
    private Dot112040BssCoexistenceElement twentyFortyBssCoexistence;
    private Dot11ExtendedCapabilitiesElement extendedCapabilities;
    private Dot11SsidListElement ssidList;
    private Dot11ChannelUsageElement channelUsage;
    private Dot11InterworkingElement interworking;
    private Dot11MeshIdElement meshId;
    private List<Dot11VendorSpecificElement> vendorSpecificElements;

    /** */
    public Builder() {}

    private Builder(Dot11ProbeRequestPacket packet) {
      super(packet);
      this.ssid = packet.header.ssid;
      this.supportedRates = packet.header.supportedRates;
      this.request = packet.header.request;
      this.extendedSupportedRates = packet.header.extendedSupportedRates;
      this.dsssParameterSet = packet.header.dsssParameterSet;
      this.supportedOperatingClasses = packet.header.supportedOperatingClasses;
      this.htCapabilities = packet.header.htCapabilities;
      this.twentyFortyBssCoexistence = packet.header.twentyFortyBssCoexistence;
      this.extendedCapabilities = packet.header.extendedCapabilities;
      this.ssidList = packet.header.ssidList;
      this.channelUsage = packet.header.channelUsage;
      this.interworking = packet.header.interworking;
      this.meshId = packet.header.meshId;
      this.vendorSpecificElements = packet.header.vendorSpecificElements;
    }

    /**
     * @param ssid ssid
     * @return this Builder object for method chaining.
     */
    public Builder ssid(Dot11SsidElement ssid) {
      this.ssid = ssid;
      return this;
    }

    /**
     * @param supportedRates supportedRates
     * @return this Builder object for method chaining.
     */
    public Builder supportedRates(Dot11SupportedRatesElement supportedRates) {
      this.supportedRates = supportedRates;
      return this;
    }

    /**
     * @param request request
     * @return this Builder object for method chaining.
     */
    public Builder request(Dot11RequestElement request) {
      this.request = request;
      return this;
    }

    /**
     * @param extendedSupportedRates extendedSupportedRates
     * @return this Builder object for method chaining.
     */
    public Builder extendedSupportedRates(
        Dot11ExtendedSupportedRatesElement extendedSupportedRates) {
      this.extendedSupportedRates = extendedSupportedRates;
      return this;
    }

    /**
     * @param dsssParameterSet dsssParameterSet
     * @return this Builder object for method chaining.
     */
    public Builder dsssParameterSet(Dot11DsssParameterSetElement dsssParameterSet) {
      this.dsssParameterSet = dsssParameterSet;
      return this;
    }

    /**
     * @param supportedOperatingClasses supportedOperatingClasses
     * @return this Builder object for method chaining.
     */
    public Builder supportedOperatingClasses(
        Dot11SupportedOperatingClassesElement supportedOperatingClasses) {
      this.supportedOperatingClasses = supportedOperatingClasses;
      return this;
    }

    /**
     * @param htCapabilities htCapabilities
     * @return this Builder object for method chaining.
     */
    public Builder htCapabilities(Dot11HTCapabilitiesElement htCapabilities) {
      this.htCapabilities = htCapabilities;
      return this;
    }

    /**
     * @param twentyFortyBssCoexistence twentyFortyBssCoexistence
     * @return this Builder object for method chaining.
     */
    public Builder twentyFortyBssCoexistence(
        Dot112040BssCoexistenceElement twentyFortyBssCoexistence) {
      this.twentyFortyBssCoexistence = twentyFortyBssCoexistence;
      return this;
    }

    /**
     * @param extendedCapabilities extendedCapabilities
     * @return this Builder object for method chaining.
     */
    public Builder extendedCapabilities(Dot11ExtendedCapabilitiesElement extendedCapabilities) {
      this.extendedCapabilities = extendedCapabilities;
      return this;
    }

    /**
     * @param ssidList ssidList
     * @return this Builder object for method chaining.
     */
    public Builder ssidList(Dot11SsidListElement ssidList) {
      this.ssidList = ssidList;
      return this;
    }

    /**
     * @param channelUsage channelUsage
     * @return this Builder object for method chaining.
     */
    public Builder channelUsage(Dot11ChannelUsageElement channelUsage) {
      this.channelUsage = channelUsage;
      return this;
    }

    /**
     * @param interworking interworking
     * @return this Builder object for method chaining.
     */
    public Builder interworking(Dot11InterworkingElement interworking) {
      this.interworking = interworking;
      return this;
    }

    /**
     * @param meshId meshId
     * @return this Builder object for method chaining.
     */
    public Builder meshId(Dot11MeshIdElement meshId) {
      this.meshId = meshId;
      return this;
    }

    /**
     * @param vendorSpecificElements vendorSpecificElements
     * @return this Builder object for method chaining.
     */
    public Builder vendorSpecificElements(List<Dot11VendorSpecificElement> vendorSpecificElements) {
      this.vendorSpecificElements = vendorSpecificElements;
      return this;
    }

    @Override
    public Builder frameControl(Dot11FrameControl frameControl) {
      super.frameControl(frameControl);
      return this;
    }

    @Override
    public Builder duration(short duration) {
      super.duration(duration);
      return this;
    }

    @Override
    public Builder address1(MacAddress address1) {
      super.address1(address1);
      return this;
    }

    @Override
    public Builder address2(MacAddress address2) {
      super.address2(address2);
      return this;
    }

    @Override
    public Builder address3(MacAddress address3) {
      super.address3(address3);
      return this;
    }

    @Override
    public Builder sequenceControl(Dot11SequenceControl sequenceControl) {
      super.sequenceControl(sequenceControl);
      return this;
    }

    @Override
    public Builder htControl(Dot11HtControl htControl) {
      super.htControl(htControl);
      return this;
    }

    @Override
    public Builder fcs(Integer fcs) {
      super.fcs(fcs);
      return this;
    }

    @Override
    public Builder correctChecksumAtBuild(boolean correctChecksumAtBuild) {
      super.correctChecksumAtBuild(correctChecksumAtBuild);
      return this;
    }

    @Override
    public Dot11ProbeRequestPacket build() {
      checkForNull();
      return newPacket(this);
    }
  }

  /**
   * Header of IEEE802.11 Probe Request
   *
   * <pre style="white-space: pre;">
   *  0                             15
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |         Frame Control         |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |         Duration              |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                               |
   * |          Address1             |
   * |                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                               |
   * |          Address2             |
   * |                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                               |
   * |          Address3             |
   * |                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |       Sequence Control        |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |         HT Control            |
   * |                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                               |
   * |          Frame Body           |
   * |                               |
   * </pre>
   *
   * <table>
   *   <caption>Frame Body</caption>
   *   <tr>
   *     <td>1</td>
   *     <td>SSID</td>
   *     <td>If dot11MeshActivated is true, the SSID element is the wildcard value.</td>
   *   </tr>
   *   <tr>
   *     <td>2</td>
   *     <td>Supported rates</td>
   *     <td></td>
   *   </tr>
   *   <tr>
   *     <td>3</td>
   *     <td>Request information</td>
   *     <td>
   *       The Request element is optionally present if dot11MultiDomainCapabilityActivated is
   *       true.
   *     </td>
   *   </tr>
   *   <tr>
   *     <td>4</td>
   *     <td>Extended Supported Rates</td>
   *     <td>
   *       The Extended Supported Rates element is present if there are more than eight supported
   *       rates, and is optionally present otherwise.
   *     </td>
   *   </tr>
   *   <tr>
   *     <td>5</td>
   *     <td>DSSS Parameter Set</td>
   *     <td>
   *       The DSSS Parameter Set element is present within Probe Request frames generated by STAs
   *       using Clause 16, Clause 17, or Clause 19 PHYs if dot11RadioMeasurementActivated is true.
   *       The DSSS Parameter Set element is present within Probe Request frames generated by STAs
   *       using a Clause 20 PHY in the 2.4 GHz band if dot11RadioMeasurementActivated is true.
   *       The DSSS Parameter Set element is optionally present within Probe Request frames
   *       generated by STAs using Clause 16, Clause 17, or Clause 19 PHYs if
   *       dot11RadioMeasurementActivated is false. The DSSS Parameter Set element is optionally
   *       present within Probe Request frames generated by STAs using a Clause 20 PHY in the 2.4
   *       GHz band if dot11RadioMeasurementActivated is false.
   *     </td>
   *   </tr>
   *   <tr>
   *     <td>6</td>
   *     <td>Supported Operating Classes</td>
   *     <td>
   *       The Supported Operating Classes element is present if
   *       dot11ExtendedChannelSwitchActivated is true.
   *     </td>
   *   </tr>
   *   <tr>
   *     <td>7</td>
   *     <td>HT Capabilities</td>
   *     <td>
   *       The HT Capabilities element is present when dot11HighThroughputOptionImplemented
   *       attribute is true.
   *     </td>
   *   </tr>
   *   <tr>
   *     <td>8</td>
   *     <td>20/40 BSS Coexistence</td>
   *     <td>
   *       The 20/40 BSS Coexistence element is optionally present when the
   *       dot112040BSSCoexistenceManagementSupport attribute is true.
   *     </td>
   *   </tr>
   *   <tr>
   *     <td>9</td>
   *     <td>Extended Capabilities</td>
   *     <td>
   *       The Extended Capabilities element is optionally present if any of the fields in this
   *       element are nonzero.
   *     </td>
   *   </tr>
   *   <tr>
   *     <td>10</td>
   *     <td>SSID List</td>
   *     <td>
   *       The SSID List element is optionally present if dot11MgmtOptionSSIDListActivated is
   *       true.
   *     </td>
   *   </tr>
   *   <tr>
   *     <td>11</td>
   *     <td>Channel Usage</td>
   *     <td>
   *       The Channel Usage element is optionally present if dot11MgmtOptionChannelUsageActivated
   *       is true.
   *     </td>
   *   </tr>
   *   <tr>
   *     <td>12</td>
   *     <td>Interworking</td>
   *     <td>
   *       The Interworking element is present if dot11InterworkingServiceActivated is true.
   *     </td>
   *   </tr>
   *   <tr>
   *     <td>13</td>
   *     <td>Mesh ID</td>
   *     <td>
   *       The Mesh ID element is present if dot11MeshActivated is true.
   *     </td>
   *   </tr>
   *   <tr>
   *     <td>Last</td>
   *     <td>Vendor Specific</td>
   *     <td>
   *       One or more vendor-specific elements are optionally present. These elements follow all
   *       other elements.
   *     </td>
   *   </tr>
   * </table>
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Dot11ProbeRequestHeader extends Dot11ManagementHeader {

    /** */
    private static final long serialVersionUID = -2203820242563461514L;

    private final Dot11SsidElement ssid;
    private final Dot11SupportedRatesElement supportedRates;
    private final Dot11RequestElement request;
    private final Dot11ExtendedSupportedRatesElement extendedSupportedRates;
    private final Dot11DsssParameterSetElement dsssParameterSet;
    private final Dot11SupportedOperatingClassesElement supportedOperatingClasses;
    private final Dot11HTCapabilitiesElement htCapabilities;
    private final Dot112040BssCoexistenceElement twentyFortyBssCoexistence;
    private final Dot11ExtendedCapabilitiesElement extendedCapabilities;
    private final Dot11SsidListElement ssidList;
    private final Dot11ChannelUsageElement channelUsage;
    private final Dot11InterworkingElement interworking;
    private final Dot11MeshIdElement meshId;
    private final List<Dot11VendorSpecificElement> vendorSpecificElements;

    private Dot11ProbeRequestHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      super(rawData, offset, length);
      int mgmtHeaderLen = super.calcLength();
      offset += mgmtHeaderLen;
      length -= mgmtHeaderLen;

      if (length > 0 && rawData[offset] == SSID.value().byteValue()) {
        this.ssid = Dot11SsidElement.newInstance(rawData, offset, length);
        int elemLen = ssid.length();
        offset += elemLen;
        length -= elemLen;
      } else {
        this.ssid = null;
      }
      if (length > 0 && rawData[offset] == SUPPORTED_RATES.value().byteValue()) {
        this.supportedRates = Dot11SupportedRatesElement.newInstance(rawData, offset, length);
        int elemLen = supportedRates.length();
        offset += elemLen;
        length -= elemLen;
      } else {
        this.supportedRates = null;
      }
      if (length > 0 && rawData[offset] == REQUEST.value().byteValue()) {
        this.request = Dot11RequestElement.newInstance(rawData, offset, length);
        int elemLen = request.length();
        offset += elemLen;
        length -= elemLen;
      } else {
        this.request = null;
      }
      if (length > 0 && rawData[offset] == EXTENDED_SUPPORTED_RATES.value().byteValue()) {
        this.extendedSupportedRates =
            Dot11ExtendedSupportedRatesElement.newInstance(rawData, offset, length);
        int elemLen = extendedSupportedRates.length();
        offset += elemLen;
        length -= elemLen;
      } else {
        this.extendedSupportedRates = null;
      }
      if (length > 0 && rawData[offset] == DSSS_PARAMETER_SET.value().byteValue()) {
        this.dsssParameterSet = Dot11DsssParameterSetElement.newInstance(rawData, offset, length);
        int elemLen = dsssParameterSet.length();
        offset += elemLen;
        length -= elemLen;
      } else {
        this.dsssParameterSet = null;
      }
      if (length > 0 && rawData[offset] == SUPPORTED_OPERATING_CLASSES.value().byteValue()) {
        this.supportedOperatingClasses =
            Dot11SupportedOperatingClassesElement.newInstance(rawData, offset, length);
        int elemLen = supportedOperatingClasses.length();
        offset += elemLen;
        length -= elemLen;
      } else {
        this.supportedOperatingClasses = null;
      }
      if (length > 0 && rawData[offset] == HT_CAPABILITIES.value().byteValue()) {
        this.htCapabilities = Dot11HTCapabilitiesElement.newInstance(rawData, offset, length);
        int elemLen = htCapabilities.length();
        offset += elemLen;
        length -= elemLen;
      } else {
        this.htCapabilities = null;
      }
      if (length > 0 && rawData[offset] == IE_20_40_BSS_COEXISTENCE.value().byteValue()) {
        this.twentyFortyBssCoexistence =
            Dot112040BssCoexistenceElement.newInstance(rawData, offset, length);
        int elemLen = twentyFortyBssCoexistence.length();
        offset += elemLen;
        length -= elemLen;
      } else {
        this.twentyFortyBssCoexistence = null;
      }
      if (length > 0 && rawData[offset] == EXTENDED_CAPABILITIES.value().byteValue()) {
        this.extendedCapabilities =
            Dot11ExtendedCapabilitiesElement.newInstance(rawData, offset, length);
        int elemLen = extendedCapabilities.length();
        offset += elemLen;
        length -= elemLen;
      } else {
        this.extendedCapabilities = null;
      }
      if (length > 0 && rawData[offset] == SSID_LIST.value().byteValue()) {
        this.ssidList = Dot11SsidListElement.newInstance(rawData, offset, length);
        int elemLen = ssidList.length();
        offset += elemLen;
        length -= elemLen;
      } else {
        this.ssidList = null;
      }
      if (length > 0 && rawData[offset] == CHANNEL_USAGE.value().byteValue()) {
        this.channelUsage = Dot11ChannelUsageElement.newInstance(rawData, offset, length);
        int elemLen = channelUsage.length();
        offset += elemLen;
        length -= elemLen;
      } else {
        this.channelUsage = null;
      }
      if (length > 0 && rawData[offset] == INTERWORKING.value().byteValue()) {
        this.interworking = Dot11InterworkingElement.newInstance(rawData, offset, length);
        int elemLen = interworking.length();
        offset += elemLen;
        length -= elemLen;
      } else {
        this.interworking = null;
      }
      if (length > 0 && rawData[offset] == MESH_ID.value().byteValue()) {
        this.meshId = Dot11MeshIdElement.newInstance(rawData, offset, length);
        int elemLen = meshId.length();
        offset += elemLen;
        length -= elemLen;
      } else {
        this.meshId = null;
      }

      this.vendorSpecificElements = new ArrayList<Dot11VendorSpecificElement>();
      while (length > 0 && rawData[offset] == VENDOR_SPECIFIC.value().byteValue()) {
        Dot11VendorSpecificElement elem =
            Dot11VendorSpecificElement.newInstance(rawData, offset, length);
        vendorSpecificElements.add(elem);
        int elemLen = elem.length();
        offset += elemLen;
        length -= elemLen;
      }
    }

    private Dot11ProbeRequestHeader(Builder builder) {
      super(builder);
      this.ssid = builder.ssid;
      this.supportedRates = builder.supportedRates;
      this.request = builder.request;
      this.extendedSupportedRates = builder.extendedSupportedRates;
      this.dsssParameterSet = builder.dsssParameterSet;
      this.supportedOperatingClasses = builder.supportedOperatingClasses;
      this.htCapabilities = builder.htCapabilities;
      this.twentyFortyBssCoexistence = builder.twentyFortyBssCoexistence;
      this.extendedCapabilities = builder.extendedCapabilities;
      this.ssidList = builder.ssidList;
      this.channelUsage = builder.channelUsage;
      this.interworking = builder.interworking;
      this.meshId = builder.meshId;
      if (builder.vendorSpecificElements == null) {
        this.vendorSpecificElements = Collections.emptyList();
      } else {
        this.vendorSpecificElements =
            new ArrayList<Dot11VendorSpecificElement>(builder.vendorSpecificElements);
      }
    }

    /** @return ssid. May be null. */
    public Dot11SsidElement getSsid() {
      return ssid;
    }

    /** @return supportedRates. May be null. */
    public Dot11SupportedRatesElement getSupportedRates() {
      return supportedRates;
    }

    /** @return request. May be null. */
    public Dot11RequestElement getRequest() {
      return request;
    }

    /** @return extendedSupportedRates. May be null. */
    public Dot11ExtendedSupportedRatesElement getExtendedSupportedRates() {
      return extendedSupportedRates;
    }

    /** @return dsssParameterSet. May be null. */
    public Dot11DsssParameterSetElement getDsssParameterSet() {
      return dsssParameterSet;
    }

    /** @return supportedOperatingClasses. May be null. */
    public Dot11SupportedOperatingClassesElement getSupportedOperatingClasses() {
      return supportedOperatingClasses;
    }

    /** @return htCapabilities. May be null. */
    public Dot11HTCapabilitiesElement getHtCapabilities() {
      return htCapabilities;
    }

    /** @return twentyFortyBssCoexistence. May be null. */
    public Dot112040BssCoexistenceElement get2040BssCoexistence() {
      return twentyFortyBssCoexistence;
    }

    /** @return extendedCapabilities. May be null. */
    public Dot11ExtendedCapabilitiesElement getExtendedCapabilities() {
      return extendedCapabilities;
    }

    /** @return ssidList. May be null. */
    public Dot11SsidListElement getSsidList() {
      return ssidList;
    }

    /** @return channelUsage. May be null. */
    public Dot11ChannelUsageElement getChannelUsage() {
      return channelUsage;
    }

    /** @return interworking. May be null. */
    public Dot11InterworkingElement getInterworking() {
      return interworking;
    }

    /** @return meshId. May be null. */
    public Dot11MeshIdElement getMeshId() {
      return meshId;
    }

    /** @return vendorSpecificElements */
    public List<Dot11VendorSpecificElement> getVendorSpecificElements() {
      return new ArrayList<Dot11VendorSpecificElement>(vendorSpecificElements);
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = super.getRawFields();

      if (ssid != null) {
        rawFields.add(ssid.getRawData());
      }
      if (supportedRates != null) {
        rawFields.add(supportedRates.getRawData());
      }
      if (request != null) {
        rawFields.add(request.getRawData());
      }
      if (extendedSupportedRates != null) {
        rawFields.add(extendedSupportedRates.getRawData());
      }
      if (dsssParameterSet != null) {
        rawFields.add(dsssParameterSet.getRawData());
      }
      if (supportedOperatingClasses != null) {
        rawFields.add(supportedOperatingClasses.getRawData());
      }
      if (htCapabilities != null) {
        rawFields.add(htCapabilities.getRawData());
      }
      if (twentyFortyBssCoexistence != null) {
        rawFields.add(twentyFortyBssCoexistence.getRawData());
      }
      if (extendedCapabilities != null) {
        rawFields.add(extendedCapabilities.getRawData());
      }
      if (ssidList != null) {
        rawFields.add(ssidList.getRawData());
      }
      if (channelUsage != null) {
        rawFields.add(channelUsage.getRawData());
      }
      if (interworking != null) {
        rawFields.add(interworking.getRawData());
      }
      if (meshId != null) {
        rawFields.add(meshId.getRawData());
      }
      for (Dot11VendorSpecificElement elem : vendorSpecificElements) {
        rawFields.add(elem.getRawData());
      }

      return rawFields;
    }

    @Override
    public int calcLength() {
      int len = super.calcLength();

      if (ssid != null) {
        len += ssid.length();
      }
      if (supportedRates != null) {
        len += supportedRates.length();
      }
      if (request != null) {
        len += request.length();
      }
      if (extendedSupportedRates != null) {
        len += extendedSupportedRates.length();
      }
      if (dsssParameterSet != null) {
        len += dsssParameterSet.length();
      }
      if (supportedOperatingClasses != null) {
        len += supportedOperatingClasses.length();
      }
      if (htCapabilities != null) {
        len += htCapabilities.length();
      }
      if (twentyFortyBssCoexistence != null) {
        len += twentyFortyBssCoexistence.length();
      }
      if (extendedCapabilities != null) {
        len += extendedCapabilities.length();
      }
      if (ssidList != null) {
        len += ssidList.length();
      }
      if (channelUsage != null) {
        len += channelUsage.length();
      }
      if (interworking != null) {
        len += interworking.length();
      }
      if (meshId != null) {
        len += meshId.length();
      }
      for (Dot11VendorSpecificElement elem : vendorSpecificElements) {
        len += elem.length();
      }

      return len;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append(super.buildString());
      sb.append("  Tags:").append(ls);
      if (ssid != null) {
        sb.append(ssid.toString("    "));
      }
      if (supportedRates != null) {
        sb.append(supportedRates.toString("    "));
      }
      if (request != null) {
        sb.append(request.toString("    "));
      }
      if (extendedSupportedRates != null) {
        sb.append(extendedSupportedRates.toString("    "));
      }
      if (dsssParameterSet != null) {
        sb.append(dsssParameterSet.toString("    "));
      }
      if (supportedOperatingClasses != null) {
        sb.append(supportedOperatingClasses.toString("    "));
      }
      if (htCapabilities != null) {
        sb.append(htCapabilities.toString("    "));
      }
      if (twentyFortyBssCoexistence != null) {
        sb.append(twentyFortyBssCoexistence.toString("    "));
      }
      if (extendedCapabilities != null) {
        sb.append(extendedCapabilities.toString("    "));
      }
      if (ssidList != null) {
        sb.append(ssidList.toString("    "));
      }
      if (channelUsage != null) {
        sb.append(channelUsage.toString("    "));
      }
      if (interworking != null) {
        sb.append(interworking.toString("    "));
      }
      if (meshId != null) {
        sb.append(meshId.toString("    "));
      }
      for (Dot11VendorSpecificElement elem : vendorSpecificElements) {
        sb.append(elem.toString("    "));
      }

      return sb.toString();
    }

    @Override
    protected String getHeaderName() {
      return "IEEE802.11 Probe Request header";
    }

    @Override
    protected int calcHashCode() {
      final int prime = 31;
      int result = super.calcHashCode();
      result = prime * result + ((channelUsage == null) ? 0 : channelUsage.hashCode());
      result = prime * result + ((dsssParameterSet == null) ? 0 : dsssParameterSet.hashCode());
      result =
          prime * result + ((extendedCapabilities == null) ? 0 : extendedCapabilities.hashCode());
      result =
          prime * result
              + ((extendedSupportedRates == null) ? 0 : extendedSupportedRates.hashCode());
      result = prime * result + ((htCapabilities == null) ? 0 : htCapabilities.hashCode());
      result = prime * result + ((interworking == null) ? 0 : interworking.hashCode());
      result = prime * result + ((meshId == null) ? 0 : meshId.hashCode());
      result = prime * result + ((request == null) ? 0 : request.hashCode());
      result = prime * result + ((ssid == null) ? 0 : ssid.hashCode());
      result = prime * result + ((ssidList == null) ? 0 : ssidList.hashCode());
      result =
          prime * result
              + ((supportedOperatingClasses == null) ? 0 : supportedOperatingClasses.hashCode());
      result = prime * result + ((supportedRates == null) ? 0 : supportedRates.hashCode());
      result =
          prime * result
              + ((twentyFortyBssCoexistence == null) ? 0 : twentyFortyBssCoexistence.hashCode());
      result = prime * result + vendorSpecificElements.hashCode();
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (!super.equals(obj)) return false;
      Dot11ProbeRequestHeader other = (Dot11ProbeRequestHeader) obj;
      if (channelUsage == null) {
        if (other.channelUsage != null) return false;
      } else if (!channelUsage.equals(other.channelUsage)) return false;
      if (dsssParameterSet == null) {
        if (other.dsssParameterSet != null) return false;
      } else if (!dsssParameterSet.equals(other.dsssParameterSet)) return false;
      if (extendedCapabilities == null) {
        if (other.extendedCapabilities != null) return false;
      } else if (!extendedCapabilities.equals(other.extendedCapabilities)) return false;
      if (extendedSupportedRates == null) {
        if (other.extendedSupportedRates != null) return false;
      } else if (!extendedSupportedRates.equals(other.extendedSupportedRates)) return false;
      if (htCapabilities == null) {
        if (other.htCapabilities != null) return false;
      } else if (!htCapabilities.equals(other.htCapabilities)) return false;
      if (interworking == null) {
        if (other.interworking != null) return false;
      } else if (!interworking.equals(other.interworking)) return false;
      if (meshId == null) {
        if (other.meshId != null) return false;
      } else if (!meshId.equals(other.meshId)) return false;
      if (request == null) {
        if (other.request != null) return false;
      } else if (!request.equals(other.request)) return false;
      if (ssid == null) {
        if (other.ssid != null) return false;
      } else if (!ssid.equals(other.ssid)) return false;
      if (ssidList == null) {
        if (other.ssidList != null) return false;
      } else if (!ssidList.equals(other.ssidList)) return false;
      if (supportedOperatingClasses == null) {
        if (other.supportedOperatingClasses != null) return false;
      } else if (!supportedOperatingClasses.equals(other.supportedOperatingClasses)) return false;
      if (supportedRates == null) {
        if (other.supportedRates != null) return false;
      } else if (!supportedRates.equals(other.supportedRates)) return false;
      if (twentyFortyBssCoexistence == null) {
        if (other.twentyFortyBssCoexistence != null) return false;
      } else if (!twentyFortyBssCoexistence.equals(other.twentyFortyBssCoexistence)) return false;
      if (!vendorSpecificElements.equals(other.vendorSpecificElements)) return false;
      return true;
    }
  }
}
