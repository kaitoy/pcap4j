/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import org.pcap4j.util.PropertiesLoader;

final class PcapPropertiesLoader {

  private static final String KEY_PREFIX
    = PcapPropertiesLoader.class.getPackage().getName();
  public static final String PCAP_PROPERTIES_NAME_KEY
    = KEY_PREFIX + "core.properties";

  private static final PcapPropertiesLoader INSTANCE
    = new PcapPropertiesLoader();

  private PropertiesLoader loader
    = new PropertiesLoader(
        System.getProperty(
          PCAP_PROPERTIES_NAME_KEY,
          KEY_PREFIX.replace('.', '/') + "/core.properties"
        )
      );

  private PcapPropertiesLoader() {}

  public static PcapPropertiesLoader getInstance() {
    return INSTANCE;
  }

  public boolean usesNextEx() {
    return loader.getBoolean(
             KEY_PREFIX + ".usesNextEx",
             Boolean.TRUE
           );
  }

}
