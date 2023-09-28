package org.apache.celeborn.common.network.sasl;

import static org.apache.celeborn.common.network.sasl.SaslConstants.*;

import java.security.Provider;
import java.security.Security;

public final class AnonymousSaslProvider extends Provider {

  private static boolean init = false;

  private AnonymousSaslProvider() {
    super("AnonymousSasl", 1.0, "ANONYMOUS SASL MECHANISM PROVIDER");
    put("SaslClientFactory." + ANONYMOUS, AnonymousSaslClientFactory.class.getName());
    put("SaslServerFactory." + ANONYMOUS, AnonymousSaslServerFactory.class.getName());
  }

  public static synchronized void initializeIfNeeded() {
    if (!init) {
      AnonymousSaslProvider provider = new AnonymousSaslProvider();
      Security.addProvider(provider);
      init = true;
    }
  }
}
