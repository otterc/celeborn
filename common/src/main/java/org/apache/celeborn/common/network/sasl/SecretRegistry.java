package org.apache.celeborn.common.network.sasl;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import com.google.common.collect.Lists;

public class SecretRegistry implements SecretKeyHolder {

  private static final SecretRegistry INSTANCE = new SecretRegistry();

  public static synchronized SecretRegistry getInstance() {
    return INSTANCE;
  }

  private final ConcurrentHashMap<String, String> secrets = new ConcurrentHashMap<>();

  public void registerApplication(String appId, String secret) {
    secrets.put(appId, secret);
  }

  public void unregisterApplication(String appId) {
    secrets.remove(appId);
  }

  public String getSecret(String appId) {
    return secrets.get(appId);
  }

  public boolean isRegistered(String appId) {
    return secrets.containsKey(appId);
  }

  public List<String> getAllRegisteredApps() {
    return Lists.newArrayList(secrets.keySet());
  }

  /**
   * Gets an appropriate SASL User for the given appId.
   *
   * @throws IllegalArgumentException if the given appId is not associated with a SASL user.
   */
  @Override
  public String getSaslUser(String appId) {
    return appId;
  }

  /**
   * Gets an appropriate SASL secret key for the given appId.
   *
   * @throws IllegalArgumentException if the given appId is not associated with a SASL secret key.
   */
  @Override
  public String getSecretKey(String appId) {
    return secrets.get(appId);
  }
}
