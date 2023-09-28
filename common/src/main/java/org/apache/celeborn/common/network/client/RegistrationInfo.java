package org.apache.celeborn.common.network.client;

import java.util.concurrent.atomic.AtomicReference;

import org.apache.celeborn.common.protocol.PbApplicationMetaInfo;

public class RegistrationInfo {

  private static RegistrationInfo INSTANCE = null;

  private RegistrationInfo(String appId, String secret) {
    this.appId = appId;
    this.secret = secret;
  }

  public static synchronized void initialize(String appId, String secret) {
    if (INSTANCE == null) {
      INSTANCE = new RegistrationInfo(appId, secret);
    }
  }

  public static synchronized RegistrationInfo getInstance() {
    if (INSTANCE == null) {
      throw new IllegalStateException("RegistrationInfo has not been initialized");
    }
    return INSTANCE;
  }

  private final AtomicReference<RegistrationState> state =
      new AtomicReference<>(RegistrationState.UNREGISTERED);
  private final String appId;
  private final String secret;

  public RegistrationState getRegistrationState() {
    return state.get();
  }

  public void setRegistrationState(RegistrationState newState) {
    state.set(newState);
  }

  public PbApplicationMetaInfo getApplicationMetaInfo() {
    return PbApplicationMetaInfo.newBuilder().setAppId(appId).setSecret(secret).build();
  }

  public String getSecret() {
    return secret;
  }

  public enum RegistrationState {
    REGISTERED,
    UNREGISTERED,
    FAILED
  }
}
