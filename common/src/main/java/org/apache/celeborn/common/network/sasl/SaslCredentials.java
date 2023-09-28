package org.apache.celeborn.common.network.sasl;

import com.google.common.base.Preconditions;

public class SaslCredentials {
  private final String userId;
  private final String password;

  public SaslCredentials(String userId, String password) {
    this.userId = Preconditions.checkNotNull(userId);
    this.password = Preconditions.checkNotNull(password);
  }

  public String getUserId() {
    return userId;
  }

  public String getPassword() {
    return password;
  }
}
