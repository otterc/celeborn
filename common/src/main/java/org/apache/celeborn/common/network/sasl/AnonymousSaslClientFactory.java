package org.apache.celeborn.common.network.sasl;

import static org.apache.celeborn.common.network.sasl.SaslConstants.*;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

public class AnonymousSaslClientFactory implements SaslClientFactory {
  @Override
  public SaslClient createSaslClient(
      String[] mechanisms,
      String authorizationId,
      String protocol,
      String serverName,
      Map<String, ?> props,
      CallbackHandler cbh)
      throws SaslException {
    for (String mech : mechanisms) {
      if (mech.equals(ANONYMOUS)) {
        return new CelebornAnonymousSaslClient();
      }
    }
    return null;
  }

  @Override
  public String[] getMechanismNames(Map<String, ?> props) {
    return new String[] {ANONYMOUS};
  }

  class CelebornAnonymousSaslClient implements SaslClient {

    private boolean isCompleted = false;

    @Override
    public String getMechanismName() {
      return ANONYMOUS;
    }

    @Override
    public boolean hasInitialResponse() {
      return false;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
      if (isCompleted) {
        throw new IllegalStateException("Authentication has already completed.");
      }
      isCompleted = true;
      return ANONYMOUS.getBytes();
    }

    @Override
    public boolean isComplete() {
      return isCompleted;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
      throw new IllegalStateException("ANONYMOUS mechanism does not support wrap/unwrap");
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
      throw new IllegalStateException("ANONYMOUS mechanism does not support wrap/unwrap");
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
      return null;
    }

    @Override
    public void dispose() throws SaslException {
      // Cleanup resources if any
    }
  }
}
