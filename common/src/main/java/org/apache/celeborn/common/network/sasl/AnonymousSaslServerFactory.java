package org.apache.celeborn.common.network.sasl;

import static org.apache.celeborn.common.network.sasl.SaslConstants.*;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

public class AnonymousSaslServerFactory implements SaslServerFactory {
  @Override
  public SaslServer createSaslServer(
      String mechanism,
      String protocol,
      String serverName,
      Map<String, ?> props,
      CallbackHandler cbh)
      throws SaslException {
    if (mechanism.equals(ANONYMOUS)) {
      return new CelebornAnonymousSaslServer();
    }
    return null;
  }

  @Override
  public String[] getMechanismNames(Map<String, ?> props) {
    return new String[] {ANONYMOUS};
  }

  class CelebornAnonymousSaslServer implements SaslServer {
    private boolean isCompleted = false;

    @Override
    public String getMechanismName() {
      return ANONYMOUS;
    }

    @Override
    public byte[] evaluateResponse(byte[] response) throws SaslException {
      if (isCompleted) {
        throw new IllegalStateException("Authentication has already completed.");
      }
      // Typically, you'd process the response here. For ANONYMOUS, you might just accept it.
      isCompleted = true;
      return new byte[0]; // No challenge is expected for ANONYMOUS.
    }

    @Override
    public boolean isComplete() {
      return isCompleted;
    }

    @Override
    public String getAuthorizationID() {
      return ANONYMOUS;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) {
      throw new IllegalStateException("ANONYMOUS mechanism does not support wrap/unwrap");
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) {
      throw new IllegalStateException("ANONYMOUS mechanism does not support wrap/unwrap");
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
      return null;
    }

    @Override
    public void dispose() {
      // Cleanup resources if any.
    }
  }
}
