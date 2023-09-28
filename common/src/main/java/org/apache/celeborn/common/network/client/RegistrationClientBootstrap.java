/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.celeborn.common.network.client;

import static org.apache.celeborn.common.network.sasl.SaslConstants.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.TimeoutException;

import com.google.common.base.Preconditions;
import com.google.common.base.Throwables;
import com.google.common.collect.Lists;
import com.google.protobuf.ByteString;
import io.netty.channel.Channel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.celeborn.common.exception.CelebornException;
import org.apache.celeborn.common.network.protocol.TransportMessage;
import org.apache.celeborn.common.network.sasl.CelebornSaslClient;
import org.apache.celeborn.common.network.sasl.SaslClientBootstrap;
import org.apache.celeborn.common.network.sasl.SaslCredentials;
import org.apache.celeborn.common.network.sasl.SaslTimeoutException;
import org.apache.celeborn.common.network.util.TransportConf;
import org.apache.celeborn.common.protocol.MessageType;
import org.apache.celeborn.common.protocol.PbAuthType;
import org.apache.celeborn.common.protocol.PbAuthenticationInitiationRequest;
import org.apache.celeborn.common.protocol.PbAuthenticationInitiationResponse;
import org.apache.celeborn.common.protocol.PbRegisterApplicationRequest;
import org.apache.celeborn.common.protocol.PbRegisterApplicationResponse;
import org.apache.celeborn.common.protocol.PbSaslMechanism;
import org.apache.celeborn.common.protocol.PbSaslMessage;
import org.apache.celeborn.common.util.JavaUtils;

public class RegistrationClientBootstrap implements TransportClientBootstrap {

  private static final Logger LOG = LoggerFactory.getLogger(RegistrationClientBootstrap.class);

  private static final String VERSION = "0";
  private static final List<PbSaslMechanism> SASL_MECHANISMS =
      Lists.newArrayList(
          PbSaslMechanism.newBuilder()
              .setMethod(ANONYMOUS)
              .addAuthTypes(PbAuthType.CLIENT_AUTH)
              .build(),
          PbSaslMechanism.newBuilder()
              .setMethod(DIGEST)
              .addAuthTypes(PbAuthType.CONNECTION_AUTH)
              .build());

  private TransportConf conf;
  private String appId;
  private SaslCredentials saslCredentials;

  public RegistrationClientBootstrap(
      TransportConf conf, String appId, SaslCredentials saslCredentials) {
    this.conf = Preconditions.checkNotNull(conf, "conf");
    this.appId = Preconditions.checkNotNull(appId, "appId");
    this.saslCredentials = Preconditions.checkNotNull(saslCredentials, "saslCredentials");
  }

  @Override
  public void doBootstrap(TransportClient client, Channel channel) throws RuntimeException {
    if (RegistrationInfo.getInstance().getRegistrationState()
        == RegistrationInfo.RegistrationState.REGISTERED) {
      LOG.info("client has already registered, skip register.");
      doSaslBootstrap(client, channel);
      return;
    }
    try {
      LOG.info("authentication initiation started for {}", appId);
      doAuthInitiation(client);
      LOG.info("authentication initiation successful for {}", appId);
      doClientAuthentication(client);
      LOG.info("client authenticated for {}", appId);
      register(client);
      LOG.info("Registration successful for {}", appId);
      RegistrationInfo.getInstance()
          .setRegistrationState(RegistrationInfo.RegistrationState.REGISTERED);
    } catch (Throwable e) {
      LOG.error("Registration failed for {}", appId, e);
      RegistrationInfo.getInstance()
          .setRegistrationState(RegistrationInfo.RegistrationState.FAILED);
      Throwables.propagate(e);
    }
  }

  private void doAuthInitiation(TransportClient client) throws IOException, CelebornException {
    PbAuthenticationInitiationRequest authInitRequest =
        PbAuthenticationInitiationRequest.newBuilder()
            .setAppId(appId)
            .setVersion(VERSION)
            .setAuthEnabled(true)
            .addAllSaslMechanisms(SASL_MECHANISMS)
            .build();
    TransportMessage msg =
        new TransportMessage(
            MessageType.AUTHENTICATION_INITIATION_REQUEST, authInitRequest.toByteArray());
    ByteBuffer authInitResponseBuffer;
    try {
      authInitResponseBuffer = client.sendRpcSync(msg.toByteBuffer(), conf.saslTimeoutMs());
    } catch (RuntimeException ex) {
      // TODO: Auth initiation timed out. Will just throw SaslTimeoutException for now
      if (ex.getCause() instanceof TimeoutException) {
        throw new SaslTimeoutException(ex.getCause());
      } else {
        throw ex;
      }
    }
    PbAuthenticationInitiationResponse authInitResponse =
        TransportMessage.fromByteBuffer(authInitResponseBuffer).getParsedPayload();
    if (!validateServerResponse(authInitResponse)) {
      String exMsg =
          "Registration failed due to incompatibility with the server."
              + " InitRequest: "
              + authInitRequest
              + " InitResponse: "
              + authInitResponse;
      throw new CelebornException(exMsg);
    }
    // TODO: Client picks up negotiated sasl mechanisms
  }

  private void doClientAuthentication(TransportClient client) throws IOException {
    // Client will authenticate itself with the selected SaslMechanism for Client Authentication
    CelebornSaslClient saslClient = new CelebornSaslClient(ANONYMOUS, null, null);
    try {
      byte[] payload = saslClient.firstToken();
      while (!saslClient.isComplete()) {
        TransportMessage msg =
            new TransportMessage(
                MessageType.SASL_MESSAGE,
                PbSaslMessage.newBuilder()
                    .setAppId(appId)
                    .setMethod(ANONYMOUS)
                    .setAuthType(PbAuthType.CLIENT_AUTH)
                    .setPayload(ByteString.copyFrom(payload))
                    .build()
                    .toByteArray());
        ByteBuffer response;
        try {
          LOG.info("Sending SASL message for client authentication");
          response = client.sendRpcSync(msg.toByteBuffer(), conf.saslTimeoutMs());
        } catch (RuntimeException ex) {
          // We know it is a Sasl timeout here if it is a TimeoutException.
          if (ex.getCause() instanceof TimeoutException) {
            throw new SaslTimeoutException(ex.getCause());
          } else {
            throw ex;
          }
        }
        payload = saslClient.response(JavaUtils.bufferToArray(response));
      }

    } finally {
      try { // Once authentication is complete, the server will trust all remaining communication.
        saslClient.dispose();
      } catch (RuntimeException e) {
        LOG.error("Error while disposing SASL client", e);
      }
    }
  }

  private void register(TransportClient client) throws IOException, CelebornException {
    TransportMessage msg =
        new TransportMessage(
            MessageType.REGISTER_APPLICATION_REQUEST,
            PbRegisterApplicationRequest.newBuilder()
                .setAppId(appId)
                .setSecret(saslCredentials.getPassword())
                .build()
                .toByteArray());
    ByteBuffer response;
    try {
      response = client.sendRpcSync(msg.toByteBuffer(), conf.saslTimeoutMs());
    } catch (RuntimeException ex) {
      // We know it is a Sasl timeout here if it is a TimeoutException.
      if (ex.getCause() instanceof TimeoutException) {
        throw new SaslTimeoutException(ex.getCause());
      } else {
        throw ex;
      }
    }
    PbRegisterApplicationResponse registerApplicationResponse =
        TransportMessage.fromByteBuffer(response).getParsedPayload();
    if (!registerApplicationResponse.getStatus()) {
      throw new CelebornException("Application registration failed. AppId = " + appId);
    }
  }

  private void doSaslBootstrap(TransportClient client, Channel channel) {
    SaslClientBootstrap bootstrap = new SaslClientBootstrap(conf, appId, saslCredentials);
    bootstrap.doBootstrap(client, channel);
  }

  private boolean validateServerResponse(PbAuthenticationInitiationResponse authInitResponse) {
    // TODO: need to elaborate this
    if (!authInitResponse.getVersion().equals(VERSION)) {
      return false;
    }
    return true;
  }
}
