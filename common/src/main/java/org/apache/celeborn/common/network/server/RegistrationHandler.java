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

package org.apache.celeborn.common.network.server;

import static org.apache.celeborn.common.network.sasl.SaslConstants.*;
import static org.apache.celeborn.common.protocol.MessageType.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

import com.google.common.base.Throwables;
import com.google.common.collect.Lists;
import io.netty.channel.Channel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.celeborn.common.exception.CelebornException;
import org.apache.celeborn.common.network.client.RpcResponseCallback;
import org.apache.celeborn.common.network.client.TransportClient;
import org.apache.celeborn.common.network.protocol.RequestMessage;
import org.apache.celeborn.common.network.protocol.RpcFailure;
import org.apache.celeborn.common.network.protocol.RpcRequest;
import org.apache.celeborn.common.network.protocol.TransportMessage;
import org.apache.celeborn.common.network.sasl.CelebornSaslServer;
import org.apache.celeborn.common.network.sasl.SaslRpcHandler;
import org.apache.celeborn.common.network.sasl.SecretKeyHolder;
import org.apache.celeborn.common.network.sasl.SecretRegistry;
import org.apache.celeborn.common.network.util.TransportConf;
import org.apache.celeborn.common.protocol.PbAuthType;
import org.apache.celeborn.common.protocol.PbAuthenticationInitiationRequest;
import org.apache.celeborn.common.protocol.PbAuthenticationInitiationResponse;
import org.apache.celeborn.common.protocol.PbRegisterApplicationRequest;
import org.apache.celeborn.common.protocol.PbRegisterApplicationResponse;
import org.apache.celeborn.common.protocol.PbSaslMechanism;
import org.apache.celeborn.common.protocol.PbSaslMessage;

public class RegistrationHandler extends BaseMessageHandler {
  private static final Logger LOG = LoggerFactory.getLogger(RegistrationHandler.class);

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

  /** Transport configuration. */
  private final TransportConf conf;

  /** The client channel. */
  private final Channel channel;

  private final BaseMessageHandler delegate;

  private RegistrationState registrationState = RegistrationState.NONE;

  /** Class which provides secret keys which are shared by server and client on a per-app basis. */
  private final SecretKeyHolder secretKeyHolder;

  private SaslRpcHandler saslHandler;

  /** Used for client authentication. */
  private CelebornSaslServer saslServer = null;

  public RegistrationHandler(
      TransportConf conf,
      Channel channel,
      BaseMessageHandler delegate,
      SecretKeyHolder secretKeyHolder) {
    this.conf = conf;
    this.channel = channel;
    this.secretKeyHolder = secretKeyHolder;
    this.delegate = delegate;
    this.saslHandler = new SaslRpcHandler(conf, channel, delegate, secretKeyHolder, null);
  }

  // TODO: This has to check the delegate
  @Override
  public boolean checkRegistered() {
    return delegate.checkRegistered();
  }

  @Override
  public final void receive(
      TransportClient client, RequestMessage message, RpcResponseCallback callback) {
    if (registrationState == RegistrationState.REGISTERED || saslHandler.isAuthenticated()) {
      LOG.trace("Already authenticated. Delegating {}", client.getClientId());
      delegate.receive(client, message, callback);
    } else {
      RpcRequest rpcRequest = (RpcRequest) message;
      try {
        register(client, rpcRequest, callback);
      } catch (IOException | CelebornException e) {
        LOG.error("Error while invoking RpcHandler#receive() on RPC id " + rpcRequest.requestId, e);
        client
            .getChannel()
            .writeAndFlush(
                new RpcFailure(rpcRequest.requestId, Throwables.getStackTraceAsString(e)));
      }
    }
  }

  @Override
  public final void receive(TransportClient client, RequestMessage message) {
    if (registrationState == RegistrationState.REGISTERED || saslHandler.isAuthenticated()) {
      LOG.trace("Already authenticated. Delegating {}", client.getClientId());
      delegate.receive(client, message);
    } else {
      throw new SecurityException("Unauthenticated call to receive().");
    }
  }

  private void register(TransportClient client, RpcRequest message, RpcResponseCallback callback)
      throws IOException, CelebornException {
    TransportMessage pbMsg = TransportMessage.fromByteBuffer(message.body().nioByteBuffer());
    switch (pbMsg.getMessageTypeValue()) {
      case AUTHENTICATION_INITIATION_REQUEST_VALUE:
        PbAuthenticationInitiationRequest authInitRequest = pbMsg.getParsedPayload();
        checkRequestAllowed(authInitRequest.getAppId(), RegistrationState.NONE);
        processAuthInitRequest(client, authInitRequest, callback);
        registrationState = RegistrationState.INIT;
        LOG.trace(
            "Authentication initialization completed: appId {} rpcId {}",
            authInitRequest.getAppId(),
            message.requestId);
        break;

      case SASL_MESSAGE_VALUE:
        PbSaslMessage saslMessage = pbMsg.getParsedPayload();
        if (saslMessage.getAuthType().equals(PbAuthType.CLIENT_AUTH)) {
          LOG.trace("Received Sasl Message for client authentication {}", saslMessage.getAppId());
          checkRequestAllowed(saslMessage.getAppId(), RegistrationState.INIT);
          authenticateClient(client, saslMessage, callback);
          if (saslServer.isComplete()) {
            LOG.debug("SASL authentication successful for channel {}", client);
            complete(true);
            registrationState = RegistrationState.AUTHENTICATED;
            LOG.trace(
                "Client authenticated: appId {} rpcId {}",
                saslMessage.getAppId(),
                message.requestId);
          }
        } else {
          // It is a SASL message to authenticate the connection, we first check if the app is
          // registered and then delegate the message to SaslRpcHandler
          if (SecretRegistry.getInstance().isRegistered(saslMessage.getAppId())) {
            LOG.trace(
                "Delegating to sasl handler: appId {} rpcId {}",
                saslMessage.getAppId(),
                message.requestId);
            saslHandler.receive(client, message, callback);
          } else {
            throw new CelebornException("Application is not registered " + saslMessage.getAppId());
          }
        }
        break;

      case REGISTER_APPLICATION_REQUEST_VALUE:
        PbRegisterApplicationRequest registerApplicationRequest = pbMsg.getParsedPayload();
        checkRequestAllowed(registerApplicationRequest.getAppId(), RegistrationState.AUTHENTICATED);
        LOG.trace("Application registration started {}", registerApplicationRequest.getAppId());
        processRegisterApplicationRequest(client, registerApplicationRequest, callback);
        registrationState = RegistrationState.REGISTERED;
        LOG.info(
            "Application registered: appId {} rpcId {} registry {}",
            registerApplicationRequest.getAppId(),
            message.requestId,
            SecretRegistry.getInstance());
        break;

      default:
        throw new CelebornException("Application is not registered " + message.requestId);
    }
  }

  private void checkRequestAllowed(String appId, RegistrationState expectedState)
      throws CelebornException {
    if (SecretRegistry.getInstance().isRegistered(appId)) {
      throw new CelebornException("Application is already registered " + appId);
    }
    if (registrationState != expectedState) {
      throw new CelebornException(
          "Invalid registration state. Expected: "
              + expectedState
              + ", Actual: "
              + registrationState);
    }
  }

  private void validateAuthenticateInitRequest(
      PbAuthenticationInitiationRequest initiationRequest) {
    // TODO: validate the request
  }

  private void processAuthInitRequest(
      TransportClient client,
      PbAuthenticationInitiationRequest authInitRequest,
      RpcResponseCallback callback) {
    validateAuthenticateInitRequest(authInitRequest);
    PbAuthenticationInitiationResponse response =
        PbAuthenticationInitiationResponse.newBuilder()
            .setAuthEnabled(true)
            .setVersion(VERSION)
            .addAllSaslMechanisms(SASL_MECHANISMS)
            .build();
    TransportMessage message =
        new TransportMessage(AUTHENTICATION_INITIATION_RESPONSE, response.toByteArray());
    callback.onSuccess(message.toByteBuffer());
  }

  private void authenticateClient(
      TransportClient client, PbSaslMessage saslMessage, RpcResponseCallback callback)
      throws CelebornException {
    if (saslServer == null || !saslServer.isComplete()) {
      if (saslServer == null) {
        // First message in the handshake, setup the necessary state.
        client.setClientId(saslMessage.getAppId());
        saslServer = new CelebornSaslServer(ANONYMOUS, null, null);
      }
      byte[] response = saslServer.response(saslMessage.getPayload().toByteArray());
      callback.onSuccess(ByteBuffer.wrap(response));
    } else {
      throw new CelebornException("Unexpected message type " + saslMessage.toString());
    }
  }

  private void processRegisterApplicationRequest(
      TransportClient client,
      PbRegisterApplicationRequest registerApplicationRequest,
      RpcResponseCallback callback) {
    // TODO: fix this to use the secretKeyHolder
    SecretRegistry.getInstance()
        .registerApplication(
            registerApplicationRequest.getAppId(), registerApplicationRequest.getSecret());
    PbRegisterApplicationResponse response =
        PbRegisterApplicationResponse.newBuilder().setStatus(true).build();
    TransportMessage message =
        new TransportMessage(REGISTER_APPLICATION_RESPONSE, response.toByteArray());
    callback.onSuccess(message.toByteBuffer());
  }

  private void complete(boolean dispose) {
    if (dispose) {
      try {
        saslServer.dispose();
      } catch (RuntimeException e) {
        LOG.error("Error while disposing SASL server", e);
      }
    }
    saslServer = null;
  }

  private enum RegistrationState {
    NONE,
    INIT,
    AUTHENTICATED,
    REGISTERED
  }
}
