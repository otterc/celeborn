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

package org.apache.celeborn.common.network.sasl;

import static org.apache.celeborn.common.network.sasl.SaslConstants.*;

import java.io.IOException;
import java.nio.ByteBuffer;

import com.google.common.base.Throwables;
import io.netty.channel.Channel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.celeborn.common.network.client.RpcResponseCallback;
import org.apache.celeborn.common.network.client.TransportClient;
import org.apache.celeborn.common.network.protocol.RequestMessage;
import org.apache.celeborn.common.network.protocol.RpcFailure;
import org.apache.celeborn.common.network.protocol.RpcRequest;
import org.apache.celeborn.common.network.protocol.TransportMessage;
import org.apache.celeborn.common.network.server.AbstractAuthRpcHandler;
import org.apache.celeborn.common.network.server.BaseMessageHandler;
import org.apache.celeborn.common.network.util.TransportConf;
import org.apache.celeborn.common.protocol.PbSaslMessage;

/**
 * RPC Handler which performs SASL authentication before delegating to a child RPC handler. The
 * delegate will only receive messages if the given connection has been successfully authenticated.
 * A connection may be authenticated at most once.
 *
 * <p>Note that the authentication process consists of multiple challenge-response pairs, each of
 * which are individual RPCs.
 */
public class SaslRpcHandler extends AbstractAuthRpcHandler {
  private static final Logger logger = LoggerFactory.getLogger(SaslRpcHandler.class);

  /** Transport configuration. */
  private final TransportConf conf;

  /** The client channel. */
  private final Channel channel;

  /** Class which provides secret keys which are shared by server and client on a per-app basis. */
  private final SecretKeyHolder secretKeyHolder;

  private CelebornSaslServer saslServer;
  private ApplicationMetaMissingHandler applicationMetaMissingHandler;

  public SaslRpcHandler(
      TransportConf conf,
      Channel channel,
      BaseMessageHandler delegate,
      SecretKeyHolder secretKeyHolder,
      ApplicationMetaMissingHandler applicationMetaMissingHandler) {
    super(delegate);
    this.conf = conf;
    this.channel = channel;
    this.secretKeyHolder = secretKeyHolder;
    this.saslServer = null;
    this.applicationMetaMissingHandler = applicationMetaMissingHandler;
  }

  @Override
  public boolean checkRegistered() {
    return delegate.checkRegistered();
  }

  @Override
  public boolean doAuthChallenge(
      TransportClient client, RequestMessage message, RpcResponseCallback callback) {
    if (saslServer == null || !saslServer.isComplete()) {
      RpcRequest rpcRequest = (RpcRequest) message;
      PbSaslMessage saslMessage = null;
      try {
        TransportMessage pbMsg = TransportMessage.fromByteBuffer(message.body().nioByteBuffer());
        saslMessage = pbMsg.getParsedPayload();
      } catch (IOException e) {
        logger.error(
            "Error while invoking RpcHandler#receive() on RPC id " + rpcRequest.requestId, e);
        client
            .getChannel()
            .writeAndFlush(
                new RpcFailure(rpcRequest.requestId, Throwables.getStackTraceAsString(e)));
      }
      assert saslMessage != null;
      if (saslServer == null) {
        // Check if the application meta info is present or not. If it isn't then we need to pull
        // that information
        // from the Master. If this is the Master, then it will definitely have the info at this
        // point.
        if (!SecretRegistry.getInstance().isRegistered(saslMessage.getAppId())) {
          logger.debug(
              "Application meta info missing for {} {}",
              saslMessage.getAppId(),
              applicationMetaMissingHandler);
          // Pull the information from master
          if (applicationMetaMissingHandler != null) {
            applicationMetaMissingHandler.applicationMetaMissing(saslMessage.getAppId());
          }
        }
        if (!SecretRegistry.getInstance().isRegistered(saslMessage.getAppId())) {
          throw new RuntimeException("Application has not registered " + saslMessage.getAppId());
        }

        // First message in the handshake, setup the necessary state.
        client.setClientId(saslMessage.getAppId());
        saslServer =
            new CelebornSaslServer(
                DIGEST,
                SASL_SERVER_PROPS,
                new CelebornSaslServer.DigestCallbackHandler(
                    saslMessage.getAppId(), secretKeyHolder));
      }

      byte[] response = saslServer.response(saslMessage.getPayload().toByteArray());
      callback.onSuccess(ByteBuffer.wrap(response));
    }

    // Setup encryption after the SASL response is sent, otherwise the client can't parse the
    // response. It's ok to change the channel pipeline here since we are processing an incoming
    // message, so the pipeline is busy and no new incoming messages will be fed to it before this
    // method returns. This assumes that the code ensures, through other means, that no outbound
    // messages are being written to the channel while negotiation is still going on.
    if (saslServer.isComplete()) {
      logger.debug("SASL authentication successful for channel {}", client);
      complete(true);
      return true;
    }
    return false;
  }

  @Override
  public void channelInactive(TransportClient client) {
    try {
      super.channelInactive(client);
    } finally {
      if (saslServer != null) {
        saslServer.dispose();
      }
    }
  }

  private void complete(boolean dispose) {
    if (dispose) {
      try {
        saslServer.dispose();
      } catch (RuntimeException e) {
        logger.error("Error while disposing SASL server", e);
      }
    }
    saslServer = null;
  }
}
