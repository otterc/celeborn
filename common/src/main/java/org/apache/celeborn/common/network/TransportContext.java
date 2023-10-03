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

package org.apache.celeborn.common.network;

import java.util.ArrayList;
import java.util.List;

import io.netty.channel.Channel;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.MessageToMessageEncoder;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.stream.ChunkedWriteHandler;
import io.netty.handler.timeout.IdleStateHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.celeborn.common.metrics.source.AbstractSource;
import org.apache.celeborn.common.network.client.TransportClient;
import org.apache.celeborn.common.network.client.TransportClientBootstrap;
import org.apache.celeborn.common.network.client.TransportClientFactory;
import org.apache.celeborn.common.network.client.TransportResponseHandler;
import org.apache.celeborn.common.network.protocol.Message;
import org.apache.celeborn.common.network.protocol.MessageEncoder;
import org.apache.celeborn.common.network.protocol.SslMessageEncoder;
import org.apache.celeborn.common.network.server.*;
import org.apache.celeborn.common.network.util.FrameDecoder;
import org.apache.celeborn.common.network.util.NettyLogger;
import org.apache.celeborn.common.network.util.TransportConf;
import org.apache.celeborn.common.network.util.TransportFrameDecoder;

/**
 * Contains the context to create a {@link TransportServer}, {@link TransportClientFactory}, and to
 * setup Netty Channel pipelines with a {@link TransportChannelHandler}.
 *
 * <p>There are two communication protocols that the TransportClient provides, control-plane RPCs
 * and data-plane "chunk fetching". The handling of the RPCs is performed outside the scope of the
 * TransportContext (i.e., by a user-provided handler), and it is responsible for setting up streams
 * which can be streamed through the data plane in chunks using zero-copy IO.
 *
 * <p>The TransportServer and TransportClientFactory both create a TransportChannelHandler for each
 * channel. As each TransportChannelHandler contains a TransportClient, this enables server
 * processes to send messages back to the client on an existing channel.
 */
public class TransportContext {
  private static final Logger logger = LoggerFactory.getLogger(TransportContext.class);

  private final TransportConf conf;
  private final BaseMessageHandler msgHandler;
  private final ChannelDuplexHandler channelsLimiter;
  private final boolean closeIdleConnections;
  private final boolean enableHeartbeat;
  private final AbstractSource source;

  private final TransportSslContext transportSslContext;

  private static final MessageEncoder ENCODER = MessageEncoder.INSTANCE;
  private static final MessageToMessageEncoder<Message> SSL_ENCODER = SslMessageEncoder.INSTANCE;

  private static final NettyLogger NETTY_LOGGER = new NettyLogger();

  public TransportContext(
      TransportConf conf,
      BaseMessageHandler msgHandler,
      boolean closeIdleConnections,
      ChannelDuplexHandler channelsLimiter,
      boolean enableHeartbeat,
      AbstractSource source,
      TransportSslContext transportSslContext) {
    this.conf = conf;
    this.msgHandler = msgHandler;
    this.closeIdleConnections = closeIdleConnections;
    this.channelsLimiter = channelsLimiter;
    this.enableHeartbeat = enableHeartbeat;
    this.source = source;
    this.transportSslContext = transportSslContext;
  }

  public TransportContext(
      TransportConf conf,
      BaseMessageHandler msgHandler,
      boolean closeIdleConnections,
      boolean enableHeartbeat,
      AbstractSource source,
      TransportSslContext transportSslContext) {
    this(
        conf, msgHandler, closeIdleConnections, null, enableHeartbeat, source, transportSslContext);
  }

  public TransportContext(
      TransportConf conf, BaseMessageHandler msgHandler, boolean closeIdleConnections) {
    this(conf, msgHandler, closeIdleConnections, null, false, null, null);
  }

  public TransportContext(TransportConf conf, BaseMessageHandler msgHandler) {
    this(conf, msgHandler, null);
  }

  public TransportContext(
      TransportConf conf, BaseMessageHandler msgHandler, TransportSslContext transportSslContext) {
    this(conf, msgHandler, false, false, null, transportSslContext);
  }

  /**
   * Initializes a ClientFactory which runs the given TransportClientBootstraps prior to returning a
   * new Client. Bootstraps will be executed synchronously, and must run successfully in order to
   * create a Client.
   */
  public TransportClientFactory createClientFactory(List<TransportClientBootstrap> bootstraps) {
    return new TransportClientFactory(this, bootstraps);
  }

  public TransportClientFactory createClientFactory() {
    return createClientFactory(new ArrayList<>());
  }

  /** Create a server which will attempt to bind to a specific host and port. */
  public TransportServer createServer(
      String host, int port, List<TransportServerBootstrap> bootstraps) {
    return new TransportServer(this, host, port, source, msgHandler, bootstraps);
  }

  public TransportServer createServer(int port, List<TransportServerBootstrap> bootstraps) {
    return createServer(null, port, bootstraps);
  }

  /** For Suite only */
  public TransportServer createServer() {
    return createServer(null, 0, new ArrayList<>());
  }

  public TransportChannelHandler initializePipeline(
      SocketChannel channel, ChannelInboundHandlerAdapter decoder, SslContext sslContext) {
    return initializePipeline(channel, decoder, sslContext, msgHandler);
  }

  public TransportChannelHandler initializePipeline(
      SocketChannel channel, SslContext sslContext, BaseMessageHandler resolvedMsgHandler) {
    return initializePipeline(channel, new TransportFrameDecoder(), sslContext, resolvedMsgHandler);
  }

  public TransportChannelHandler initializePipeline(
      SocketChannel channel,
      ChannelInboundHandlerAdapter decoder,
      SslContext sslContext,
      BaseMessageHandler resolvedMsgHandler) {
    try {
      if (sslContext != null) {
        channel.pipeline().addLast("sslHandler", sslContext.newHandler(channel.alloc()));
      }
      if (NETTY_LOGGER.getLoggingHandler() != null) {
        channel.pipeline().addLast("loggingHandler", NETTY_LOGGER.getLoggingHandler());
      }
      if (channelsLimiter != null) {
        channel.pipeline().addLast("limiter", channelsLimiter);
      }
      if (sslContext != null) {
        // Cannot use zero-copy with HTTPS, so we add in our ChunkedWriteHandler just before the
        // MessageEncoder
        channel.pipeline().addLast("chunkedWriter", new ChunkedWriteHandler());
      }
      TransportChannelHandler channelHandler = createChannelHandler(channel, resolvedMsgHandler);
      channel
          .pipeline()
          .addLast("encoder", sslContext != null ? SSL_ENCODER : ENCODER)
          .addLast(FrameDecoder.HANDLER_NAME, decoder)
          .addLast(
              "idleStateHandler",
              enableHeartbeat
                  ? new IdleStateHandler(conf.connectionTimeoutMs() / 1000, 0, 0)
                  : new IdleStateHandler(0, 0, conf.connectionTimeoutMs() / 1000))
          .addLast("handler", channelHandler);
      return channelHandler;
    } catch (RuntimeException e) {
      logger.error("Error while initializing Netty pipeline", e);
      throw e;
    }
  }

  private TransportChannelHandler createChannelHandler(
      Channel channel, BaseMessageHandler msgHandler) {
    TransportResponseHandler responseHandler = new TransportResponseHandler(conf, channel);
    TransportClient client = new TransportClient(channel, responseHandler);
    TransportRequestHandler requestHandler =
        new TransportRequestHandler(channel, client, msgHandler);
    return new TransportChannelHandler(
        client,
        responseHandler,
        requestHandler,
        conf.connectionTimeoutMs(),
        closeIdleConnections,
        enableHeartbeat,
        conf.clientHearbeatInterval());
  }

  public TransportConf getConf() {
    return conf;
  }

  public BaseMessageHandler getMsgHandler() {
    return msgHandler;
  }

  public SslContext getServerSslContext() {
    return transportSslContext != null ? transportSslContext.serverSslContext : null;
  }

  public SslContext getClientSslContext() {
    return transportSslContext != null ? transportSslContext.clientSslContext : null;
  }

  public static class TransportSslContext {
    private final SslContext serverSslContext;
    private final SslContext clientSslContext;

    public TransportSslContext(SslContext serverSslContext, SslContext clientSslContext) {
      this.serverSslContext = serverSslContext;
      this.clientSslContext = clientSslContext;
    }

    public SslContext getServerSslContext() {
      return serverSslContext;
    }

    public SslContext getClientSslContext() {
      return clientSslContext;
    }
  }
}
