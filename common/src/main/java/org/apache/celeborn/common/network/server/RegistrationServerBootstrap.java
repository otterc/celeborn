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

import io.netty.channel.Channel;

import org.apache.celeborn.common.network.sasl.SecretKeyHolder;
import org.apache.celeborn.common.network.util.TransportConf;

/**
 * A bootstrap which is executed on a TransportServer's client channel once a client connects to the
 * server, enabling authentication using Spark's auth protocol (and optionally SASL for clients that
 * don't support the new protocol).
 *
 * <p>It also automatically falls back to SASL if the new encryption backend is disabled, so that
 * callers only need to install this bootstrap when authentication is enabled.
 */
public class RegistrationServerBootstrap implements TransportServerBootstrap {

  private final TransportConf conf;
  private final SecretKeyHolder secretKeyHolder;

  public RegistrationServerBootstrap(TransportConf conf, SecretKeyHolder secretKeyHolder) {
    this.conf = conf;
    this.secretKeyHolder = secretKeyHolder;
  }

  @Override
  public BaseMessageHandler doBootstrap(Channel channel, BaseMessageHandler rpcHandler) {
    return new RegistrationHandler(conf, channel, rpcHandler, secretKeyHolder);
  }
}
