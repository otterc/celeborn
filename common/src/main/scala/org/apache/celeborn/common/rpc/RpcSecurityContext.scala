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
package org.apache.celeborn.common.security

import io.netty.handler.ssl.SslContext

import org.apache.celeborn.common.network.client.TransportClientBootstrap
import org.apache.celeborn.common.network.sasl.{ApplicationMetaMissingHandler, SaslCredentials, SecretKeyHolder}
import org.apache.celeborn.common.network.server.TransportServerBootstrap

/**
 * Represents the security context, combining both client and server contexts.
 *
 * @param clientSecurityContext Optional client security context.
 * @param serverSecurityContext Optional server security context.
 */
private[celeborn] case class SecurityContext(
    clientSecurityContext: Option[ClientSecurityContext] = None,
    serverSecurityContext: Option[ServerSecurityContext] = None)

/**
 * Represents the client security context.
 *
 * @param sslContext        Optional SSL context for secure communication.
 * @param clientSaslContext Optional client SASL context.
 */
private[celeborn] case class ClientSecurityContext(
    sslContext: Option[SslContext] = None,
    clientSaslContext: Option[ClientSaslContext] = None)

/**
 * Represents the SASL context.
 */
private[celeborn] trait SaslContext {}

private[celeborn] case class ClientSaslContext(
    appId: String,
    saslCredentials: SaslCredentials,
    addRegistrationBootstrap: Boolean = false) extends SaslContext

private[celeborn] case class ServerSaslContext(
    secretKeyHolder: SecretKeyHolder,
    addRegistrationBootstrap: Boolean = false,
    applicationMetaMissingHandler: Option[ApplicationMetaMissingHandler] = None) extends SaslContext

/**
 * Represents the server security context.
 *
 * @param sslContext        Optional SSL context for secure communication.
 * @param serverSaslContext Optional holder of secret keys for further encryption or signing.
 */
private[celeborn] case class ServerSecurityContext(
    sslContext: Option[SslContext] = None,
    serverSaslContext: Option[ServerSaslContext] = None)

/**
 * Builder for [[ClientSecurityContext]].
 */
private[celeborn] class ClientSecurityContextBuilder {
  private var sslContext: Option[SslContext] = None
  private var saslUser: String = _
  private var saslPassword: String = _
  private var appId: String = _
  private var addRegistrationBootstrap: Boolean = false

  def withSslContext(sslContext: Option[SslContext]): ClientSecurityContextBuilder = {
    this.sslContext = sslContext
    this
  }

  def withSaslUser(user: String): ClientSecurityContextBuilder = {
    this.saslUser = user
    this
  }

  def withSaslPassword(password: String): ClientSecurityContextBuilder = {
    this.saslPassword = password
    this
  }

  def withAppId(appId: String): ClientSecurityContextBuilder = {
    this.appId = appId
    this
  }

  def withAddRegistrationBootstrap(addRegistrationBootstrap: Boolean)
      : ClientSecurityContextBuilder = {
    this.addRegistrationBootstrap = addRegistrationBootstrap
    this
  }

  def build(): ClientSecurityContext = {
    if ((saslUser == null && saslPassword != null) || (saslUser != null && saslPassword == null)) {
      throw new IllegalStateException(
        "SASL user and password must be set or unset at the same time.")
    }
    val clientSaslContext =
      if (saslUser != null) {
        Some(ClientSaslContext(
          appId,
          new SaslCredentials(saslUser, saslPassword),
          addRegistrationBootstrap))
      } else {
        None
      }
    ClientSecurityContext(sslContext, clientSaslContext)
  }
}

/**
 * Builder for [[ServerSecurityContext]].
 */
private[celeborn] class ServerSecurityContextBuilder {
  private var sslContext: Option[SslContext] = None
  private var secretKeyHolder: SecretKeyHolder = _
  private var addRegistrationBootstrap: Boolean = false
  private var applicationMetaMissingHandler: Option[ApplicationMetaMissingHandler] = None

  def withSslContext(sslContext: Option[SslContext]): ServerSecurityContextBuilder = {
    this.sslContext = sslContext
    this
  }

  def withSecretKeyHolder(keyHolder: SecretKeyHolder): ServerSecurityContextBuilder = {
    this.secretKeyHolder = keyHolder
    this
  }

  def withAddRegistrationBootstrap(addRegistrationBootstrap: Boolean)
      : ServerSecurityContextBuilder = {
    this.addRegistrationBootstrap = addRegistrationBootstrap
    this
  }

  def withAppMetaMissingHandler(handler: ApplicationMetaMissingHandler)
      : ServerSecurityContextBuilder = {
    this.applicationMetaMissingHandler = Some(handler)
    this
  }

  def build(): ServerSecurityContext = {
    val serverSaslContext =
      if (secretKeyHolder != null) {
        Some(ServerSaslContext(
          secretKeyHolder,
          addRegistrationBootstrap,
          applicationMetaMissingHandler))
      } else {
        None
      }
    ServerSecurityContext(sslContext, serverSaslContext)
  }
}

/**
 * Builder for [[SecurityContext]].
 */
private[celeborn] class SecurityContextBuilder {
  private var clientSecurityContext: Option[ClientSecurityContext] = None
  private var serverSecurityContext: Option[ServerSecurityContext] = None

  def withClientSecurityContext(context: ClientSecurityContext): SecurityContextBuilder = {
    this.clientSecurityContext = Some(context)
    this
  }

  def withServerSecurityContext(context: ServerSecurityContext): SecurityContextBuilder = {
    this.serverSecurityContext = Some(context)
    this
  }

  def build(): SecurityContext = SecurityContext(clientSecurityContext, serverSecurityContext)
}
