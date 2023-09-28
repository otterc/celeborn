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

package org.apache.celeborn.service.deploy.master

import org.apache.celeborn.common.CelebornConf
import org.apache.celeborn.common.exception.CelebornException
import org.apache.celeborn.common.internal.Logging
import org.apache.celeborn.common.network.sasl.SecretRegistry
import org.apache.celeborn.common.protocol.message.ControlMessages._
import org.apache.celeborn.common.rpc._

private[celeborn] class MasterController(
    val master: Master,
    override val rpcEnv: RpcEnv,
    val conf: CelebornConf)
  extends RpcEndpoint with Logging {

  // start threads to check timeout for workers and applications
  override def onStart(): Unit = {
    master.onStartInternal()
  }

  override def onStop(): Unit = {
    master.onStopInternal()
  }

  override def onDisconnected(address: RpcAddress): Unit = {
    // The disconnected client could've been either a worker or an app; remove whichever it was
    logDebug(s"Controller $address got disassociated.")
  }

  override def receive: PartialFunction[Any, Unit] = {
    master.receive
  }

  override def receiveAndReply(context: RpcCallContext): PartialFunction[Any, Unit] = {
    case ApplicationMetaInfoRequest(appId, requestId) =>
      logInfo(s"Received request for meta info $requestId $appId.")
      master.executeWithLeaderChecker(
        context,
        handleRequestForApplicationMeta(context, appId))
    case _ =>
      master.receiveAndReply(context)
  }

  private[master] def handleRequestForApplicationMeta(
      context: RpcCallContext,
      applicationId: String): Unit = {
    logInfo(
      s"Handling request for application meta info $applicationId ${SecretRegistry.getInstance()}.")
    if (!SecretRegistry.getInstance().isRegistered(applicationId)) {
      logError(s"Couldn't find the app $applicationId ${SecretRegistry.getInstance()}.")
      throw new CelebornException("Application is not registered.")
    } else {
      logInfo(s"Found the app $applicationId ${SecretRegistry.getInstance()}.")
      context.reply(ApplicationMetaInfo(
        applicationId,
        SecretRegistry.getInstance().getSecret(applicationId)))
    }
  }
}
