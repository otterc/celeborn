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

import java.util

import scala.collection.JavaConverters._
import scala.util.Random

import org.apache.celeborn.common.CelebornConf
import org.apache.celeborn.common.exception.CelebornException
import org.apache.celeborn.common.internal.Logging
import org.apache.celeborn.common.meta.WorkerInfo
import org.apache.celeborn.common.network.sasl.SecretRegistry
import org.apache.celeborn.common.protocol.{PbCheckForWorkerTimeout, PbRegisterWorker, PbRemoveWorkersUnavailableInfo, PbWorkerLost}
import org.apache.celeborn.common.protocol.message.ControlMessages._
import org.apache.celeborn.common.rpc._
import org.apache.celeborn.common.util.PbSerDeUtils

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
    case _: PbCheckForWorkerTimeout =>
      master.executeWithLeaderChecker(null, master.timeoutDeadWorkers())
    case CheckForWorkerUnavailableInfoTimeout =>
      master.executeWithLeaderChecker(null, master.timeoutWorkerUnavailableInfos())
    case CheckForApplicationTimeOut =>
      master.executeWithLeaderChecker(null, master.timeoutDeadApplications())
    case CheckForHDFSExpiredDirsTimeout =>
      master.executeWithLeaderChecker(null, master.checkAndCleanExpiredAppDirsOnHDFS())
    case pb: PbWorkerLost =>
      master.internalWorkerLost(null, pb)
    case pb: PbRemoveWorkersUnavailableInfo =>
      val unavailableWorkers = new util.ArrayList[WorkerInfo](pb.getWorkerInfoList
        .asScala.map(PbSerDeUtils.fromPbWorkerInfo).toList.asJava)
      master.executeWithLeaderChecker(
        null,
        master.handleRemoveWorkersUnavailableInfos(unavailableWorkers, pb.getRequestId))
  }
  override def receiveAndReply(context: RpcCallContext): PartialFunction[Any, Unit] = {
    case ApplicationMetaInfoRequest(appId, requestId) =>
      logDebug(s"Received request for meta info $requestId $appId.")
      master.executeWithLeaderChecker(
        context,
        handleRequestForApplicationMeta(context, appId))
    case HeartbeatFromWorker(
          host,
          rpcPort,
          pushPort,
          fetchPort,
          replicatePort,
          internalRpcPort,
          disks,
          userResourceConsumption,
          activeShuffleKey,
          estimatedAppDiskUsage,
          highWorkload,
          requestId) =>
      master.internalHeartbeatFromWorker(
        context,
        host,
        rpcPort,
        pushPort,
        fetchPort,
        replicatePort,
        internalRpcPort,
        disks,
        userResourceConsumption,
        activeShuffleKey,
        estimatedAppDiskUsage,
        highWorkload,
        requestId)
    case pbRegisterWorker: PbRegisterWorker =>
      logDebug(s"Received register worker from  ${pbRegisterWorker.getHost}")
      master.internalWorkerRegister(context, pbRegisterWorker)
    case ReportWorkerUnavailable(failedWorkers: util.List[WorkerInfo], requestId: String) =>
      master.internalWorkerUnavailable(context, failedWorkers, requestId)
    case pb: PbWorkerLost =>
      logDebug(s"Received worker lost from  ${pb.getHost}")
      master.internalWorkerLost(context, pb)
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
