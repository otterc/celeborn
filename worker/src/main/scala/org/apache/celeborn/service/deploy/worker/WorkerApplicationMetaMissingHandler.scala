package org.apache.celeborn.service.deploy.worker

import org.apache.celeborn.common.client.MasterClient
import org.apache.celeborn.common.internal.Logging
import org.apache.celeborn.common.network.sasl.{ApplicationMetaMissingHandler, SecretRegistry}
import org.apache.celeborn.common.protocol.message.ControlMessages.{ApplicationMetaInfo, ApplicationMetaInfoRequest}

class WorkerApplicationMetaMissingHandler()
  extends ApplicationMetaMissingHandler with Logging {

  private var masterClient: MasterClient = _

  private[worker] def init(masterClient: MasterClient): Unit = {
    this.masterClient = masterClient
  }

  override def applicationMetaMissing(appId: String): Unit = {
    try {
      assert(masterClient != null)
      logInfo(s"fetched the application meta info for $appId from the master")
      val resp = masterClient.askSync[ApplicationMetaInfo](
        ApplicationMetaInfoRequest(appId, MasterClient.genRequestId()),
        classOf[ApplicationMetaInfo])
      logInfo(s"Successfully fetched the application meta info for $appId from the master")
      SecretRegistry.getInstance().registerApplication(appId, resp.secret)
    } catch {
      case throwable: Throwable =>
        val errMsg = s"Failed to fetch the application meta info for $appId from the master"
        logWarning(errMsg, throwable)
    }
  }
}
