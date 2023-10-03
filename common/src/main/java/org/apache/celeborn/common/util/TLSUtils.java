package org.apache.celeborn.common.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;

import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TLSUtils {
  private static Logger LOG = LoggerFactory.getLogger(TLSUtils.class);

  public static SslContext buildSslContextForServer(Path serverCertPath, Path serverKeyPath)
      throws IOException, CertificateException {
    SslProvider provider = OpenSsl.isAvailable() ? SslProvider.OPENSSL : SslProvider.JDK;
    LOG.info("SSL provider: {}", provider);
    SslContextBuilder sslContextBuilder =
        SslContextBuilder.forServer(
                Files.newInputStream(serverCertPath), Files.newInputStream(serverKeyPath))
            .sslProvider(provider);
    sslContextBuilder.trustManager(InsecureTrustManagerFactory.INSTANCE);
    return sslContextBuilder.build();
  }

  public static SslContext buildSslContextForClient(boolean validateCert) throws IOException {
    SslContextBuilder sslContextBuilder =
        SslContextBuilder.forClient().sslProvider(SslProvider.JDK);
    // FIXME: Make client validate the server certificate. When the client needs to validate cert,
    //  it will use the default JDK trust store
    sslContextBuilder.trustManager(InsecureTrustManagerFactory.INSTANCE);
    return sslContextBuilder.build();
  }
}
