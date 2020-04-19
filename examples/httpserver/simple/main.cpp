/****************************************************************************
**
** Copyright (C) 2018 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtHttpServer module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:BSD$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** BSD License Usage
** Alternatively, you may use this file under the terms of the BSD license
** as follows:
**
** "Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are
** met:
**   * Redistributions of source code must retain the above copyright
**     notice, this list of conditions and the following disclaimer.
**   * Redistributions in binary form must reproduce the above copyright
**     notice, this list of conditions and the following disclaimer in
**     the documentation and/or other materials provided with the
**     distribution.
**   * Neither the name of The Qt Company Ltd nor the names of its
**     contributors may be used to endorse or promote products derived
**     from this software without specific prior written permission.
**
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
** "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
** LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
** A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
** OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
** OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
**
** $QT_END_LICENSE$
**
****************************************************************************/

#include <QHttpServerResponse>
#include <QtCore>
#include <QtHttpServer>
#if QT_CONFIG(ssl)
#ifdef DEFAULT_CERT
#include "SSLConfig.h"
#endif
#endif

static inline QString host(const QHttpServerRequest& request)
{
    return request.headers()[QStringLiteral("Host")].toString();
}

int main(int argc, char* argv[])
{
    QCoreApplication app(argc, argv);
    quint16 httpPort = 2332;
    quint16 httpSSLPort = 2333;

    if (qEnvironmentVariableIsSet("HTTP_PORT"))
        httpPort = qEnvironmentVariableIntValue("HTTP_PORT");
    if (qEnvironmentVariableIsSet("HTTPS_PORT"))
        httpSSLPort = qEnvironmentVariableIntValue("HTTPS_PORT");


    QHttpServer httpServer;

    httpServer.route("/", []() { return "Hello world"; });

    httpServer.route("/query", [](const QHttpServerRequest& request) {
        QHttpServerResponse response(QByteArray("text/plain"), QByteArray("Error"),
                                     QHttpServerResponse::StatusCode::NotFound);
        return response;
        //        return QString("%1/query/").arg(host(request));
    });

    httpServer.route("/query/", [](qint32 id, const QHttpServerRequest& request) {
        return QString("%1/query/%2").arg(host(request)).arg(id);
    });

    httpServer.route("/query/<arg>/log", [](qint32 id, const QHttpServerRequest& request) {
        return QString("%1/query/%2/log").arg(host(request)).arg(id);
    });

    httpServer.route("/query/<arg>/log/", [](qint32 id, float threshold, const QHttpServerRequest& request) {
        return QString("%1/query/%2/log/%3").arg(host(request)).arg(id).arg(threshold);
    });

    httpServer.route("/user/", [](const qint32 id) { return QString("User %1").arg(id); });

    httpServer.route("/user/<arg>/detail", [](const qint32 id) { return QString("User %1 detail").arg(id); });

    httpServer.route("/user/<arg>/detail/", [](const qint32 id, const qint32 year) {
        return QString("User %1 detail year - %2").arg(id).arg(year);
    });

    httpServer.route("/json/", [] { return QJsonObject{{{"key1", "1"}, {"key2", "2"}, {"key3", "3"}}}; });

    httpServer.route("/assets/<arg>", [](const QUrl& url) {
        return QHttpServerResponse::fromFile(QStringLiteral(":/assets/%1").arg(url.path()));
    });

    httpServer.route("/remote_address",
                     [](const QHttpServerRequest& request) { return request.remoteAddress().toString(); });

    const auto port = httpServer.listen(QHostAddress::Any, httpPort);
    if (!port)
    {
        qDebug() << QCoreApplication::translate("QHttpServerExample", "Server failed to listen on a port.");
        return 0;
    }

    qDebug() << QCoreApplication::translate("QHttpServerExample",
                                            "Running on http://127.0.0.1:%1/ (Press CTRL+C to quit)")
                    .arg(port);

#if QT_CONFIG(ssl)
    // openssl genrsa -des3 -out server.key 1024
    // openssl req -new -key server.key -out server.csr
    // cp server.key server.key.org
    // openssl rsa -in server.key.org -out server.key
    // openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
#ifdef USER_CERT
    QFile certificate("server.crt");
    certificate.open(QIODevice::ReadOnly);
    auto g_certificate = certificate.readAll();

    QFile key("server.key");
    key.open(QIODevice::ReadOnly);
    auto g_privateKey = key.readAll();
#else
#error Provide server certificate or disable SSL
#endif

    httpServer.sslSetup(QSslCertificate(g_certificate), QSslKey(g_privateKey, QSsl::KeyAlgorithm::Rsa),
                        QSsl::SslProtocol::TlsV1_3OrLater);

    const auto portSSL = httpServer.listen(QHostAddress::Any, httpSSLPort);
    if (!portSSL)
    {
        qDebug() << QCoreApplication::translate("QHttpServerExample", "Server failed to listen on a port.");
        return 0;
    }
    qDebug() << QCoreApplication::translate("QHttpServerExample",
                                            "Running on https://127.0.0.1:%1/ (Press CTRL+C to quit)")
                    .arg(portSSL);

    // Code that might be required to pass tests if there will be any
    //#ifndef QT_NO_OPENSSL
    //#define CERTIFICATE_ERROR QSslError::SelfSignedCertificate
    //#else
    //#define CERTIFICATE_ERROR QSslError::CertificateUntrusted
    //#endif
    //    QList<QSslError> expectedSslErrors;
    //    expectedSslErrors.append(QSslError(CERTIFICATE_ERROR, QSslCertificate(g_certificate)));
    //    expectedSslErrors.append(QSslError(QSslError::HostNameMismatch, QSslCertificate(g_certificate)));

    //    connect(&networkAccessManager, &QNetworkAccessManager::sslErrors,
    //            [expectedSslErrors](QNetworkReply* reply, const QList<QSslError>& errors) {
    //                for (const auto& error : errors)
    //                {
    //                    for (const auto& expectedError : expectedSslErrors)
    //                    {
    //                        if (error.error() != expectedError.error() ||
    //                            error.certificate() != expectedError.certificate())
    //                        {
    //                            qCritical() << "Got unexpected ssl error:" << error << error.certificate();
    //                        }
    //                    }
    //                }
    //                reply->ignoreSslErrors(expectedSslErrors);
    //            });

#endif

    return app.exec();
}
