/*
 * Demoiselle Framework
 * Copyright (C) 2016 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 *
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 *
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 *
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 *
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */

package org.demoiselle.signer.timestamp.connector;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Time-Stamp Protocol via HTTP
 * <p>
 * This subsection specifies a means for conveying ASN.1-encoded
 * messages for the protocol exchanges described in Section 2 and
 * Appendix D via the HyperText Transfer Protocol.
 * <p>
 * Two MIME objects are specified as follows.
 * <p>
 * Content-Type: application/timestamp-query
 * <p>
 * &lt;&lt;the ASN.1 DER-encoded Time-Stamp Request message&gt;&gt;
 * <p>
 * Content-Type: application/timestamp-reply
 * <p>
 * &lt;&lt;the ASN.1 DER-encoded Time-Stamp Response message&gt;&gt;
 * <p>
 * These MIME objects can be sent and received using common HTTP
 * processing engines over WWW links and provides a simple browser-
 * server transport for Time-Stamp messages.
 * <p>
 * Upon receiving a valid request, the server MUST respond with either a
 * valid response with content type application/timestamp-response or with an HTTP error.
 *
 * @author 07721825741
 */
public class HttpConnector implements Connector {

	private static final Logger logger = LoggerFactory.getLogger(HttpConnector.class);
	private String hostname;
	private int port;
	private OutputStream out = null;
	private HttpsURLConnection HttpsConnector;
	private static final String TIMESTAMP_QUERY_CONTENT_TYPE = "application/timestamp-query";

	private static MessagesBundle timeStampMessagesBundle = new MessagesBundle();

	@Override
	public InputStream connect(byte[] content) {
		 InputStream in = null;
		
		try {
		


			   URL myUrl = new URL("<https_url_provider>");
		       HttpsURLConnection conn = (HttpsURLConnection)myUrl.openConnection();
		       String userpass = "<client_id>" + ":" + <client_secret>";
		       String basicAuth = "Basic " + new String(Base64.getEncoder().encode(userpass.getBytes()));
		       //httpsurlconnection
		       conn.setRequestProperty("Authorization", basicAuth);
		       conn.setRequestMethod("POST");
		       conn.setRequestProperty("Content-Type", TIMESTAMP_QUERY_CONTENT_TYPE);
		       conn.setChunkedStreamingMode(1024);
		       conn.setDoInput(true);
		       conn.setDoOutput(true);
//			HttpURLConnection connection = (HttpURLConnection) url.openConnection();
//			connection.setRequestMethod("POST");
			//connection.setDoOutput(true);
			//connection.setDoInput(true);
			//connection.setRequestProperty("Authorization", "Basic " + encoding);
//			connection.setRequestProperty("Content-Type", TIMESTAMP_QUERY_CONTENT_TYPE);
			//connection.setChunkedStreamingMode(4 * 1024);

		       
		    // Calculando o resumo criptografico SHA-256 do conteudo que sera carimbado
				MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
				byte[] digest = messageDigest.digest("Teste".getBytes());

				TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
				timeStampRequestGenerator.setCertReq(true);
				// Definido o OID da politica
				timeStampRequestGenerator.setReqPolicy("2.16.76.1.6.6");

				// OID SHA-256
				TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate("2.16.840.1.101.3.4.2.1", digest,
						BigInteger.valueOf(new SecureRandom().nextInt()));

		       
//			// Enviando requisio de carimbo do tempo
			OutputStream connectionOutputStream = conn.getOutputStream();
			connectionOutputStream.write(timeStampRequest.getEncoded());
			connectionOutputStream.flush();

			in = conn.getInputStream();

		
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}
		
		return in;

	}

	@Override
	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	@Override
	public void setPort(int port) {
		this.port = port;
	}

	public HttpsURLConnection getHttpsConnector() {
		return HttpsConnector;
	}

	public void setHttpsConnector(HttpsURLConnection httpsConnector) {
		HttpsConnector = httpsConnector;
	}

	public String getHostname() {
		return hostname;
	}

	public int getPort() {
		return port;
	}

	@Override
	public void close() {
		try {
			this.HttpsConnector.disconnect();
			this.out.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	
	class CustomSSLSocketFactory extends SSLSocketFactory {
	    SSLSocketFactory factory = null;
	    CustomSSLSocketFactory(SSLSocketFactory factory) {
	        this.factory = factory;
	    }

	    @Override
	    public Socket createSocket(Socket s, String host, int port,
	            boolean autoClose) throws IOException {
	        Socket skt = factory.createSocket(s, host, port, autoClose);
	        return customizeSSLSocket(skt);
	    }

	    @Override
	    public String[] getDefaultCipherSuites() {
	        return factory.getDefaultCipherSuites();
	    }

	    @Override
	    public String[] getSupportedCipherSuites() {
	        return factory.getSupportedCipherSuites();
	    }

	    @Override
	    public Socket createSocket(String host, int port) throws IOException,
	            UnknownHostException {
	        Socket skt = factory.createSocket(host, port);
	        return customizeSSLSocket(skt);
	    }

	    @Override
	    public Socket createSocket(InetAddress host, int port) throws IOException {
	        Socket skt = factory.createSocket(host, port);
	        return customizeSSLSocket(skt);
	    }

	    @Override
	    public Socket createSocket(String host, int port, InetAddress localHost,
	            int localPort) throws IOException, UnknownHostException {
	        Socket skt = factory.createSocket(host, port, localHost, localPort);
	        return customizeSSLSocket(skt); 
	    }

	    @Override
	    public Socket createSocket(InetAddress address, int port,
	            InetAddress localAddress, int localPort) throws IOException {
	        Socket skt = factory.createSocket(address, port, localAddress, localPort);
	        return customizeSSLSocket(skt); 
	    }

	    private Socket customizeSSLSocket(Socket skt) throws SocketException {
	        ((SSLSocket)skt).addHandshakeCompletedListener(
	                new HandshakeCompletedListener() {
	                    public void handshakeCompleted(
	                            HandshakeCompletedEvent event) {
	                        System.out.println("Handshake finished!");
	                        System.out.println(
	                                "\t CipherSuite:" + event.getCipherSuite());
	                        System.out.println(
	                                "\t SessionId " + event.getSession());
	                        System.out.println(
	                                "\t PeerHost " + event.getSession().getPeerHost());
	                        System.out.println(
	                                "\t PeerHost " + event.getSession().getProtocol());

	                    }
	                }
	                );      
	        return skt;
	    }
	}

}
