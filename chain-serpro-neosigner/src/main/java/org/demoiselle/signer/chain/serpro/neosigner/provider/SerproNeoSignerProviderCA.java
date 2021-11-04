/*
 * Demoiselle Framework
 * Copyright (C) 2021 SERPRO
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

package org.demoiselle.signer.chain.serpro.neosigner.provider;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.demoiselle.signer.core.ca.provider.ProviderCA;
import org.demoiselle.signer.core.keystore.loader.configuration.Configuration;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides Certificate Authority chain of SERPRO's
 */
public class SerproNeoSignerProviderCA implements ProviderCA {

	protected static MessagesBundle chainMessagesBundle = new MessagesBundle();
	private static final Logger logger = LoggerFactory.getLogger(Configuration.class);

	@SuppressWarnings("finally")
	public Collection<X509Certificate> getCAs() {
		List<X509Certificate> result = new ArrayList<X509Certificate>();
		try {

			// CADEIAS de PRODUÇÃO
			InputStream AutoridadeCertificadoraAssinadorSERPRORaiz =
				SerproNeoSignerProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraAssinadorSERPRORaiz.crt");
			InputStream AutoridadeCertificadoraAssinadorSERPROFinal =
				SerproNeoSignerProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraAssinadorSERPROFinal.crt");
			// CADEIAS de HOMOLOGAÇÃO
			InputStream AutoridadeCertificadoraRaizdoSERPRO =
				SerproNeoSignerProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraRaizdoSERPRO.crt");
			InputStream AutoridadeCertificadoraFinaldoSERPRO =
				SerproNeoSignerProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraFinaldoSERPRO.crt");
			// CADEIA geradas em software/Testes
			InputStream AutoridadeCertificadoraRaizdoSERPROSoftware =
				SerproNeoSignerProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraRaizdoSERPROSoftware.crt");
			InputStream AutoridadeCertificadoraFinaldoSERPROSoftware =
				SerproNeoSignerProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraFinaldoSERPROSoftware.crt");

			logger.debug(chainMessagesBundle.getString("info.provider.name.serpro.neosigner"));
			result.add((X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(AutoridadeCertificadoraAssinadorSERPRORaiz));
			result.add((X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(AutoridadeCertificadoraAssinadorSERPROFinal));
			result.add((X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(AutoridadeCertificadoraRaizdoSERPRO));
			result.add((X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(AutoridadeCertificadoraFinaldoSERPRO));
			result.add((X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(AutoridadeCertificadoraRaizdoSERPROSoftware));
			result.add((X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(AutoridadeCertificadoraFinaldoSERPROSoftware));
		} catch (Throwable error) {
			logger.error(error.getMessage());
			return null;
		} finally {
			return result;
		}
	}

	public String getName() {
		return chainMessagesBundle.getString("info.provider.name.serpro.neosigner");
	}
}
