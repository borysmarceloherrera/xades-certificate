/*
 * Demoiselle Framework
 * Copyright (c) 2009 Serpro and other contributors as indicated
 * by the @author tag. See the copyright.txt in the distribution for a
 * full listing of contributors.
 *
 * Demoiselle Framework is an open source Java EE library designed to accelerate
 * the development of transactional database Web applications.
 *
 * Demoiselle Framework is released under the terms of the LGPL license 3
 * http://www.gnu.org/licenses/lgpl.html  LGPL License 3
 *
 * This file is part of Demoiselle Framework.
 *
 * Demoiselle Framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License 3 as published by
 * the Free Software Foundation.
 *
 * Demoiselle Framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Demoiselle Framework.  If not, see <http://www.gnu.org/licenses/>.
 */
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
 * Este arquivo ?? parte do Framework Demoiselle.
 *
 * O Framework Demoiselle ?? um software livre; voc?? pode redistribu??-lo e/ou
 * modific??-lo dentro dos termos da GNU LGPL vers??o 3 como publicada pela Funda????o
 * do Software Livre (FSF).
 *
 * Este programa ?? distribu??do na esperan??a que possa ser ??til, mas SEM NENHUMA
 * GARANTIA; sem uma garantia impl??cita de ADEQUA????O a qualquer MERCADO ou
 * APLICA????O EM PARTICULAR. Veja a Licen??a P??blica Geral GNU/LGPL em portugu??s
 * para maiores detalhes.
 *
 * Voc?? deve ter recebido uma c??pia da GNU LGPL vers??o 3, sob o t??tulo
 * "LICENCA.txt", junto com esse programa. Se n??o, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Funda????o do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */

package org.demoiselle.signer.core.oid;

/**
 * Class OID 2.16.76.1.3.2 <br>
 * <br>
 * It has some specific attributes of ICP-BRASIL'S "Pessoa Juridica" or equipment. <br>
 * <b>* Name of the person responsible for the certificate </b> <br>
 */
public class OID_2_16_76_1_3_2 extends OIDGeneric {

	public static final String OID = "2.16.76.1.3.2";

	public OID_2_16_76_1_3_2() {
	}

	@Override
	public void initialize() {
	}

	/**
	 * @return Name of the person responsible for the certificate
	 */
	public String getName() {
		return super.getData();
	}
}
