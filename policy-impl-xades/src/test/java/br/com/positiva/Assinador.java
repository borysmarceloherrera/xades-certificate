package br.com.positiva;



import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.util.Calendar;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.demoiselle.signer.policy.impl.xades.XMLPoliciesOID;
import org.demoiselle.signer.policy.impl.xades.xml.impl.XMLSigner;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;



public class Assinador {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		


DocumentBuilderFactory dbf =
  DocumentBuilderFactory.newInstance(); 

dbf.setNamespaceAware(true); 

DocumentBuilder builder = null;
try {
	builder = dbf.newDocumentBuilder();
} catch (ParserConfigurationException e5) {
	// TODO Auto-generated catch block
	e5.printStackTrace();
}  
Document doc = null;
try {
	doc = builder.parse(new FileInputStream("/home/borys/teste.xml"));
	//doc = builder.parse(new FileInputStream("/home/borys/assinado1_101_2021_15_23_54_645.xml"));
	
} catch (SAXException | IOException e5) {
	// TODO Auto-generated catch block
	e5.printStackTrace();
} 

/*
KeyStore ks = null;
try {
	ks = KeyStore.getInstance("JKS");
} catch (KeyStoreException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
}
InputStream readStream = null;
try {
	readStream = new FileInputStream("/home/borys/FABRICADS/POSITIVA/CERTIFICADOS/keystore.jks");
} catch (FileNotFoundException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
}
try {
	ks.load(readStream, "password".toCharArray());
} catch (NoSuchAlgorithmException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
} catch (CertificateException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
} catch (IOException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
}
Key key = null;
try {
	key = ks.getKey("keyAlias", "password".toCharArray());
} catch (UnrecoverableKeyException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
} catch (KeyStoreException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
} catch (NoSuchAlgorithmException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
}
try {
	readStream.close();
} catch (IOException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
}

XMLSigner xades = new XMLSigner();
xades.setPrivateKey((PrivateKey)key);

xades.setPolicyId(null);

doc = xades.signEnveloped(doc);

*/
/*
KeyPairGenerator kpg = null;
try {
	kpg = KeyPairGenerator.getInstance("DSA");
} catch (NoSuchAlgorithmException e5) {
	// TODO Auto-generated catch block
	e5.printStackTrace();
}
kpg.initialize(2048);
KeyPair kp = kpg.generateKeyPair(); 


DOMSignContext dsc = new DOMSignContext
(kp.getPrivate(), doc.getDocumentElement()); 

XMLSignatureFactory fac = 
XMLSignatureFactory.getInstance("DOM"); 

Reference ref = null;
try {
	ref = fac.newReference
	("", fac.newDigestMethod(DigestMethod.SHA256, null),
	  Collections.singletonList
	    (fac.newTransform(Transform.ENVELOPED,
	      (TransformParameterSpec) null)), null, null);
} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e4) {
	// TODO Auto-generated catch block
	e4.printStackTrace();
} 


SignedInfo si = null;
try {
	si = fac.newSignedInfo
	(fac.newCanonicalizationMethod
	  (CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
	    (C14NMethodParameterSpec) null),
	  fac.newSignatureMethod("http://www.w3.org/2009/xmldsig11#dsa-sha256", null),
	  Collections.singletonList(ref));
} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e3) {
	// TODO Auto-generated catch block
	e3.printStackTrace();
} 


KeyInfoFactory kif = fac.getKeyInfoFactory(); 

KeyValue kv = null;
try {
	kv = kif.newKeyValue(kp.getPublic());
} catch (KeyException e2) {
	// TODO Auto-generated catch block
	e2.printStackTrace();
}
KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv)); 

XMLSignature signature = fac.newXMLSignature(si, ki); 

try {
	signature.sign(dsc);
} catch (MarshalException | XMLSignatureException e1) {
	// TODO Auto-generated catch block
	e1.printStackTrace();
} 

*/


try {

	
	
	KeyStore ks = null;
	try {
		ks = KeyStore.getInstance("JKS");
	} catch (KeyStoreException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	InputStream readStream = null;
	try {
		readStream = new FileInputStream("/home/borys/FABRICADS/POSITIVA/CERTIFICADOS/fabricads.jks");
	} catch (FileNotFoundException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	try {
		ks.load(readStream, "password".toCharArray());
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (CertificateException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	
	
	// window ou NeoID
	//ks = getKeyStoreTokenBySigner();

	// arquivo
	// ks = getKeyStoreFileBySigner();

	// token
	// ks = getKeyStoreToken();

	//String fileName = "teste.xml";


	String alias = "selfsigned";//getAlias(ks);
	XMLSigner xmlSigner = new XMLSigner(XMLPoliciesOID.AD_RA_XADES_2_3);
	
	
	System.out.println(ks.getKey("selfsigned", "password".toCharArray()));

	// para token
	xmlSigner.setPrivateKey((PrivateKey) ks.getKey("selfsigned", "password".toCharArray()));

	// para arquivo
	// quando certificado em arquivo, precisa informar a senha
	// char[] senha = "teste".toCharArray();
	// xmlSigner.setPrivateKey((PrivateKey) ks.getKey(alias, senha));
	
	System.out.println(ks.getCertificateChain("selfsigned"));
	System.out.println(ks.aliases());

	xmlSigner.setCertificateChain(ks.getCertificateChain("selfsigned"));
	// para mudar a politica
	xmlSigner.setPolicyId(XMLPoliciesOID.AD_RA_XADES_2_3.getOID());
	// indicando o local do arquivo XML
	Document docSigned = xmlSigner.signEnveloped(doc);
	
	
	/**
	 * itemsDiplomado: [{
        title: 'IES Representantes', // eCPF 1 ou mais assinaturas (reitor, decano ou chefe de departamento)
        step: 1,
        sequence: 1,
        rolesParsed: [{}],
        nodes: 'DadosDiplomaNSF', // Se for do sistema federal de ensino usar a tag 'DadosDiploma', sistema privado usar 'DadosDiplomaNSF'.
        policyOID: "2.16.76.1.7.1.6.2.4",
        multi: true
    }, {
        title: 'IES Emissora', // eCNPJ 1 assinatura
        step: 1,
        sequence: 2,
        rolesParsed: [{}],
        nodes: 'DadosDiplomaNSF', // Se for do sistema federal de ensino usar a tag 'DadosDiploma', sistema privado usar 'DadosDiplomaNSF'.
        policyOID: "2.16.76.1.7.1.9.2.4",
        multi: false
    }, {
        title: 'Pessoas Físicas', // eCPF 1 ou mais assinaturas
        step: 1,
        sequence: 3,
        rolesParsed: [{}],
        nodes: 'DadosRegistroNSF', // Se for do sistema federal de ensino usar a tag 'DadosRegistro', sistema privado usar 'DadosRegistroNSF'.
        policyOID: "2.16.76.1.7.1.6.2.4",
        multi: true
    }, {
        title: 'IES Registradora', // eCNPJ 1 assinatura
        step: 1,
        sequence: 4,
        rolesParsed: [{}],
        nodes: 'Diploma',
        policyOID: "2.16.76.1.7.1.10.2.4",
        multi: false
    }]
	 */
	

	
	
	
	
	OutputStream os = null;
	Calendar calend = Calendar.getInstance();

	  try {
		  
		  //os = new FileOutputStream("/home/borys/assinado1_101_2021_15_23_54_645.xml");} catch (FileNotFoundException e) {
		  os = new FileOutputStream("/home/borys/assinado"+calend.get(Calendar.DAY_OF_MONTH)+ "_"+ calend.get(Calendar.MONTH)+1 +"_"+ calend.get(Calendar.YEAR)+"_"+calend.get(Calendar.HOUR_OF_DAY)+ "_"+calend.get(Calendar.MINUTE)+"_"+calend.get(Calendar.SECOND)+"_"+calend.get(Calendar.MILLISECOND)+".xml");} catch (FileNotFoundException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}

	TransformerFactory tf = TransformerFactory.newInstance();
	Transformer trans = tf.newTransformer();
	trans.transform(new DOMSource(docSigned), new StreamResult(os));

} catch (TransformerException e) {
	e.printStackTrace();
} catch (Throwable e) {
	e.printStackTrace();
}

/*
OutputStream os = null;
Calendar calend = Calendar.getInstance();

  try {
	  os = new FileOutputStream("/home/borys/assinado"+calend.get(Calendar.DAY_OF_MONTH)+ "_"+ calend.get(Calendar.MONTH)+1 +"_"+ calend.get(Calendar.YEAR)+"_"+calend.get(Calendar.HOUR_OF_DAY)+ "_"+calend.get(Calendar.MINUTE)+"_"+calend.get(Calendar.SECOND)+"_"+calend.get(Calendar.MILLISECOND)+".xml");} catch (FileNotFoundException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
}

TransformerFactory tf = TransformerFactory.newInstance();
Transformer trans = null;
try {
	trans = tf.newTransformer();
} catch (TransformerConfigurationException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
}
try {
	trans.transform(new DOMSource(doc), new StreamResult(os));
} catch (TransformerException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
} 

*/

	}

	
	
	

}
