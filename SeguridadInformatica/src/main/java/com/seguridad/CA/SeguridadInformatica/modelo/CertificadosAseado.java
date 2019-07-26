package com.seguridad.CA.SeguridadInformatica.modelo;

import java.io.FileOutputStream;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.swing.plaf.synth.SynthSeparatorUI;

import org.bouncycastle.asn1.mozilla.PublicKeyAndChallenge;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.mozilla.jcajce.JcaSignedPublicKeyAndChallenge;
import org.bouncycastle.util.encoders.Base64;

import sun.security.pkcs10.PKCS10;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

@SuppressWarnings({ "unused", "restriction" })
public class CertificadosAseado {

	//Medida de las claves
	public static final int KEY_LEN = 2048;

	//Fecha de expiración
	private static final int EXPIRATION = 365;

	//Algoritmo de firma a usar
	private static final String ALGORITHM = "SHA1withRSA";

	private KeyPairGenerator rsa;

	private KeyStore keyStore;


	public X509Certificate generarCertificadoDesdePKCS10(PKCS10 pkcs10) throws Exception{

		X509Certificate certificado = (X509Certificate) keyStore.getCertificate("ca");

		PrivateKey cast = (PrivateKey) keyStore.getKey("ca","password".toCharArray());

		System.out.println(certificado.toString());

		return convertPKCS10toX509Cert(pkcs10,certificado.getSubjectDN().getName(),cast);

	}

	public void generarCertificadoAutofirmado (){
		try {
			rsa=KeyPairGenerator.getInstance("RSA");
			rsa.initialize(KEY_LEN);
			KeyPair kp = rsa.generateKeyPair();
			String subject = "CN=AutoridadCertificadora,O=UOC,OU=EIMT,L=BCN,ST=LAPOBLACITYBIACH,C=ES";
			X509Certificate cert = generateCertificate(subject, kp.getPublic(), subject, kp.getPrivate());
			FileOutputStream certFile = new FileOutputStream("certificadoAutofirmado.crt");
			certFile.write(cert.getEncoded());
			certFile.close();
			X509Certificate[] miCertificado = new X509Certificate[1];
			miCertificado[0]=cert;
			keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(null, null);
			String nombre = "ca";
			String password= "password";
			keyStore.setKeyEntry(nombre, kp.getPrivate(), password.toCharArray(), miCertificado);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void generarCertificadoAutoinstalable(DatosCliente cliente) throws Exception {


		X509Certificate certificado = (X509Certificate) keyStore.getCertificate("ca");
		PrivateKey cast = (PrivateKey) keyStore.getKey("ca","password".toCharArray());
		String nombre= cliente.getEmail();
		byte[]  clave = cliente.getKeygen();


		try {


			JcaSignedPublicKeyAndChallenge llave_verdad = new   JcaSignedPublicKeyAndChallenge(Base64.decode(clave));
			PublicKeyAndChallenge llave_der = llave_verdad.getPublicKeyAndChallenge();
			System.out.println(llave_der.getSubjectPublicKeyInfo()+"   "+ llave_der.getChallenge());

			SubjectPublicKeyInfo sujeto = llave_der.getSubjectPublicKeyInfo();

			PublicKey publicaCliente = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(sujeto.getEncoded()));


			System.out.println(publicaCliente);
			X509Certificate cert =generateCertificate("email="+nombre,publicaCliente,certificado.getSubjectDN().getName(),cast);

			//System.out.println("CLAVE DESPUES: " + clave);
			FileOutputStream certFile = new FileOutputStream("/tmp/certificadoAutoinstall.crt");
			certFile.write(cert.getEncoded());
			certFile.close();


		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Error en la creacion del certificado");

		}
		

	}

	public void generarCertificadoCliente (String email, DatosCliente cliente, String rutaDescarga){
		try {
			rsa=KeyPairGenerator.getInstance("RSA");
			String passwordCliente = cliente.getPassword();
			System.out.println(cliente.getTamanyoClave());
			rsa.initialize(Integer.parseInt(cliente.getTamanyoClave()));
			KeyPair kp = rsa.generateKeyPair();
			//X500Name x500name = new X500Name("email="+email);
			X509Certificate certificado = (X509Certificate) keyStore.getCertificate("ca");
			PrivateKey cast = (PrivateKey) keyStore.getKey("ca","password".toCharArray());
			X509Certificate cert=generateCertificate("email="+email,kp.getPublic(),certificado.getSubjectDN().getName(), cast);
			generarPKCS12(kp.getPrivate(),passwordCliente,certificado,cert, rutaDescarga);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
	private void generarPKCS12(PrivateKey key,String password,X509Certificate emisor,X509Certificate receptor, String rutaGuardar){

		String alias="alias";
		try {
			X509Certificate[] chain = new X509Certificate[2];
			chain[1]=emisor;
			chain[0]=receptor;
			keyStore.setKeyEntry(alias, key,password.toCharArray() ,chain);
			FileOutputStream guardarPKCS12 = new FileOutputStream(rutaGuardar+"/cliente.p12");
			keyStore.store(guardarPKCS12, password.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/** Genera un certificado autofirmado
	 *
	 * @param subName Nombre del propietario.
	 * @param pubKey Clave pública del propietario.
	 * @param issName Nombre del emisor..
	 * @param issKey Clave privada del emisor, para firmar el certificado.
	 * @return Certificado X.509.
	 * @throws Exception Error.
	 */
	private X509Certificate generateCertificate(String subName, PublicKey pubKey, String issName, PrivateKey issKey) throws Exception {

		//Todo certificado tiene un número de serie único
		BigInteger sn = new BigInteger(64, new SecureRandom());

		//Calcular fecha de expiración
		Date from = new Date();
		Date to = new Date(from.getTime() + EXPIRATION * 86400000l);
		CertificateValidity interval = new CertificateValidity(from, to);

		//Se generan las identidades de propietario y emisor
		X500Name owner = new X500Name(subName);
		X500Name issuer = new X500Name(issName);

		//Se genera la información del certificado
		X509CertInfo info = new X509CertInfo();
		info.set(X509CertInfo.VALIDITY, interval);
		info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
		//info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
		//info.set(X509CertInfo.ISSUER, new CertificateIssuerName(issuer));
		info.set(X509CertInfo.SUBJECT, owner);
		info.set(X509CertInfo.ISSUER, issuer);
		info.set(X509CertInfo.KEY, new CertificateX509Key(pubKey));
		info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V1));
		AlgorithmId algo = new AlgorithmId(AlgorithmId.sha1WithRSAEncryption_oid);
		info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));


		//Se firma el certificado
		X509CertImpl cert = new X509CertImpl(info);
		cert.sign(issKey, ALGORITHM);

		//Se actualiza el campo del algoritmo y se vuelve a firmar
		algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
		info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
		cert = new X509CertImpl(info);
		cert.sign(issKey, ALGORITHM);
		return cert;
	}

	/** Genera un certificado x509 de a partir de un objeto pkcs10
	 *
	 * @param pkcs10 Objecto request
	 * @param issName Nombre del emisor
	 * @param issKey Clave privada del emisor, para firmar el certificado.
	 * @return Certificado X.509.
	 * @throws Exception Error.
	 */
	private X509Certificate convertPKCS10toX509Cert(PKCS10 pkcs10,String issName,PrivateKey issKey) throws Exception {

		//Todo certificado tiene un número de serie único
		BigInteger sn = new BigInteger(64, new SecureRandom());

		//Calcular fecha de expiración
		Date from = new Date();
		Date to = new Date(from.getTime() + EXPIRATION * 86400000l);
		CertificateValidity interval = new CertificateValidity(from, to);

		//Se generan las identidades de propietario y emisor
		X500Name owner = new X500Name(pkcs10.getSubjectName().toString());
		X500Name issuer = new X500Name(issName);

		//Se genera la información del certificado
		X509CertInfo info = new X509CertInfo();
		info.set(X509CertInfo.VALIDITY, interval);
		info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
		//info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
		//info.set(X509CertInfo.ISSUER, new CertificateIssuerName(issuer));
		info.set(X509CertInfo.SUBJECT, owner);
		info.set(X509CertInfo.ISSUER, issuer);
		info.set(X509CertInfo.KEY, new CertificateX509Key(pkcs10.getSubjectPublicKeyInfo()));
		info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
		AlgorithmId algo = new AlgorithmId(AlgorithmId.sha1WithRSAEncryption_oid);
		info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));


		//Se firma el certificado
		X509CertImpl cert = new X509CertImpl(info);
		cert.sign(issKey, ALGORITHM);

		//Se actualiza el campo del algoritmo y se vuelve a firmar
		algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
		info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
		cert = new X509CertImpl(info);
		cert.sign(issKey, ALGORITHM);
		return cert;
	}
}
