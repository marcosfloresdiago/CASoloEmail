package com.seguridad.CA.SeguridadInformatica.controller;

import java.io.File;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.tomcat.util.codec.binary.Base64;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.seguridad.CA.SeguridadInformatica.modelo.CertificadosAseado;
import com.seguridad.CA.SeguridadInformatica.modelo.DatosCliente;
import com.seguridad.CA.SeguridadInformatica.modelo.EnviarMail;
import com.seguridad.CA.SeguridadInformatica.modelo.MediaTypeUtils;
import com.seguridad.CA.SeguridadInformatica.modelo.Redireccion;

import sun.security.pkcs10.PKCS10;
import sun.security.x509.X500Name;

@Controller
@RequestMapping("/SeguridadInformatica")
public class RedireccionController {
	private Map<String, Redireccion> mapa = new HashMap<String, Redireccion>();
	private CertificadosAseado certificadosAseado;
	private EnviarMail envios = new EnviarMail();

	@Autowired
	public void setCertificadosAseado(CertificadosAseado certificadosAseado){
		this.certificadosAseado=certificadosAseado;
	}


	/*-----------------------Inicio de los mapas-----------------------------------*/

	@RequestMapping("/index2")
	public String goIndex(Model model) {
		return "index2.html";
	}

	@RequestMapping("/exito")
	public String goExito(Model model) {
		return "exito.html";
	}

	@RequestMapping("/exito2")
	public String goExito2(Model model) {
		return "exito2.html";
	}
	@RequestMapping("/fallo")
	public String goFallo(Model model) {
		return "fallo.html";
	}

	@RequestMapping("/validarCodigo")
	public String goValidarCodigo(Model model) {
		return "validarCodigo.html";
	}

	@RequestMapping("/autoinstalable")
	public String goAutoinstalable(Model model) {
		model.addAttribute("datos", new DatosCliente());
		return "autoinstalable";
	}

	@RequestMapping("/introducirDatosAutoInstalable") 
	public String goIntroducirEmailAutoInstalable(Model model) {
		model.addAttribute("datos", new DatosCliente());
		return "introducirDatosAutoInstalable";
	}


	@RequestMapping("/importarPKCS10") 
	public String goIntroducirPKCS10(Model model) {
		//model.addAttribute("datos", new DatosCliente());
		return "/importarPKCS10";
	}

	/*--------------------------------Fin de los mapas-----------------------------------*/



	/*----------------------------Inicio de coger  los diversos datos cliente-----------------------------------*/
	@RequestMapping(value="/introducirDatosAutoInstalable", method = RequestMethod.POST) 
	public String processEmailSubmitAutoInstalable(@ModelAttribute("datos") DatosCliente datos,
			@RequestParam("llaveGenerada") byte[] keygen,
			BindingResult bindingResult){

		System.out.println("CLAVE ANTES: "+keygen);
		if (bindingResult.hasErrors()){
			return "introducirDatosAutoInstalable";
		}

		datos.setKeygen(keygen);
		enviarEmailAutoinstalar(datos);
		return "infoMiraEmail";
	}




	@RequestMapping("/introducirDatos") 
	public String goIntroducirEmail(Model model) {
		model.addAttribute("datos", new DatosCliente());
		return "introducirDatos";
	}


	@RequestMapping(value="/introducirDatos", method = RequestMethod.POST) 
	public String processEmailSubmit(@ModelAttribute("datos") DatosCliente datos,
			@ModelAttribute("contrasenya") String contrasenya, @ModelAttribute("tamanyo") String tamanyo,
			BindingResult bindingResult){
		datos.setPassword(contrasenya);
		datos.setTamanyoClave(tamanyo);
		if (bindingResult.hasErrors()){
			return "introducirDatos";
		}
		enviarEmail(datos);
		return "infoMiraEmail";
	}


	@RequestMapping(value="/importarPKCS10", method = RequestMethod.POST) 
	public String processPKCS10Submit(@ModelAttribute("texto") String texto,
			BindingResult bindingResult) throws Exception{
		if (bindingResult.hasErrors()){
			return "/importarPKCS10";
		}
		
		DatosCliente datos = new DatosCliente();

		byte[] cadena = texto.getBytes();
		byte[] valueDecoded = Base64.decodeBase64(cadena);
		
		try{

			PKCS10 pkcs10 = new PKCS10 (valueDecoded);
			
			//Un split ya que lo coge todo
			String[] email = pkcs10.getSubjectName().toString().split("=");
			
			datos.setEmail(email[1]);
			datos.setPkcs10(true);
			System.out.println(email[1]);
			
			X509Certificate certificadoCliente=certificadosAseado.generarCertificadoDesdePKCS10(pkcs10);

			//Se crea el certificado
			FileOutputStream certFile = new FileOutputStream("/tmp/certificadoCliente.crt");
			certFile.write(certificadoCliente.getEncoded());
			certFile.close();

			enviarEmail(datos);
			return "/infoMiraEmail";
			
			
		}catch (Exception e) {
			
			return "/FalloImportar";
		}
		

	}

	/*----------------------------Fin de coger  los diversos datos cliente-----------------------------------*/



	/*----------------------------Inicio de enviar mail cliente-----------------------------------*/
	private void enviarEmail(DatosCliente datos){
		String email = datos.getEmail();
		System.out.println("\n\nSe envia el email ..."+email+"\n\n");
		Redireccion objeto = new Redireccion();
		objeto.setDatos(datos);
		mapa.put(objeto.getCodigoValidacion(), objeto);
		String url = "localhost:8080/SeguridadInformatica/descargar/"+objeto.getCodigoValidacion();
		System.out.println("\n\n"+url+"\n\n");
		envios.enviarMail(url, datos.getEmail());

	}

	private void enviarEmailAutoinstalar(DatosCliente datos){
		String email = datos.getEmail();
		System.out.println("\n\nSe envia el email ..."+email+"\n\n");
		Redireccion objeto = new Redireccion();
		objeto.setDatos(datos);
		mapa.put(objeto.getCodigoValidacion(), objeto);
		String url = "localhost:8080/SeguridadInformatica/autoinstalar/"+objeto.getCodigoValidacion();
		System.out.println("\n\n"+url+"\n\n");
		envios.enviarMail(url, datos.getEmail());
	}

	/*----------------------------Fin de enviar mail cliente-----------------------------------*/


	/*----------------------------Inicio de verificado mail e descarga de certificados-----------------------------------*/

	@RequestMapping(value="/descargar/{clave}")
	public String processUpdateSubmit(@PathVariable String clave) {
		Redireccion objeto = mapa.get(clave);
		String email = objeto.getDatos().getEmail();
		if(objeto != null){		
			if(objeto.isUtilizado() == false){
				Calendar ahora = Calendar.getInstance();
				ahora.setTime(new Date());
				if(objeto.getFechaCaducidad().compareTo(ahora) > 0){
					objeto.setUtilizado(true);
					if(objeto.getDatos().isPkcs10()){
						
						return "/exito2";
						
					}else{
						
						certificadosAseado.generarCertificadoCliente(email,objeto.getDatos(), "/tmp");
						return "/exito";
					}
				}
			}
		}
		return "/fallo"; 
	}



	@RequestMapping(value="/autoinstalar/{clave}")
	public String processAutoinstallSubmit(@PathVariable String clave) {
		Redireccion objeto = mapa.get(clave);
		String email = objeto.getDatos().getEmail();
		if(objeto != null){		
			if(objeto.isUtilizado() == false){
				Calendar ahora = Calendar.getInstance();
				ahora.setTime(new Date());
				if(objeto.getFechaCaducidad().compareTo(ahora) > 0){
					objeto.setUtilizado(true);;
					try {
						certificadosAseado.generarCertificadoAutoinstalable(objeto.getDatos());
					} catch (Exception e) {
						e.printStackTrace();
					}
					return "/exito3";
				}
			}
		}
		return "/fallo"; 
	}


	/*----------------------------Inicio del email verificado e descarga de certificados-----------------------------------*/


	/*----------------------------Inicio diversos tipos de Descargas de certificados----------------------------------*/


	private static final String DIRECTORY = "/tmp";

	@Autowired
	private ServletContext servletContext;
	@RequestMapping("/download1")
	public ResponseEntity<InputStreamResource> downloadFile1(
			@RequestParam(defaultValue = "cliente.p12") String fileName) throws IOException {

		MediaType mediaType = MediaTypeUtils.getMediaTypeForFileName(this.servletContext, fileName);
		System.out.println("fileName: " + fileName);
		System.out.println("mediaType: " + mediaType);

		File file = new File(DIRECTORY + "/" + fileName);
		InputStreamResource resource = new InputStreamResource(new FileInputStream(file));

		return ResponseEntity.ok()
				// Content-Disposition
				.header(HttpHeaders.CONTENT_DISPOSITION, "attachment;filename=" + file.getName())
				// Content-Type
				.contentType(mediaType)
				// Contet-Length
				.contentLength(file.length()) //
				.body(resource);
	}

	@RequestMapping("/download2")
	public ResponseEntity<InputStreamResource> downloadFile2(
			@RequestParam(defaultValue = "certificadoCliente.crt") String fileName) throws IOException {

		MediaType mediaType = MediaTypeUtils.getMediaTypeForFileName(this.servletContext, fileName);
		System.out.println("fileName: " + fileName);
		System.out.println("mediaType: " + mediaType);

		File file = new File(DIRECTORY + "/" + fileName);
		InputStreamResource resource = new InputStreamResource(new FileInputStream(file));

		return ResponseEntity.ok()
				// Content-Disposition
				.header(HttpHeaders.CONTENT_DISPOSITION, "attachment;filename=" + file.getName())
				// Content-Type
				.contentType(mediaType)
				// Contet-Length
				.contentLength(file.length()) //
				.body(resource);
	}

	@RequestMapping("/download3")
	public ResponseEntity<InputStreamResource> downloadFile3(
			@RequestParam(defaultValue = "certificadoAutoinstall.crt") String fileName) throws IOException {

		MediaType mediaType = MediaTypeUtils.getMediaTypeForFileName(this.servletContext, fileName);
		System.out.println("fileName: " + fileName);
		System.out.println("mediaType: " + mediaType);

		File file = new File(DIRECTORY + "/" + fileName);
		InputStreamResource resource = new InputStreamResource(new FileInputStream(file));


		return ResponseEntity.ok()
				// Content-Disposition
				// Content-Type
				.contentType(mediaType)
				// Contet-Length
				.contentLength(file.length()) //
				.body(resource);
	}



}
