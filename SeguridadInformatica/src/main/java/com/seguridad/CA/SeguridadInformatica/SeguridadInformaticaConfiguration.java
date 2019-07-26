package com.seguridad.CA.SeguridadInformatica;

import javax.sql.DataSource;


import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.seguridad.CA.SeguridadInformatica.modelo.CertificadosAseado;
import com.seguridad.CA.SeguridadInformatica.modelo.Redireccion;

@Configuration
public class SeguridadInformaticaConfiguration {

	@Bean
	public Redireccion redireccion(){
		return new Redireccion();
	}
	
	@Bean
	public CertificadosAseado certificadosAseado(){
		CertificadosAseado cert = new CertificadosAseado();
		cert.generarCertificadoAutofirmado();
		return cert;
		
	}
	
	/*@Bean
	@ConfigurationProperties(prefix = "spring.datasource")
	public DataSource dataSource() {
		return DataSourceBuilder.create().build();
	}
	*/
	
}
