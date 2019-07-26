package com.seguridad.CA.SeguridadInformatica.modelo;

import javax.servlet.ServletContext;

import org.springframework.http.MediaType;
 
public class MediaTypeUtils {
 
    // abc.zip
    // abc.pdf,..
    public static MediaType getMediaTypeForFileName(ServletContext servletContext, String fileName) {
        // application/pdf
        // application/xml
        // image/gif, ...
        String mineType = "application/x-x509-user-cert";
        try {
            MediaType mediaType = MediaType.parseMediaType(mineType);
            return mediaType;
        } catch (Exception e) {
            return MediaType.APPLICATION_OCTET_STREAM;
        }
    }
     
}