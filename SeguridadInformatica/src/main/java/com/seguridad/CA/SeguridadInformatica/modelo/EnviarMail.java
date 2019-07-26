package com.seguridad.CA.SeguridadInformatica.modelo;

import java.security.Security;
import java.util.*;
import javax.mail.*;
import javax.mail.internet.*;

import com.sun.mail.smtp.SMTPTransport;

import javax.activation.*;

public class EnviarMail {

	public void enviarMail(String url, String destinatario) {     
		Security.addProvider(new com.sun.net.ssl.internal.ssl.Provider());
        final String SSL_FACTORY = "javax.net.ssl.SSLSocketFactory";

        // Get a Properties object
        Properties props = System.getProperties();
        props.setProperty("mail.smtps.host", "smtp.gmail.com");
        props.setProperty("mail.smtp.socketFactory.class", SSL_FACTORY);
        props.setProperty("mail.smtp.socketFactory.fallback", "false");
        props.setProperty("mail.smtp.port", "465");
        props.setProperty("mail.smtp.socketFactory.port", "465");
        props.setProperty("mail.smtps.auth", "true");

        /*
        If set to false, the QUIT command is sent and the connection is immediately closed. If set 
        to true (the default), causes the transport to wait for the response to the QUIT command.

        */
        props.put("mail.smtps.quitwait", "false");

        Session session = Session.getInstance(props, null);

        // -- Crear el mensaje a new message --
        final MimeMessage msg = new MimeMessage(session);

        try {
        // -- Setear desde quien se envia  --
        msg.setFrom(new InternetAddress( "emiliosegurocopiacomodo@gmail.com"));
        msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(destinatario, false));
        msg.setRecipients(Message.RecipientType.CC, InternetAddress.parse("", false));
      

        //Contenido del mensaje
        msg.setSubject("Certificado CopiaComodo ");
        msg.setText("Porfavor haga clik en el siguiente enlace para confirmar su correo electronico:\n\n" +url, "utf-8");
        msg.setSentDate(new Date());

        SMTPTransport t = (SMTPTransport)session.getTransport("smtps");

        t.connect("smtp.gmail.com", "emiliosegurocopiacomodo@gmail.com", "ManuelMollar");
        t.sendMessage(msg, msg.getAllRecipients());      
        t.close();
        }catch(Exception e) {
        	e.printStackTrace();
        	System.out.println("No se ha podido enviar el email.");
        }
    }
}