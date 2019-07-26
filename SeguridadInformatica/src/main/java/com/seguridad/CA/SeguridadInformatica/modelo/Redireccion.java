package com.seguridad.CA.SeguridadInformatica.modelo;

import java.util.Calendar;
import java.util.Date;


public class Redireccion {

	private Calendar fechaCreacion;
	private Calendar fechaCaducidad;
	private boolean utilizado;
	private String codigoValidacion; //si peta es por que era publico
	private DatosCliente datos;
	

	public Redireccion() {
		this.fechaCreacion = Calendar.getInstance();
		this.fechaCreacion.setTime(new Date());
		this.fechaCaducidad = fechaCreacion;
		this.fechaCaducidad.add(Calendar.HOUR_OF_DAY, 3);
		this.utilizado = false;
		this.codigoValidacion = generarClave(10);
	}

	public Calendar getFechaCreacion() {
		return fechaCreacion;
	}

	public void setFechaCreacion(Calendar fechaCreacion) {
		this.fechaCreacion = fechaCreacion;
	}

	public Calendar getFechaCaducidad() {
		return fechaCaducidad;
	}

	public void setFechaCaducidad(Calendar fechaCaducidad) {
		this.fechaCaducidad = fechaCaducidad;
	}

	public boolean isUtilizado() {
		return utilizado;
	}

	public void setUtilizado(boolean utilizado) {
		this.utilizado = utilizado;
	}

	public String getCodigoValidacion() {
		return codigoValidacion;
	}

	public void setCodigoValidacion(String codigoValidacion) {
		this.codigoValidacion = codigoValidacion;
	}
	
	private String generarClave(int tamanyo){
		String [] abecedario = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", 
				"K", "L", "M","N","O","P","Q","R","S","T","U","V","W", "X","Y","Z" };
		int numRandom;
		String clave = "";
		for(int i=0;i<tamanyo;i++){
			numRandom= (int) Math.round(Math.random() * 25 );
			clave += abecedario[numRandom];
		}
		return clave;
	}

	public DatosCliente getDatos() {
		return datos;
	}

	public void setDatos(DatosCliente datos) {
		this.datos = datos;
	}
	
	

}
