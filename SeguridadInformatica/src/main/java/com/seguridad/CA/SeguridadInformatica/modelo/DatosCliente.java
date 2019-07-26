package com.seguridad.CA.SeguridadInformatica.modelo;

public class DatosCliente {

	private String email;
	private String password;
	private byte[] keygen;
	private boolean pkcs10 = false;
	private String tamanyoClave;
	
	
	public String getTamanyoClave() {
		return tamanyoClave;
	}

	public void setTamanyoClave(String tamanyoClave) {
		this.tamanyoClave = tamanyoClave;
	}

	public boolean isPkcs10() {
		return pkcs10;
	}

	public void setPkcs10(boolean pkcs10) {
		this.pkcs10 = pkcs10;
	}

	public byte[] getKeygen() {
		return keygen;
	}

	public void setKeygen(byte[] keygen) {
		this.keygen = keygen;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getEmail(){
		return email;
	}
	
	@Override
	public String toString(){
		return ""+email;
	}
	
	public String getPassword(){
		return password;
	}
	
	public void setPassword(String password){
		this.password=password;
	}
	
}
