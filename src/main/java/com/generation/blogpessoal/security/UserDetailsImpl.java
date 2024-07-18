package com.generation.blogpessoal.security;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.generation.blogpessoal.model.Usuario;

/* Essa classe fornece infos básicas do Usuário para o Security
 Usa-se o Impl de Implementação para diferenciar as classes das Interfaces
 O UserDetails já é uma interface do Spring
 O nome UserDetailsImpl é um nome de boas práticas pois implementa a interface UserDetails */
public class UserDetailsImpl implements UserDetails {
	
	public static final long serialVersionUID = 1L;
	
	//Atributos
	private String userName;
	private String password;
	private List<GrantedAuthority> authorities; //Forma de garantir o que o usuário pode ou não fazer
	
	//Método Construtor
	public UserDetailsImpl (Usuario user) {
		this.userName = user.getUsuario();
		this.password = user.getSenha();
	}
	
	public UserDetailsImpl() {}
	
	//Comportamentos 
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities(){
		
		return authorities;
	}
	
	@Override
	public String getPassword() {
		
		return password;
	}
	
	@Override
	public String getUsername() {
		
		return userName;
	}
	
	@Override
	public boolean isAccountNonExpired() {
		
		return true;
	}
	
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}
	
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}
	
	@Override
	public boolean isEnabled() {
		return true;
	}
}
