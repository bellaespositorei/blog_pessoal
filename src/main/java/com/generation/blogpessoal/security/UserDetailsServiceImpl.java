package com.generation.blogpessoal.security;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.generation.blogpessoal.model.Usuario;
import com.generation.blogpessoal.repository.UsuarioRepository;


/* Classe que valida a existência de um usuário no Banco de Dados
 * e retornar um objeto da Classe UserDetailsImpl
 * Usa-se o Impl de Implementação para diferenciar as classes das Interfaces
 * O UserDetailsService já é uma interface do Spring
 * O nome UserDetailsServiceImpl é um nome de boas práticas pois implementa 
 a interface UserDetailsService
 
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
	
	@Autowired
	private UsuarioRepository usuarioRepository;

	@Override //Carregue o seu usuário pelo Username. Busca específica
	public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {

		Optional<Usuario> usuario = usuarioRepository.findByUsuario(userName);

		if (usuario.isPresent())
			return new UserDetailsImpl(usuario.get());
		else
			throw new ResponseStatusException(HttpStatus.FORBIDDEN);
			
	}
}