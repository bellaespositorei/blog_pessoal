package com.generation.blogpessoal.security;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;


// A Classe JwtService é responsável por criar e validar o Token JwT
// Tem todos os métodos de criação, validação e verificação do Token
/* Todo Service são classes de regra de negócio. 
 * Regras que a aplicação precisa fazer mas não necessariamente os usuários precisam saber
 * Então todo service tem funções responsáveis por validar as regras de negócio*/
@Component
public class JwtService {

	public static final String SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";

	//Codifica a SECRET e gera a Assinatura do Token JWT
	private Key getSignKey() {
		byte[] keyBytes = Decoders.BASE64.decode(SECRET);
		return Keys.hmacShaKeyFor(keyBytes);
	}

		//Retorna todas as claims(Informações), inseridas no Payload(corpo) do Token JWT
	private Claims extractAllClaims(String token) {
		return Jwts.parserBuilder()
				.setSigningKey(getSignKey()).build()
				.parseClaimsJws(token).getBody();
	}

	// Método genérico que serve para retornar uma Claim(informação) em específico
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}

	//Retorna dados da Claim sub, onde se encontra o usuário(e-mail)
	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	//Retorna os dados da Claim exp, onde se encontra a data e horário de expiração do token JWT
	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	//Método que verifica se o Token está expirado ou não
	private Boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	//Método que verifica se o Token pertence ao MESMO usuário que enviou o token
	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = extractUsername(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
	//Método que cria um Token válido para o usuário
	private String createToken(Map<String, Object> claims, String userName) {
		return Jwts.builder()
					.setClaims(claims)
					.setSubject(userName)
					.setIssuedAt(new Date(System.currentTimeMillis()))
					.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
					.signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
	}

	//Método responsável por criar um novo Token sempre que o anterior expirar ou o usuario logar
	public String generateToken(String userName) {
		Map<String, Object> claims = new HashMap<>();
		return createToken(claims, userName);
	}

}