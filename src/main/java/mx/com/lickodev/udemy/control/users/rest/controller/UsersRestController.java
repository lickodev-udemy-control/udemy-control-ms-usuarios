package mx.com.lickodev.udemy.control.users.rest.controller;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import mx.com.lickodev.udemy.control.commons.constants.CommonUtil;
import mx.com.lickodev.udemy.control.commons.exceptions.TokenException;
import mx.com.lickodev.udemy.control.users.rest.repository.UsersRepository;

@RequestMapping("users")
@RestController
public class UsersRestController {

	/**
	 * https://stackoverflow.com/questions/30595757/how-to-use-spring-el-in-value-when-using-constants-to-resolve-a-property
	 */
	@Value("${" + CommonUtil.JWT_PROPERTY_KEY + "}")
	private String jwtKey;

	@Autowired
	private UsersRepository usersRepository;

	@GetMapping("validate-token")
	public boolean isTokenValid(@RequestHeader(CommonUtil.HEADER_AUTHORIZATION) String authorizationHeader)
			throws TokenException {

		String token = authorizationHeader.replace(CommonUtil.BEARER_PREFIX, "").trim();

		/**
		 * https://www.baeldung.com/java-base64-encode-and-decode;
		 * https://newbedev.com/jwt-signature-does-not-match-locally-computed-signature
		 */
		Jws<Claims> claims = Jwts.parser().setSigningKey(Base64.getEncoder().encodeToString(jwtKey.getBytes()))
				.parseClaimsJws(token);

		Date dateToConvert = claims.getBody().getExpiration();

		LocalDateTime expirationLocalDateTimeToken = dateToConvert.toInstant().atZone(ZoneId.systemDefault())
				.toLocalDateTime();

		/**
		 * Si la hora actual esta despues de la fecha de expiracion quiere decir que el
		 * token ha expirado.
		 * 
		 * https://stackoverflow.com/questions/56181357/expiration-of-jwt-not-working-when-using-expiration-date-in-utc
		 */
		if (LocalDateTime.now().isAfter(expirationLocalDateTimeToken)) {
			throw new TokenException("token-expired");
		}

		String userName = claims.getBody().get(CommonUtil.JWT_CLAIM_USERNAME).toString();

		return usersRepository.existsByUserName(userName);
	}

}
