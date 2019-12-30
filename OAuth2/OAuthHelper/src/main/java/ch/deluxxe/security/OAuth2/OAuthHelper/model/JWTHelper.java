package ch.deluxxe.security.OAuth2.OAuthHelper.model;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

public class JWTHelper {
	
	// Example Key --> Needs to be replaced in production!!! Generate with https://gist.github.com/destan/b708d11bd4f403506d6d5bb5fe6a82c5
	private final String PRIVATE_KEY = "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";
	JSONObject header = new JSONObject();

	
	
	
	public JWTHelper() {
		header.put("typ", "JWT");
	}
	
	public static JSONObject payload(int ttl, String sub, String jti) {
		ZonedDateTime dtnow = ZonedDateTime.now();
		long now = dtnow.toEpochSecond();
		
		
		JSONObject payload = new JSONObject();
		payload.put("iss", "deluxxe.ch");
		payload.put("sub", sub); //User ID
		payload.put("aud", "deluxxe.ch");
		payload.put("jti", jti);
		payload.put("exp", now + ttl);
		payload.put("nbf", now);
		payload.put("iat", now);
		return payload;
	}
	
	
	public String getTokenRSA(JSONObject payload) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		header.put("alg", "RS256");
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PRIVATE_KEY));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		Cipher encryptCipher = Cipher.getInstance("RSA");
		encryptCipher.init(Cipher.ENCRYPT_MODE, kf.generatePrivate(keySpec));
		StringBuilder token = new StringBuilder();
		token.append(Base64.getUrlEncoder().encodeToString(header.toString().getBytes(StandardCharsets.UTF_8)));
		token.append(".");
		token.append(Base64.getUrlEncoder().encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8)));
		byte[] encodedhash = digest.digest(token.toString().getBytes(StandardCharsets.UTF_8));
		System.out.println(Base64.getUrlEncoder().encodeToString(encodedhash));
		token.append(".");
		token.append(Base64.getUrlEncoder().encodeToString(encryptCipher.doFinal(encodedhash)));
		return token.toString();
	}
	
	public String getTokenHMAC(JSONObject payload, String secret) throws NoSuchAlgorithmException, InvalidKeyException {
		header.put("alg", "HS256");
		StringBuilder token = new StringBuilder();
		token.append(Base64.getUrlEncoder().encodeToString(header.toString().getBytes(StandardCharsets.UTF_8)).replace("=", ""));
		token.append(".");
		token.append(Base64.getUrlEncoder().encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8)).replace("=", ""));
		Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
		sha256_HMAC.init(secret_key);
		
		String hash = Base64.getUrlEncoder().encodeToString(sha256_HMAC.doFinal(token.toString().getBytes(StandardCharsets.UTF_8))).replace("=", "");
		System.out.println(hash);
		token.append(".");
		token.append(hash);
		
		return token.toString();
	}
	
	public String getJTI(String code) {
		return null;
	}
	
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException {
		JWTHelper jwt = new JWTHelper();
		JSONObject payload = JWTHelper.payload(120, "Someone", "Jibbyydfad6576f4-yyy");
		System.out.println(jwt.getTokenHMAC(payload,"SuperSecret"));
		System.out.println(UUID.randomUUID());
	}

}
