package my.hebuc.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import sun.misc.BASE64Decoder;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

public class JWTDemoRS256 {

    private static String privateKey = "-----BEGIN PRIVATE KEY-----" +
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDtdw9T3qw2XNrq" +
            "RYTHc82FbWlODqLgDjrpAfB4NBL6qlSCd9yBmMmolpEOVGNm2HDY53SyAwZ8UlDv" +
            "UrPgeDjYCsoUxk8nYsyxd+zeCkNdWOcCHKcBlw8p4BbkVAZ8oH51vzZksBB7zmvd" +
            "c2pArx3KNHkvufcQv3SUtutqJo091lpSnXCcMUpT3X7hV55hXEmb6doOt/QAUeVl" +
            "BxewsSa5Zu76caoFqh5x1Up4lz91z0McvUDjT50hP6K3Ee1clrBLtExbYFs0eEuD" +
            "PKb+YABMV9da9EAC4JT6a62ciR/jrHBdcdrtYQ88vKrsd1lLeLZ0z2znVSQj5X+J" +
            "Q6PAKV7lAgMBAAECggEBALJEMhaFUIUTGijK/Y356mzjIS2/IRjQtfrcQNkMRr81" +
            "BXJYZwpHWAQe3FCEm4bGr5i10U4dpU3JQgcX7/9wYUQWfXQxF5T6v63u2Lwrujym" +
            "k+1q8xjnfTOzjZvlVGVU2vqsDDp0TjuTUDiT/00F6Xg2AlAI7Gf/Qpat53bt8BRd" +
            "l4IXVbk3gh3hxNXE/HJ4OheHf8DQ4szZ59egI8texx7ny4vttIUfGIveC36ljsPG" +
            "eid+pe28KnScJ+SYkujrh13rBZwLXkGvVN7O+VXRwQesaZxnsyPhYpYGddgYixhv" +
            "GfHpITYSE+BvTvEjOWfYxE8NoJ7RTNdGBZJVzl3tWgECgYEA+cK5sT5Ooe2FNZHq" +
            "vvtEfNDQEiCFUS1ohJFlY5Yqt2m6OlxASq+DHITFfDtiCi7gcpUj2QPIhgIg2/g1" +
            "cj56MG+xvQS0afj1GWQlFJWMaZoG9DQbx4u6aEj0AI0hZQjtvJZMpQ6dPiKLo8zH" +
            "74nqwLQ91v9AsGvn1pmVBwPJS2UCgYEA82Wzng/4FrV9EK88Uv6FloC3M69mfU8c" +
            "s1a5owSxrrySKS4HKRJVdFUa4bYvhh6zAe414lZfNKGHXyM4n+MeWwXD0f5ER4pQ" +
            "dHf/WXsJraggIArZk3fD/XB82qIsnmcSwV0jD5E1FXIcl5+32aISxQi8AUqIdRw3" +
            "+YjPSneJTYECgYBRp3nyGn62reKpGuV2PsurStFbu8oaOhA7lxVgs42PnT9HKTXT" +
            "tQHWZwnxjbCFx8GVdHDd2EDMnxGDGOjQSuDDySCAvXMGWmA3RuhgjGv1cmfnmsmi" +
            "OWpeAcvUCk/qqjqfNzwjkl2SHNUuXhrXk21uRv8YtSa/Bugq3tc8Dd7XiQKBgQDo" +
            "bSsL+qXnUaI/Z4eMnZ8F7J6Fza5qZTy8CUo2YQooGczdZCXUU7yk3YxRFD/nrLM2" +
            "Wbq9C8vYn5N9B05QaHsZYrTveAbN5kgUIG8IjNTeLxmWX6YMC6duAphH0+wVy8n+" +
            "Oql7eSee9hxVsmDHg9y2qTOXbAxJAQx2zu1caDAGgQKBgDn+GTy/eGsnGRTpJIMz" +
            "CmKoaQnVJrt6kggkGdiDnP4mJDW4lUxYGgHt/3Uz9Y8RabZiIICk0uCLfdWvXtCq" +
            "am38/Ws4OvGPn3NR4Od3Flbgs511DlUv9gI2K73HFI6YCJhwIFsxOZTuKI+z/BqS" +
            "cuM8OOSPpjZEQloTP8O/lyO1" +
            "-----END PRIVATE KEY-----";



    public static String createJwtRs256(String aud, String sub)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        privateKey = privateKey.replace("-----BEGIN PRIVATE KEY-----", "");
        privateKey = privateKey.replace("-----END PRIVATE KEY-----", "");
        privateKey = privateKey.replaceAll("\\s+","");

        BASE64Decoder base64Decoder = new BASE64Decoder();
        byte[] encodedKey = base64Decoder.decodeBuffer(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);

        PrivateKey privKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);

        long nowMillis = System.currentTimeMillis();

        return Jwts.builder()
                .setSubject(sub)
                .setAudience(aud)
                .setExpiration(new Date(nowMillis))
                .setIssuedAt(new Date(nowMillis + 60000))
                .setId("testuserid")
                .signWith(SignatureAlgorithm.RS256, privKey)
                .compact();
    }

    public static Claims decodeJwtRs256(String jwt) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7XcPU96sNlza6kWEx3PN\n" +
                "hW1pTg6i4A466QHweDQS+qpUgnfcgZjJqJaRDlRjZthw2Od0sgMGfFJQ71Kz4Hg4\n" +
                "2ArKFMZPJ2LMsXfs3gpDXVjnAhynAZcPKeAW5FQGfKB+db82ZLAQe85r3XNqQK8d\n" +
                "yjR5L7n3EL90lLbraiaNPdZaUp1wnDFKU91+4VeeYVxJm+naDrf0AFHlZQcXsLEm\n" +
                "uWbu+nGqBaoecdVKeJc/dc9DHL1A40+dIT+itxHtXJawS7RMW2BbNHhLgzym/mAA\n" +
                "TFfXWvRAAuCU+mutnIkf46xwXXHa7WEPPLyq7HdZS3i2dM9s51UkI+V/iUOjwCle\n" +
                "5QIDAQAB\n" +
                "-----END PUBLIC KEY-----";

        publicKey = publicKey.replace("-----BEGIN PUBLIC KEY-----", "");
        publicKey = publicKey.replace("-----END PUBLIC KEY-----", "");
        publicKey = publicKey.replaceAll("\\s+","");

        byte[] publicKeyBytes = new BASE64Decoder().decodeBuffer(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

        return Jwts.parser()
                .setSigningKey(pubKey)
                .parseClaimsJws(jwt)
                .getBody();
    }
}