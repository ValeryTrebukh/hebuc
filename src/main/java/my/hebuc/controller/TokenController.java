package my.hebuc.controller;

import my.hebuc.service.JWTDemoRS256;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.ModelMap;
import java.util.UUID;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/hebuc")
public class TokenController {

    private static final String CLIENT_ID = "mydhlplus";
    private static final String CLIENT_SECRET = "mydhlplussecret";
    private static final String REDIRECT_URI = "https://abc.dhl.com/content/dhl/us/en/auth/saml-login.htm";
    private static final String SCOPE = "dhl";

    private static Map<String, String> tokens = new HashMap<>();

    @GetMapping("/authorize")
    public ModelAndView authorize(@RequestParam(name="client_id") String client,
                                  @RequestParam(name="response_type") String type,
                                  @RequestParam(name="redirect_uri") String uri,
                                  @RequestParam(name="scope") String scope,
                                  @RequestParam(name="state") String state,
                                  @RequestParam(name="login") String login) {

        validateGetParams(client, type, uri, scope);

        String code = login.equals("500") || login.equals("502")
                ? storeToken(login)
                : storeToken(creteJwt(client, login));

        ModelMap model = new ModelMap();
        model.addAttribute("state", state);
        model.addAttribute("code", code);

        return new ModelAndView("redirect:" + uri, model);
    }

    private void validateGetParams(String client, String type, String uri, String scope) {
        if (!(client.equals(CLIENT_ID) && type.equals("code") && scope.equals(SCOPE) && uri.equals(REDIRECT_URI))) {
            throw new RuntimeException("parameters are invalid");
        }
    }

    private String creteJwt(String client, String login) {
        String jwt = null;
        try {
            jwt = JWTDemoRS256.createJwtRs256(client, login);
        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return jwt;
    }

    private String storeToken(String jwt) {
        String code = UUID.randomUUID().toString();
        tokens.put(code, jwt);
        return code;
    }

    @PostMapping("/token")
    public ResponseEntity<String> token(@ModelAttribute("code") String code,
                        @RequestParam(name="client_id") String client,
                        @RequestParam(name="client_secret") String secret,
                        @RequestParam(name="response_type") String type,
                        @RequestParam(name="redirect_uri") String uri) {

        validatePostParams(client, secret, uri, type);

        String token = tokens.remove(code);

        if(token.equals("502")) {
            try {
                Thread.sleep(60000);
            } catch (InterruptedException ignore) {}
        } else if (token.equals("500")) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(token, HttpStatus.OK);
    }

    private void validatePostParams(String client, String secret, String uri, String type) {
        if (!(client.equals(CLIENT_ID) && type.equals("authorization_code") && secret.equals(CLIENT_SECRET) && uri.equals(REDIRECT_URI))) {
            throw new RuntimeException("parameters are invalid");
        }
    }

}