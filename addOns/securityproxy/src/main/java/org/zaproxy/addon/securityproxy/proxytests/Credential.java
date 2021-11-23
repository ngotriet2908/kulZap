package org.zaproxy.addon.securityproxy.proxytests;

import org.zaproxy.addon.securityproxy.ExtensionSecurityProxy;
import org.zaproxy.addon.securityproxy.SecurityProxyListener;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class Credential implements Serializable {
    private String username;
    private String salt;
    private String hashPassword;
    private List<String> safeHostnames;

    static final long serialVersionUID = 43L;

    public Credential(String username, String password) {
        this.username = username;

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        this.salt = new String(salt);

        this.hashPassword = this.hash(password);
        this.safeHostnames = new ArrayList<>();
    }

    public String hash(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(this.salt.getBytes(StandardCharsets.UTF_8));
            byte[] hashedPassword = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return new String(hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return ExtensionSecurityProxy.NULL;
    }

    public String getUsername() {
        return username;
    }

    public String getSalt() {
        return salt;
    }

    public String getHashPassword() {
        return hashPassword;
    }

    public List<String> getSafeHostnames() {
        return safeHostnames;
    }

    @Override
    public String toString() {
        return "Credential{" +
                "username='" + username + '\'' +
                ", salt='" + salt + '\'' +
                ", hashPassword='" + hashPassword + '\'' +
                ", safeHostnames=" + safeHostnames +
                '}';
    }
}
