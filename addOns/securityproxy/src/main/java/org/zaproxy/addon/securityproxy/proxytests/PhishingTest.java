package org.zaproxy.addon.securityproxy.proxytests;

import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.securityproxy.ExtensionSecurityProxy;
import org.zaproxy.addon.securityproxy.SecurityProxyListener;
import org.zaproxy.addon.securityproxy.proxytests.constraints.NumericPasswConstraint;
import org.zaproxy.addon.securityproxy.proxytests.constraints.PopularPasswConstraint;
import org.zaproxy.addon.securityproxy.proxytests.constraints.SafePasswordConstraint;
import org.zaproxy.addon.securityproxy.proxytests.constraints.CrackLibPasswConstraint;

import java.io.File;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Scanner;
import java.util.Map;
import java.util.stream.Collectors;

public class PhishingTest extends ProxyTest{

    private static final Logger LOGGER = LogManager.getLogger(TypoSquattingTest.class);
    private final List<SafePasswordConstraint> constraints;
    private static final String SAFE = "safe";
    private List<String> usernameFields;
    private List<String> passwordFields;
    private static final String PHISHING_HOST = "[PhishingHost]";
    private static final String CRE_USED_HOST = "[CreUsedHost]";
    private static final String REASON = "[Reason]";
    private static final String USERNAME = "[Username]";
    private static final String UUID = "[UUID]";
    private Map<String, HttpMessage> loginMessageMap;
    private List<CreHostCombi> ignorePasswordCheckList;

    public PhishingTest(SecurityProxyListener listener) {
        super(listener);
        this.constraints = List.of(
                new NumericPasswConstraint(),
                new PopularPasswConstraint(),
                new CrackLibPasswConstraint()
        );

        this.usernameFields = List.of(
                "username",
                "user",
                "uname"
        );

        this.passwordFields = List.of(
                "pass",
                "password",
                "pwd"
        );
        loginMessageMap = new HashMap<>();
        ignorePasswordCheckList = new ArrayList<>();
    }

    public boolean isPasswordSafe(String password) {
        return isPasswordSafeWithReason(password).equals(SAFE);
    }

    public String isPasswordSafeWithReason(String password) {
        String res = SAFE;

        for(SafePasswordConstraint constraint: this.constraints) {
            if (!constraint.passedConstraint(password)) {
                res = constraint.getReason();
                break;
            }
        }

        return res;
    }

    public boolean isLoginRequest(HttpMessage msg) {

        boolean hasUsername = false;
        boolean hasPassword = false;

        for (Iterator<HtmlParameter> it = msg.getFormParams().descendingIterator(); it.hasNext(); ) {
            HtmlParameter param = it.next();
            if (usernameFields.contains(param.getName())) {
                hasUsername = true;
            }
        }

        for (Iterator<HtmlParameter> it = msg.getFormParams().descendingIterator(); it.hasNext(); ) {
            HtmlParameter param = it.next();
            if (passwordFields.contains(param.getName())) {
                hasPassword = true;
            }
        }

        return hasPassword && hasUsername;
    }

    public String getUsername(HttpMessage msg) {
        for (Iterator<HtmlParameter> it = msg.getFormParams().descendingIterator(); it.hasNext(); ) {
            HtmlParameter param = it.next();
            if (usernameFields.contains(param.getName())) {
                return param.getValue();
            }
        }
        return ExtensionSecurityProxy.NULL;
    }

    public String getPassword(HttpMessage msg) {
        for (Iterator<HtmlParameter> it = msg.getFormParams().descendingIterator(); it.hasNext(); ) {
            HtmlParameter param = it.next();
            if (passwordFields.contains(param.getName())) {
                return param.getValue();
            }
        }
        return ExtensionSecurityProxy.NULL;
    }

    public String isSafeWithReason(HttpMessage msg) {
        List<Website> legitWebsites = getKnownWebsites();
        String username = getUsername(msg);
        String password = getPassword(msg);

        //If a host already contains username -> safe
        for(Website website: legitWebsites) {
            if (website.getHost().equals(sanitizeHostname(msg.getRequestHeader().getHostName()))) {
                for(Credential credential: website.getCredentials()) {
                    if (credential.getUsername().equals(username)) {
                        return SAFE;
                    }
                }
            }
        }

        //Check if other website contain combination
        for(Website website: legitWebsites) {
            for(Credential credential: website.getCredentials()) {
                if (
                        credential.getUsername().equals(username) &&
                        credential.getHashPassword().equals(credential.hash(password))
                ) {
                    return website.getHost();
                }
            }
        }

        return SAFE;
    }

    @Override
    public boolean isSafe(HttpMessage msg) {
        return isSafeWithReason(msg).equals(SAFE);
    }

    @Override
    public String getTestName() {
        return "Phishing test";
    }


    /**
     * @return a list of legitimate websites from storage
     */
    public List<Website> getKnownWebsites() {
        return this.listener.getExtension().getWebsites()
                .stream()
                .filter(website -> website.getDirectedWebsite() == null)
                .collect(Collectors.toList());
    }

    public String sanitizeHostname(String hostname) {
        return hostname
                .replace("www.", "")
                .replace("https://", "")
                .replace("http://", "");
    }

    public void addCredential(Credential credential, Website website) {
        for(Credential credential1: website.getCredentials()) {
            if (credential.getUsername().equals(credential1.getUsername())) {
                return;
            }
        }
        website.getCredentials().add(credential);
    }

    public void removeCredential(String username, Website website) {
        Credential credentialRM = null;
        for(Credential credential1: website.getCredentials()) {
            if (username.equals(credential1.getUsername())) {
                credentialRM = credential1;
                break;
            }
        }
        if (credentialRM != null) {
            website.getCredentials().remove(credentialRM);
        }
    }

    public Map<String, HttpMessage> getLoginMessageMap() {
        return loginMessageMap;
    }

    public List<CreHostCombi> getIgnorePasswordCheckList() {
        return ignorePasswordCheckList;
    }

    public boolean ignoreCombi(String host, String username) {
        for (CreHostCombi combi: ignorePasswordCheckList) {
            if (combi.getUsername().equals(username) && combi.getHost().equals(host)) {
                return true;
            }
        }
        return false;
    }

    public String getWeakPasswordPage(String... args) {
        String host = args[0];
        String reason = args[1];
        String username = args[2];

        try {
            File ff = new File(Constant.getZapHome(), ExtensionSecurityProxy.PASSWORD_HTML_TEMPLATE);
            Scanner myReader = new Scanner(ff);
            StringBuilder html_content = new StringBuilder();
            while (myReader.hasNextLine()) {
                html_content.append(myReader.nextLine()).append("\n");
            }
            myReader.close();

            return html_content.toString()
                    .replace(PHISHING_HOST, host)
                    .replace(USERNAME, username)
                    .replace(REASON, reason);

        } catch (Exception e) {
            LOGGER.log(Level.ERROR, e.getMessage());
        }
        return null;
    }

    @Override
    public String getWarningPage(String... args) {
        String phishingHost = args[0];
        String creUsedHost = args[1];
        String username = args[2];
        String uuid = args[3];

        try {
            File ff = new File(Constant.getZapHome(), ExtensionSecurityProxy.PHISHING_HTML_TEMPLATE);
            Scanner myReader = new Scanner(ff);
            StringBuilder html_content = new StringBuilder();
            while (myReader.hasNextLine()) {
                html_content.append(myReader.nextLine()).append("\n");
            }
            myReader.close();

            return html_content.toString()
                    .replace(PHISHING_HOST, phishingHost)
                    .replace(CRE_USED_HOST, creUsedHost)
                    .replace(USERNAME, username)
                    .replace(UUID, uuid);
        } catch (Exception e) {
            LOGGER.log(Level.ERROR, e.getMessage());
        }
        return null;
    }
}
