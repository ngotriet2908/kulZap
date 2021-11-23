package org.zaproxy.addon.securityproxy;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;

import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.securityproxy.proxytests.TypoSquattingTest;
import org.zaproxy.addon.securityproxy.proxytests.PhishingTest;
import org.zaproxy.addon.securityproxy.proxytests.Website;
import org.zaproxy.addon.securityproxy.proxytests.CreHostCombi;
import org.zaproxy.addon.securityproxy.proxytests.Credential;
import org.zaproxy.addon.securityproxy.proxytests.constraints.PopularPasswConstraint;

import java.util.Date;
import java.util.Locale;
import java.util.UUID;

/**
 * A custom proxy listener that process the requests from user and apply
 * security constraint such as TypoSquatting Prevention
 */
public class SecurityProxyListener implements ProxyListener {
    // Should be the last one before the listener that saves the HttpMessage to
    // the DB, this way the HttpMessage will be correctly shown to the user (to
    // edit it) because it could have been changed by other ProxyListener.
    public static final int PROXY_LISTENER_ORDER = ProxyListenerLog.PROXY_LISTENER_ORDER - 1;

    private static final String HTML_CONTENT_TYPE = "text/html";
    private static final String TYPO_LINK = "[TypoPage]";
    private static final String TYPO_HOST = "[TypoHost]";
    private static final String REDIRECT_HOST = "[RedirectHost]";
    private static final String IS_SAFE_HEADER = "ZAP-IS-SAFE";
    private static final String ADD_TO_LEGIT_HOST = "/zapgroup8addtolegithost";
    private static final String ADD_REDIRECT_HOST = "/zapgroup8addredirect";
    private static final String ADD_CREDENTIAL = "/zapgroup8addcredential";
    private static final String SUPPRESS_PASSWORD_WARNING = "/zapgroup8suppresspasswordwarning";

    private ExtensionSecurityProxy extension;
    private static final Logger LOGGER = LogManager.getLogger(SecurityProxyListener.class);

    private TypoSquattingTest typoSquattingTest;
    private PhishingTest phishingTest;

    public SecurityProxyListener(ExtensionSecurityProxy extension) {
        this.extension = extension;
        this.typoSquattingTest = new TypoSquattingTest(this);
        this.phishingTest = new PhishingTest(this);
    }

    /**
     * Remove user credential if the entered password is wrong
     * @param msg user request
     * @return always allow
     */
    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {

        if (
                typoSquattingTest.isSafe(msg) &&
                msg.getRequestHeader().getMethod().equals(HttpRequestHeader.POST) &&
                phishingTest.isLoginRequest(msg)
        ) {

            if (
                    !(msg.getResponseHeader().getStatusCode() == 302 ||
                    msg.getResponseHeader().getStatusCode() == 200 ||
                    msg.getResponseHeader().getStatusCode() == 301)
            ) {
                String username = phishingTest.getUsername(msg);

                Website safeWebsite = getWebsiteWithHostName(
                        phishingTest.sanitizeHostname(msg.getRequestHeader().getHostName())
                );

                if (safeWebsite != null) {
                    phishingTest.removeCredential(username, safeWebsite);
                    logToOutput("removed Credential with username: " + username);
                }
            }
        }
        return true;
    }

    /**
     * When a request is received, the method determine the following:
     * - If the hostname is in the saved Typo list (if yes, then extract the redirect host then redirect the user)
     * - If the user indicates in the request that they want to save a typo host as legitimate host -> then save the host to known Host list
     * - If the user indicates in the request that they want to save a typo host with the intended host as preference
     *      then save the preference and redirect the user in future requests
     * - If the page contains HTML  (usually when the user enter a link in the address bar)
     * -- if no violations found then allow the user to access the page
     * -- show the user a warning page telling them that they violate the Typo Squatting test
     * - For other requests, allow if the hostname pass the Tests
     * @param msg user requests
     * @return the unmodified request if the hostname is safe and modified in case of violated request
     */
    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {

        try {
            boolean passed = typoSquattingProcessing(msg);
            if (!passed) {
                return true;
            }

            if (msg.getRequestHeader().getURI().toString().contains(SUPPRESS_PASSWORD_WARNING)) {
                String paramsS = msg.getRequestHeader().getURI().toString()
                        .replace(SUPPRESS_PASSWORD_WARNING.toLowerCase(Locale.ROOT), "")
                        .replace("https://", "")
                        .replace("www.", "")
                        .replace("http://", "");
                String[] params = paramsS.split(";");
                String username = params[1];
                String host = params[0];

                phishingTest.getIgnorePasswordCheckList().add(new CreHostCombi(host, username));
                logToOutput("add ignore : " + host + "; " + username);

                //Add disregarded response
                msg.setResponseHeader(new HttpResponseHeader(
                        "HTTP/1.1 200 OK"
                                + HttpHeader.CRLF
                                + "Content-Type: text/html;charset=utf-8"
                                + HttpHeader.CRLF
                                + "Content-Language: en"));
                msg.setResponseBody(this.phishingTest.getWarningPage("a", "a", "a","a"));
                msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                msg.setTimeSentMillis(new Date().getTime());
                return true;
            }

            if (msg.getRequestHeader().getURI().toString().contains(ADD_CREDENTIAL)) {
                String paramsS = msg.getRequestHeader().getURI().toString()
                        .replace(ADD_REDIRECT_HOST.toLowerCase(Locale.ROOT), "")
                        .replace("https://", "")
                        .replace("www.", "")
                        .replace("http://", "");

                String[] params = paramsS.split(";");

                logToOutput("Add credential request: " + params[1]);
                HttpMessage phishingMessage = phishingTest.getLoginMessageMap().get(params[1]);
                Website website = getWebsiteWithHostName(
                        phishingTest.sanitizeHostname(phishingMessage.getRequestHeader().getHostName())
                );

                if (website != null) {
                    Credential credential = new Credential(
                            phishingTest.getUsername(phishingMessage),
                            phishingTest.getPassword(phishingMessage)
                    );
                    phishingTest.addCredential(credential, website);
                    logToOutput("adding credential for " + website.getHost());
                    logToOutput("added Credential " + credential);
                }


                //Add disregarded response
                msg.setResponseHeader(new HttpResponseHeader(
                        "HTTP/1.1 200 OK"
                                + HttpHeader.CRLF
                                + "Content-Type: text/html;charset=utf-8"
                                + HttpHeader.CRLF
                                + "Content-Language: en"));
                msg.setResponseBody(this.phishingTest.getWarningPage("a", "a", "a","a"));
                msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                msg.setTimeSentMillis(new Date().getTime());
                return true;
            }

            //Detect login
            if (
                    msg.getRequestHeader().getMethod().equals(HttpRequestHeader.POST)
                    && phishingTest.isLoginRequest(msg)
            ) {

                String username = phishingTest.getUsername(msg);
                String password = phishingTest.getPassword(msg);
                String sanitizedHostname = phishingTest.sanitizeHostname(msg.getRequestHeader().getHostName());

                logToOutput("username: " + username);
                logToOutput("password: " + password);
                logToOutput("isSafeWithR: " + phishingTest.isSafeWithReason(msg));

                if (phishingTest.isSafe(msg)) {

                    Website safeWebsite = getWebsiteWithHostName(
                            phishingTest.sanitizeHostname(msg.getRequestHeader().getHostName())
                    );

                    if (safeWebsite != null) {
                        if (extension.enablePasswordCheck) {
                            if (!(this.phishingTest.ignoreCombi(sanitizedHostname, username)
                                    || this.phishingTest.isPasswordSafe(password))) {
                                msg.setResponseHeader(new HttpResponseHeader(
                                        "HTTP/1.1 200 OK"
                                                + HttpHeader.CRLF
                                                + "Content-Type: text/html;charset=utf-8"
                                                + HttpHeader.CRLF
                                                + "Content-Language: en"));

                                msg.setResponseBody(this.phishingTest.getWeakPasswordPage(
                                        phishingTest.sanitizeHostname(msg.getRequestHeader().getHostName()),
                                        phishingTest.isPasswordSafeWithReason(password),
                                        username
                                        ));

                                msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                                msg.setTimeSentMillis(new Date().getTime());
                                return true;
                            }
                        }

                        Credential credential = new Credential(username, password);
                        safeWebsite.getCredentials().add(credential);

                        logToOutput("added Credential " + credential);
                    }

                } else {
                    String creUsedHost = phishingTest.isSafeWithReason(msg);
                    UUID uuid = UUID.randomUUID();

                    HttpMessage message = new HttpMessage(msg);

                    logToOutput("Add phishing request to map: " + uuid);
                    phishingTest.getLoginMessageMap().put(
                            uuid.toString(),
                            message
                    );

                    msg.setResponseHeader(new HttpResponseHeader(
                            "HTTP/1.1 200 OK"
                                    + HttpHeader.CRLF
                                    + "Content-Type: text/html;charset=utf-8"
                                    + HttpHeader.CRLF
                                    + "Content-Language: en"));

                    msg.setResponseBody(this.phishingTest.getWarningPage(
                            phishingTest.sanitizeHostname(msg.getRequestHeader().getHostName()),
                            creUsedHost,
                            username,
                            uuid.toString()
                    ));

                    msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                    msg.setTimeSentMillis(new Date().getTime());

                }
            }



        } catch (Exception e) {
            LOGGER.log(Level.ERROR, e.getMessage());
        }
        return true;
    }

    private boolean typoSquattingProcessing(HttpMessage msg) throws HttpMalformedHeaderException {
        boolean isGood = this.typoSquattingTest.isSafe(msg);
        String isGoodHostName = this.typoSquattingTest.extractSearchHost(msg);
        String contentType = msg.getRequestHeader().getHeader("Accept");
        contentType = (contentType == null) ? "null" : contentType;
        boolean containsHTML = contentType.contains(HTML_CONTENT_TYPE);
        String sanitizedHostName = msg.getRequestHeader().getHostName()
                .replace("https://", "")
                .replace("www.", "")
                .replace("http://", "");


//            Check if the hostname is in the saved Typo list (if yes, then extract the redirect host then redirect the user)
        if (!isGood) {
            for (Website web : this.typoSquattingTest.getTypoWebsites()) {
                if (web.getHost().equals(sanitizedHostName)) {
                    msg.setResponseHeader(new HttpResponseHeader(
                            "HTTP/1.1 200 OK"
                                    + HttpHeader.CRLF
                                    + "Content-Type: text/html;charset=utf-8"
                                    + HttpHeader.CRLF
                                    + "Content-Language: en"));
                    String html = this.getTypoSquattingTest().getRedirectPage();
                    msg.setResponseBody(html.replace(REDIRECT_HOST, "https://www." + web.getDirectedWebsite().getHost()));
                    msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                    msg.setTimeSentMillis(new Date().getTime());

                    return false;
                }
            }

        }

        logToOutput(
                "Request > isGood: " + isGood +
                        ", host: " + sanitizedHostName +
                        ", contains html: " + containsHTML +
                        ", ref: " + ((msg.getRequestHeader().getHeader("Referer") != null) ?
                        this.typoSquattingTest.uriStringToHostName(msg.getRequestHeader().getHeader("Referer")) : "null") +
                        ", origin: " + ((msg.getRequestHeader().getHeader("Origin") != null) ?
                        this.typoSquattingTest.uriStringToHostName(msg.getRequestHeader().getHeader("Origin")) : "null")
        );


        //  If request contains pre-made keywords ADD_TO_LEGIT_HOST (add the host to legit host) -> then save the host to known Host list
        if (msg.getRequestHeader().getURI().toString().contains(ADD_TO_LEGIT_HOST)) {
            String legitHost = msg.getRequestHeader().getURI().toString()
                    .replace(ADD_TO_LEGIT_HOST.toLowerCase(Locale.ROOT), "")
                    .replace("https://", "")
                    .replace("www.", "")
                    .replace("http://", "");

            if (this.typoSquattingTest.addKnownHost(legitHost)) {
                logToOutput("Operation > Add new KnownHost 1: " + legitHost);
            }

            msg.setResponseHeader(new HttpResponseHeader(
                    "HTTP/1.1 200 OK"
                            + HttpHeader.CRLF
                            + "Content-Type: text/html;charset=utf-8"
                            + HttpHeader.CRLF
                            + "Content-Language: en"));
            msg.setResponseBody(this.typoSquattingTest.getWarningPage("a", "a"));
            msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
            msg.setTimeSentMillis(new Date().getTime());

            return false;
        }

        //  If request contains pre-made keywords ADD_REDIRECT_HOST (add typo host with redirect host preference) -> then save the preference
        if (msg.getRequestHeader().getURI().toString().contains(ADD_REDIRECT_HOST)) {
            String params = msg.getRequestHeader().getURI().toString()
                    .replace(ADD_REDIRECT_HOST.toLowerCase(Locale.ROOT), "")
                    .replace("https://", "")
                    .replace("www.", "")
                    .replace("http://", "");

            String typoHost = params.split(";")[0]
                    .replace("https://", "")
                    .replace("www.", "")
                    .replace("http://", "");

            String originHost = params.split(";")[1]
                    .replace("https://", "")
                    .replace("www.", "")
                    .replace("http://", "");

            this.typoSquattingTest.addTypoHost(typoHost, this.typoSquattingTest.getKnownWebsite(originHost));
            logToOutput("Operation > Add Typo Redirect: " + typoHost + " -> " + originHost);

            msg.setResponseHeader(new HttpResponseHeader(
                    "HTTP/1.1 200 OK"
                            + HttpHeader.CRLF
                            + "Content-Type: text/html;charset=utf-8"
                            + HttpHeader.CRLF
                            + "Content-Language: en"));
            msg.setResponseBody(this.typoSquattingTest.getWarningPage("a", "a"));
            msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
            msg.setTimeSentMillis(new Date().getTime());

            return false;
        }

        // If the page contains HTML -> usually when the user enter a link in the address bar
        if (containsHTML) {

            // If the hostname is good and not a typo -> add the host to knownHost list
            if (isGood && !this.typoSquattingTest.isTypoWebsite(isGoodHostName)) {
                if (this.typoSquattingTest.addKnownHost(isGoodHostName)) {
                    logToOutput("Operation > Add new KnownHost 2: " + isGoodHostName);
                }
                return true;
            } else if (isGood) {
                return true;
            }


            // Otherwise, the host failed the typo test -> send the warning page
            String originalHost = this.typoSquattingTest.isSafeWithReason(msg);

            msg.setResponseHeader(new HttpResponseHeader(
                    "HTTP/1.1 200 OK"
                            + HttpHeader.CRLF
                            + "Content-Type: text/html;charset=utf-8"
                            + HttpHeader.CRLF
                            + "Content-Language: en"));

            msg.setResponseBody(this.typoSquattingTest.getWarningPage(
                    msg.getRequestHeader().getHostName(),
                    originalHost)
            );

            msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
            msg.setTimeSentMillis(new Date().getTime());

            return false;
        } else {
            return isGood;
        }
    }

    @Override
    public int getArrangeableListenerOrder() {
        return PROXY_LISTENER_ORDER;
    }

    /**
     * Log to output in ZAP application
     * @param msg user request
     */
    public void logToOutput(String msg) {
        if (View.isInitialised()) {
            // Running in daemon mode, shouldnt have been called
            View.getSingleton().getOutputPanel().append(msg + "\n");
            View.getSingleton().getOutputPanel().setTabFocus();
        }
    }

    public Website getWebsiteWithHostName(String hostname) {
        for(Website website: extension.getWebsites()) {
            if (website.getHost().equals(hostname)) {
                return website;
            }
        }
        return null;
    }


    /**
     * @return return the ZAP extension for usage
     */
    public ExtensionSecurityProxy getExtension() {
        return extension;
    }

    public TypoSquattingTest getTypoSquattingTest() {
        return typoSquattingTest;
    }
}
