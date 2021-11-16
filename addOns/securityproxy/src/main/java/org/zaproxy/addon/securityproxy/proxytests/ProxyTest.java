package org.zaproxy.addon.securityproxy.proxytests;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.securityproxy.ExtensionSecurityProxy;
import org.zaproxy.addon.securityproxy.SecurityProxyListener;

/**
 * An abstract class represents the test that user want to apply to
 * every requests that are captured by ZAP Proxy
 */
public abstract class ProxyTest {

    protected SecurityProxyListener listener;

    /**
     * Create an ProxyTest
     * @param listener each ProxyTest request a ProxyListener to pass on the requests
     */
    public ProxyTest(SecurityProxyListener listener) {
        this.listener = listener;
    }

    /**
     * Determine whether the request is safe with the respect too each test
     * @param msg the http request from the user
     * @return whether the request is safe
     */
    public abstract boolean isSafe(HttpMessage msg);

    /**
     * Since an abstract class can have many implementations
     * each of the test requires a different name
     * @return the name of the test
     */
    public abstract String getTestName();

    /**
     * When isSage return false (the request fails the test), a warning page
     * will be given to the user.
     * @param args appropriate arguments depending on each test
     * @return a html warning page in String
     */
    public abstract String getWarningPage(String... args);
}
