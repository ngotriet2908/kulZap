package org.zaproxy.addon.securityproxy.proxytests;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.securityproxy.ExtensionSecurityProxy;
import org.zaproxy.addon.securityproxy.SecurityProxyListener;

public abstract class ProxyTest {
    protected SecurityProxyListener listener;

    public ProxyTest(SecurityProxyListener listener) {
        this.listener = listener;
    }

    public abstract boolean isSafe(HttpMessage msg);
    public abstract String getTestName();
    public abstract String getWarningPage(String... args);
}
