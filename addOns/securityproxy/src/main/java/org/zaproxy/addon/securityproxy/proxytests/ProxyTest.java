package org.zaproxy.addon.securityproxy.proxytests;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.securityproxy.ExtensionSecurityProxy;

public abstract class ProxyTest {
    protected ExtensionSecurityProxy proxy;

    public ProxyTest(ExtensionSecurityProxy proxy) {
        this.proxy = proxy;
    }

    public abstract boolean isSafe(HttpMessage msg);
    public abstract String getTestName();
    public abstract String getWarningPage();
}
