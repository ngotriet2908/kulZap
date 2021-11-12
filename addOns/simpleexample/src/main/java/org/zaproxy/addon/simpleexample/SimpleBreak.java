package org.zaproxy.addon.simpleexample;

import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.brk.ExtensionBreak;

public class SimpleBreak implements ProxyListener {
    // Should be the last one before the listener that saves the HttpMessage to
    // the DB, this way the HttpMessage will be correctly shown to the user (to
    // edit it) because it could have been changed by other ProxyListener.
    public static final int PROXY_LISTENER_ORDER = ProxyListenerLog.PROXY_LISTENER_ORDER - 1;

    private ExtensionSimpleExample extension;

    public SimpleBreak(ExtensionSimpleExample extension) {
        /*
         * This is how you can pass in your extension, which you may well need to use
         * when you actually do anything of use.
         */
        this.extension = extension;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {

//        boolean isGood = false;
//        String ref = msg.getRequestHeader().getHeader("Referer");
//        if (ref != null) {
//            ref = ref.replace("https://","").replace("/","");
//            logToOutput("Request > Host: " + msg.getRequestHeader().getHostName() + ", isGood: " + isHostnameGood(ref) + ", Ref: " + ref);
//            isGood = isHostnameGood(ref);
//        } else {
//            logToOutput("Request > Host: " + msg.getRequestHeader().getHostName() + ", isGood: " + isGood(msg));
//            isGood =  isHostnameGood(msg.getRequestHeader().getHostName());
//        }

        return true;
    }



    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {


        return true;
    }

    @Override
    public int getArrangeableListenerOrder() {
        return PROXY_LISTENER_ORDER;
    }

    public void logToOutput(String msg) {
        if (View.isInitialised()) {
            // Running in daemon mode, shouldnt have been called
            View.getSingleton().getOutputPanel().append(msg + "\n");
            View.getSingleton().getOutputPanel().setTabFocus();
        }
    }

    public boolean isHostnameGood(String hostname) {
        return this.extension.getKnownUrlList().contains(hostname);
    }

    public boolean isGood(HttpMessage msg) {
        String hostName = msg.getRequestHeader().getHostName();
        return this.extension.getKnownUrlList().contains(hostName);
    }
}
