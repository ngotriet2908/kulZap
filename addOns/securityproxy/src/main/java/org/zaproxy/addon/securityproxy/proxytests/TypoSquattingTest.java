package org.zaproxy.addon.securityproxy.proxytests;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.securityproxy.ExtensionSecurityProxy;
import org.zaproxy.addon.securityproxy.proxytests.constraints.AdjSwappedCharacterConstraint;
import org.zaproxy.addon.securityproxy.proxytests.constraints.ExtraCharacterConstraint;
import org.zaproxy.addon.securityproxy.proxytests.constraints.MissingCharacterConstraint;
import org.zaproxy.addon.securityproxy.proxytests.constraints.ReplacedCharacterConstraint;
import org.zaproxy.addon.securityproxy.proxytests.constraints.TypoSquattingConstraint;

import java.util.List;

public class TypoSquattingTest extends ProxyTest{

    private final List<TypoSquattingConstraint> constraints;

    public TypoSquattingTest(ExtensionSecurityProxy proxy) {
        super(proxy);
        constraints = List.of(
                new AdjSwappedCharacterConstraint(),
                new ExtraCharacterConstraint(),
                new MissingCharacterConstraint(),
                new ReplacedCharacterConstraint()
        );
    }

    @Override
    public boolean isSafe(HttpMessage msg) {
        return isSafeWithReason(msg).equals("safe");
    }


    private String isSafeWithReason(HttpMessage msg) {
        String ref = msg.getRequestHeader().getHeader("Referer");
        String origin = msg.getRequestHeader().getHeader("Origin");
        String testHostName;

        if (origin != null) {
            testHostName = origin;
        } else if (ref != null) {
            testHostName = ref;
        } else {
            testHostName = msg.getRequestHeader().getHostName();
        }

        for(TypoSquattingConstraint constraint : constraints) {
            for(String knownHostName : super.proxy.getKnownUrlList())
                if (!constraint.passedConstraint(testHostName, knownHostName))
                    return knownHostName;
        }
        return "safe";
    }

    @Override
    public String getTestName() {
        return "Typosquatting";
    }

//    TODO add custom warning page for typosquatting
    @Override
    public String getWarningPage() {
        return null;
    }
}
