package org.zaproxy.addon.securityproxy.proxytests.constraints;

import org.zaproxy.addon.securityproxy.proxytests.TypoSquattingTest;

public interface TypoSquattingConstraint {

    public abstract boolean passedConstraint(String original, String typo);
}
