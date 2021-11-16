package org.zaproxy.addon.securityproxy.proxytests.constraints;

import org.zaproxy.addon.securityproxy.proxytests.TypoSquattingTest;

/**
 *An interface which has a method to check if one string is considered a typo of another.
 */
public interface TypoSquattingConstraint {

    /**
     * Checks if the typo string is a typo of the original string according to a specific rule defined in the implementation.
     * @param original The string to be checked against.
     * @param typo The potential typo.
     * @return Whether the typo string is a typo of the original string.
     */
    public abstract boolean passedConstraint(String original, String typo);
}
