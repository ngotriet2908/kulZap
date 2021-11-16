package org.zaproxy.addon.securityproxy.proxytests.constraints;

import org.zaproxy.addon.securityproxy.proxytests.TypoSquattingTest;

/**
 * A constraint to check if a typo where one character is missing was made.
 */
public class MissingCharacterConstraint implements TypoSquattingConstraint{

    /**
     * @param original The string to be checked against.
     * @param typo     The potential typo.
     * @return true if there is a single character removed from the typo string compared to the original string
     */
    @Override
    public boolean passedConstraint(String original, String typo) {
        int n=original.length();
        if (! (typo.length()+1==n)) return false;
        int skip = 0;
        for (int i = 0; i < n; i++) {
            if (skip==0 && i==n-1) return true;
            if (!(original.charAt(i)==typo.charAt(i-skip))) {
                skip+=1;
                if (skip>1) return false;
            }
        }
        return true;
    }
}
