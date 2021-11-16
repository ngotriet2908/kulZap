package org.zaproxy.addon.securityproxy.proxytests.constraints;

import org.zaproxy.addon.securityproxy.proxytests.TypoSquattingTest;

/**
 * A constraint to check if a typo where two adjacent characters are swapped was made.
 */
public class AdjSwappedCharacterConstraint implements TypoSquattingConstraint{

    /**
     * @param original The string to be checked against.
     * @param typo     The potential typo.
     * @return true if the typo string is identical to the original string except for exactly two adjacent characters being swapped.
     */
    @Override
    public boolean passedConstraint(String original, String typo) {
        int n=original.length();
        if (typo.length() != n) return false;
        int nError = 0;
        for (int i = 0; i < n-1; i++) {
            if (!(original.charAt(i)==typo.charAt(i))) {
                if (i==n-1) return false;
                if (original.charAt(i+1)==typo.charAt(i) && original.charAt(i)==typo.charAt(i+1)) {
                    nError+=1;
                    i+=1;
                    if (nError >1) return false;
                } else return false;
            }
        }
        return nError == 1;
    }

}
