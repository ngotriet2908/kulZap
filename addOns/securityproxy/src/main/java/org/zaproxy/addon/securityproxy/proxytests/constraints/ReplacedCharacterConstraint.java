package org.zaproxy.addon.securityproxy.proxytests.constraints;

/**
 * A constraint to check if a typo where one character is replaced with another was made.
 */
public class ReplacedCharacterConstraint implements TypoSquattingConstraint{

    /**
     * @param original The string to be checked against.
     * @param typo     The potential typo.
     * @return true if exactly one character in the typo string differs from the original string.
     */
    @Override
    public boolean passedConstraint(String original, String typo) {
        int n=original.length();
        if (! (typo.length()==n)) return false;
        int nError = 0;
        for (int i = 0; i < n; i++) {
            if (!(original.charAt(i)==typo.charAt(i))) {
                nError +=1;
                if (nError >1) return false;
            }
        }
        return nError == 1;
    }
}
