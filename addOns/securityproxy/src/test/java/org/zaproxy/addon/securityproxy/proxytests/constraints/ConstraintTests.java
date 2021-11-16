package org.zaproxy.addon.securityproxy.proxytests.constraints;


import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.ValueSource;

public class ConstraintTests {
    @org.junit.jupiter.params.ParameterizedTest
    @ValueSource(strings = {"abxde","xbcde","abcdx"})
    void ReplacedCharacterTrueTest(String typo) {
        String original = "abcde";
        TypoSquattingConstraint constraint = new ReplacedCharacterConstraint();
        Assertions.assertTrue(constraint.passedConstraint(original,typo));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @ValueSource(strings = {"something_else","xbcdx","acbde"})
    void ReplacedCharacterFalseTest(String typo) {
        String original = "abcde";
        TypoSquattingConstraint constraint = new ReplacedCharacterConstraint();
        Assertions.assertFalse(constraint.passedConstraint(original,typo));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @ValueSource(strings = {"bcde","abde","abcd"})
    void MissingCharacterTrueTest(String typo) {
        String original = "abcde";
        TypoSquattingConstraint constraint = new MissingCharacterConstraint();
        Assertions.assertTrue(constraint.passedConstraint(original,typo));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @ValueSource(strings = {"something_else","abcde","abxd"})
    void MissingCharacterFalseTest(String typo) {
        String original = "abcde";
        TypoSquattingConstraint constraint = new MissingCharacterConstraint();
        Assertions.assertFalse(constraint.passedConstraint(original,typo));
    }
    @org.junit.jupiter.params.ParameterizedTest
    @ValueSource(strings = {"aabcde","abcxde","abcdex"})
    void ExtraCharacterTrueTest(String typo) {
        String original = "abcde";
        TypoSquattingConstraint constraint = new ExtraCharacterConstraint();
        Assertions.assertTrue(constraint.passedConstraint(original,typo));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @ValueSource(strings = {"something_else","xabcdex","abcxd"})
    void ExtraCharacterFalseTest(String typo) {
        String original = "abcde";
        TypoSquattingConstraint constraint = new ExtraCharacterConstraint();
        Assertions.assertFalse(constraint.passedConstraint(original,typo));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @ValueSource(strings = {"bacde","acbde","abced"})
    void AdjSwappedCharacterTrueTest(String typo) {
        String original = "abcde";
        TypoSquattingConstraint constraint = new AdjSwappedCharacterConstraint();
        Assertions.assertTrue(constraint.passedConstraint(original,typo));
        //Assertions.assertTrue(constraint.passedConstraint("www.youtube.com","www.google.com"));

    }

    @org.junit.jupiter.params.ParameterizedTest
    @ValueSource(strings = {"something_else","baced","baxde"})
    void AdjSwappedCharacterFalseTest(String typo) {
        String original = "abcde";
        TypoSquattingConstraint constraint = new AdjSwappedCharacterConstraint();
        Assertions.assertFalse(constraint.passedConstraint(original,typo));
    }
}
