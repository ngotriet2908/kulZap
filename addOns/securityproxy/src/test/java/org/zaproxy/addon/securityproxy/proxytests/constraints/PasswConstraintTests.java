package org.zaproxy.addon.securityproxy.proxytests.constraints;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;

public class PasswConstraintTests {
    @ParameterizedTest
    @ValueSource(strings = {"123456","password","0"})
    void popPaswdFalseTest(String passw){
        SafePasswordConstraint constraint = new PopularPasswConstraint();
        Assertions.assertFalse(constraint.passedConstraint(passw));
    }

    @ParameterizedTest
    @ValueSource(strings = {"very_good_password_not_on_list"})
    void popPaswdTrueTest(String passw){
        SafePasswordConstraint constraint = new PopularPasswConstraint();
        Assertions.assertTrue(constraint.passedConstraint(passw));
    }

    @ParameterizedTest
    @ValueSource(strings = {"1238","8963"})
    void NumericPaswdFalseTest(String passw){
        SafePasswordConstraint constraint = new NumericPasswConstraint();
        Assertions.assertFalse(constraint.passedConstraint(passw));
    }

    @ParameterizedTest
    @ValueSource(strings = {"1a2","abc","5698%"})
    void NumericPaswdTrueTest(String passw){
        SafePasswordConstraint constraint = new NumericPasswConstraint();
        Assertions.assertTrue(constraint.passedConstraint(passw));
    }
}
