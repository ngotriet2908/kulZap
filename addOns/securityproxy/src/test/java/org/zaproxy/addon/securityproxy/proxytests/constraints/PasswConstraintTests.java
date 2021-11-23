package org.zaproxy.addon.securityproxy.proxytests.constraints;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class PasswConstraintTests {
    @ParameterizedTest
    @ValueSource(strings = {"123456","password","0"})
    public void popPaswdFalseTest(String passw){
        SafePasswordConstraint constraint = new PopularPasswConstraint();
        Assertions.assertFalse(constraint.passedConstraint(passw));
    }

    @ParameterizedTest
    @ValueSource(strings = {"very_good_password_not_on_list"})
    public void popPaswdTrueTest(String passw){
        SafePasswordConstraint constraint = new PopularPasswConstraint();
        Assertions.assertTrue(constraint.passedConstraint(passw));
    }

    @ParameterizedTest
    @ValueSource(strings = {"1238","8963"})
    public void NumericPaswdFalseTest(String passw){
        SafePasswordConstraint constraint = new NumericPasswConstraint();
        Assertions.assertFalse(constraint.passedConstraint(passw));
    }

    @ParameterizedTest
    @ValueSource(strings = {"1a2","abc","5698%"})
    public void NumericPaswdTrueTest(String passw){
        SafePasswordConstraint constraint = new NumericPasswConstraint();
        Assertions.assertTrue(constraint.passedConstraint(passw));
    }
    @ParameterizedTest
    @ValueSource(strings = {"1a2"})
    public void CrackLibFalseTest(String passw){
        SafePasswordConstraint constraint = new CrackLibPasswConstraint();
        Assertions.assertFalse(constraint.passedConstraint(passw));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Minhtriet2908@"})
    public void CrackLibTrueTest(String passw){
        SafePasswordConstraint constraint = new CrackLibPasswConstraint();
        Assertions.assertTrue(constraint.passedConstraint(passw));
    }
}
