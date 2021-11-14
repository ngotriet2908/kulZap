package org.zaproxy.addon.simpleexample.tests;

import org.zaproxy.addon.simpleexample.ExtensionSimpleExample;

public class ExtraCharacterTest extends MissingOrExtraCharTest{
    public ExtraCharacterTest(ExtensionSimpleExample extension) {
        super(extension);
    }

    @Override
    public boolean isTypoOf(String original, String typo) {
        return hasMissingChar(typo, original);
    }
}
