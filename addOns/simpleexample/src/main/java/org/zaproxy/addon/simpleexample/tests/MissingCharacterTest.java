package org.zaproxy.addon.simpleexample.tests;

import org.zaproxy.addon.simpleexample.ExtensionSimpleExample;

public class MissingCharacterTest extends MissingOrExtraCharTest{
    public MissingCharacterTest(ExtensionSimpleExample extension) {
        super(extension);
    }

    @Override
    public boolean isTypoOf(String original, String typo) {
        return hasMissingChar(original, typo);
    }
}
