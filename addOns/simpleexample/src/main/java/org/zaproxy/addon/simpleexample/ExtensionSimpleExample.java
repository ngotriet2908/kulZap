/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.simpleexample;

import java.awt.CardLayout;
import java.awt.Font;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import javax.swing.ImageIcon;
import javax.swing.JTextPane;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.brk.impl.http.ProxyListenerBreak;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.ZapMenuItem;

/**
 * An example ZAP extension which adds a top level menu item, a pop up menu item and a status panel.
 *
 * <p>{@link ExtensionAdaptor} classes are the main entry point for adding/loading functionalities
 * provided by the add-ons.
 *
 * @see #hook(ExtensionHook)
 */
public class ExtensionSimpleExample extends ExtensionAdaptor {

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionSimpleExample";

    // The i18n prefix, by default the package name - defined in one place to make it easier
    // to copy and change this example
    protected static final String PREFIX = "simpleExample";

    /**
     * Relative path (from add-on package) to load add-on resources.
     *
     * @see Class#getResource(String)
     */
    private static final String RESOURCES = "resources";

    private static final ImageIcon ICON =
            new ImageIcon(ExtensionSimpleExample.class.getResource(RESOURCES + "/cake.png"));

    private static final String EXAMPLE_FILE = "example/ExampleFile.txt";
    private static final String URL_FILE = "example/Known_URL.txt";

    private ZapMenuItem menuExample;
    private RightClickMsgMenu popupMsgMenuExample;
    private AbstractPanel statusPanel;
    private SimpleBreak breaker;

    private SimpleExampleAPI api;

    private List<String> knownUrlList;

    private static final Logger LOGGER = LogManager.getLogger(ExtensionSimpleExample.class);

    public ExtensionSimpleExample() {
        super(NAME);
        setI18nPrefix(PREFIX);
        breaker = new SimpleBreak(this);

    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        this.api = new SimpleExampleAPI();
        extensionHook.addApiImplementor(this.api);
        extensionHook.addProxyListener(this.breaker);

//        knownUrlList = new ArrayList<>();
        knownUrlList = new ArrayList<>(Arrays.asList("www.google.com"));

        createOrLoadUrlFile();

        // As long as we're not running as a daemon
        if (getView() != null) {
            extensionHook.getHookMenu().addToolsMenuItem(getMenuExample());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupMsgMenuExample());
            extensionHook.getHookView().addStatusPanel(getStatusPanel());
        }

    }

    @Override
    public boolean canUnload() {
        // The extension can be dynamically unloaded, all resources used/added can be freed/removed
        // from core.
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        // In this example it's not necessary to override the method, as there's nothing to unload
        // manually, the components added through the class ExtensionHook (in hook(ExtensionHook))
        // are automatically removed by the base unload() method.
        // If you use/add other components through other methods you might need to free/remove them
        // here (if the extension declares that can be unloaded, see above method).
    }

    private AbstractPanel getStatusPanel() {
        if (statusPanel == null) {
            statusPanel = new AbstractPanel();
            statusPanel.setLayout(new CardLayout());
            statusPanel.setName(Constant.messages.getString(PREFIX + ".panel.title"));
            statusPanel.setIcon(ICON);
            JTextPane pane = new JTextPane();
            pane.setEditable(false);
            // Obtain (and set) a font with the size defined in the options
            pane.setFont(FontUtils.getFont("Dialog", Font.PLAIN));
            pane.setContentType("text/html");
            pane.setText(Constant.messages.getString(PREFIX + ".panel.msg"));
            statusPanel.add(pane);
        }
        return statusPanel;
    }

    private ZapMenuItem getMenuExample() {
        if (menuExample == null) {
            menuExample = new ZapMenuItem(PREFIX + ".topmenu.tools.title");

            menuExample.addActionListener(
                    e -> {
                        // This is where you do what you want to do.
                        // In this case we'll just show a popup message.
                        exportToUrlFile();
                        View.getSingleton()
                                .showMessageDialog("Exported to url file");
                        // And display a file included with the add-on in the Output tab
                    });
        }
        return menuExample;
    }

    private void createOrLoadUrlFile() {

        this.breaker.logToOutput("Start CreateOrLoad url file");

        LOGGER.log(Level.INFO, "Start CreateOrLoad url file");

        try {
            File f = new File(Constant.getZapHome(), URL_FILE);
            if (f.createNewFile()) {
                LOGGER.log(Level.INFO,"URL file not exists, create URL file");
            } else {
                LOGGER.log(Level.INFO,"URL exists, loading url file");
            }

            Scanner myReader = new Scanner(f);
            while (myReader.hasNextLine()) {
                String data = myReader.nextLine();
                knownUrlList.add(data);
                LOGGER.log(Level.INFO,"Loaded: " + data);
            }
            myReader.close();

        } catch (Exception e) {
            this.breaker.logToOutput(e.getMessage());
        }
    }

    private void exportToUrlFile() {

        this.breaker.logToOutput("Exporting to url file");

        try {
            File f = new File(Constant.getZapHome(), URL_FILE);
            if (f.createNewFile()) {
                this.breaker.logToOutput("URL file not exists, create URL file");
            } else {
                this.breaker.logToOutput("URL exists, updating url file");
            }

            FileWriter myWriter = new FileWriter(f);
            for(String url: knownUrlList) {
                myWriter.write(url + "\n");
                this.breaker.logToOutput("Written: " + url);
            }
            myWriter.close();
            this.breaker.logToOutput("written " + knownUrlList.size() + " urls to url file");

        } catch (Exception e) {
            this.breaker.logToOutput(e.getMessage());
        }
    }

    private void displayFile(String file) {
        if (!View.isInitialised()) {
            // Running in daemon mode, shouldnt have been called
            return;
        }
        try {
            File f = new File(Constant.getZapHome(), file);
            if (!f.exists()) {
                // This is something the user should know, so show a warning dialog
                View.getSingleton()
                        .showWarningDialog(
                                Constant.messages.getString(
                                        ExtensionSimpleExample.PREFIX + ".error.nofile",
                                        f.getAbsolutePath()));
                return;
            }
            // Quick way to read a small text file
            String contents = new String(Files.readAllBytes(f.toPath()));
            // Write to the output panel
            View.getSingleton().getOutputPanel().append(contents);
            // Give focus to the Output tab
            View.getSingleton().getOutputPanel().setTabFocus();
        } catch (Exception e) {
            // Something unexpected went wrong, write the error to the log
            LOGGER.error(e.getMessage(), e);
        }
    }

    private RightClickMsgMenu getPopupMsgMenuExample() {
        if (popupMsgMenuExample == null) {
            popupMsgMenuExample =
                    new RightClickMsgMenu(
                            this, Constant.messages.getString(PREFIX + ".popup.title"));
        }
        return popupMsgMenuExample;
    }

//    private SimpleBreak getBreaker() {
//        breaker = new SimpleBreak(this);
//        return breaker;
//    }


    public List<String> getKnownUrlList() {
        return knownUrlList;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }
}
