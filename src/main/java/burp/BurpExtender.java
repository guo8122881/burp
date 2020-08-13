package burp;

import java.awt.*;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener ,ITab {
    private IExtensionHelpers burpHelpers = null;
    private PrintWriter debugLogger = null;
    private PrintWriter errorLogger = null;
    private DecryptView decryptView;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        burpHelpers = callbacks.getHelpers();
        debugLogger = new PrintWriter(callbacks.getStdout(), true);
        errorLogger = new PrintWriter(callbacks.getStderr(), true);
        callbacks.setExtensionName("Cryptor");
        callbacks.registerHttpListener(this);  // 注册HttpListener
        callbacks.registerProxyListener(this); // 注册ProxyListener
        callbacks.printOutput("脚本加载成功");
        decryptView=new DecryptView(callbacks);
        callbacks.addSuiteTab(this);
    }

    public void processHttpMessage(
            int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            requestOut(messageInfo);
        } else {
            responseIn(messageInfo);
        }
    }

    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (messageIsRequest) {
            requestIn(message);
        } else {
            responseOut(message);
        }
    }
    private  void requestIn(IInterceptedProxyMessage message) {
        System.out.println(message);
    }
    private void requestOut(IHttpRequestResponse messageInfo) {
        //
    }
    private void responseIn(IHttpRequestResponse messageInfo) {
        System.out.println(messageInfo);
    }
    private void responseOut(IInterceptedProxyMessage message) {
        //
    }


    @Override
    public String getTabCaption() {
        return "Cryptor";
    }

    @Override
    public Component getUiComponent() {
        return decryptView.$$$getRootComponent$$$();
    }
}
