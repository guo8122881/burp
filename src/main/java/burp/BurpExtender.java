package burp;

import java.awt.*;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;

public class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener ,ITab {
    private IExtensionHelpers burpHelpers = null;
    private PrintWriter debugLogger = null;
    private PrintWriter errorLogger = null;
    private DecryptView decryptView;
    private IBurpExtenderCallbacks callbacks;


    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
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
            requestIn(message,messageIsRequest);
        } else {
            responseOut(message);
        }
    }
    private  void requestIn(IInterceptedProxyMessage message, boolean messageIsRequest) {
        callbacks.printOutput(message.toString());
        IHttpRequestResponse qqq=message.getMessageInfo();
        byte[] new_requests = qqq.getRequest();
        String req=burpHelpers.bytesToString(new_requests);
        new_requests=burpHelpers.urlDecode(new_requests);
        this.callbacks.printOutput(req);
        qqq.setRequest(new_requests);

        }



    private void requestOut(IHttpRequestResponse messageInfo) {

    }
    private void responseIn(IHttpRequestResponse messageInfo) {
        System.out.println(messageInfo);
    }
    private void responseOut(IInterceptedProxyMessage message) {
        //
    }
    public static String getURLEncoderString(String str) {
        String result = "";
        if (null == str) {
            return "";
        }
        try {
            result = URLEncoder.encode(str, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return result;
    }

    public static String URLDecoderString(String str) {
        String result = "";
        if (null == str) {
            return "";
        }
        try {
            result = URLDecoder.decode(str, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return result;
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
