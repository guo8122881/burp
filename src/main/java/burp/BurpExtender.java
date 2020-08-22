package burp;

import java.awt.*;
import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.List;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

public class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener ,ITab {
    private IExtensionHelpers burpHelpers = null;
    private PrintWriter debugLogger = null;
    private PrintWriter errorLogger = null;
    private DecryptView decryptView;
    private IBurpExtenderCallbacks callbacks;
    public String path;


    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        burpHelpers = callbacks.getHelpers();
        debugLogger = new PrintWriter(callbacks.getStdout(), true);
        errorLogger = new PrintWriter(callbacks.getStderr(), true);
        callbacks.setExtensionName("Cryptor");
        callbacks.registerHttpListener(this);  // 注册HttpListener
        callbacks.registerProxyListener(this); // 注册ProxyListener
        callbacks.printOutput("脚本加载成功6");
        decryptView=new DecryptView(callbacks);
        callbacks.addSuiteTab(this);
    }

    public void processHttpMessage(
            int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) throws Exception {
        if (messageIsRequest) {
            requestOut(messageInfo);
        } else {
            responseIn(messageInfo);
        }
    }

    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) throws Exception {
        if (messageIsRequest) {
            requestIn(message,messageIsRequest);
        } else {
            responseOut(message);
        }
    }
    private  void requestIn(IInterceptedProxyMessage message, boolean messageIsRequest) throws Exception {
        if(messageIsRequest){
            IHttpRequestResponse qqq=message.getMessageInfo();//获取报文信息
            byte[] new_requests = qqq.getRequest();//从豹纹对象中获取请求包
            String req=burpHelpers.bytesToString(new_requests);//将请求转换从字节数组转换成
            if(req.contains("jsonData=")){
                IRequestInfo analyzeRequest=burpHelpers.analyzeRequest(message.getMessageInfo());//获取请求报文信息
                int a=analyzeRequest.getBodyOffset();//获取请求体内容
                String body=burpHelpers.bytesToString(new_requests).substring(a).trim();//利用substring截取豹纹体
                String ccc=body.substring(17);//利用substring截取要解密的字段
                String cccc=URLDecoder.decode(ccc,"UTF-8");//对解密的字段进行url转码,这儿必须要用系统自带的url转换
                //不能使用burphelps里的urldecode方法
                new_requests=burpHelpers.stringToBytes(cccc);//对解密的字段进行base64转码
                String aaaa=burpHelpers.bytesToString(new_requests);//从字节转换成字符串
                String yyyy=aaaa.substring(aaaa.indexOf("jsonData=")+1,aaaa.indexOf(",\"mac"));
                String yyyyy=hmac(yyyy+"}");
                String aa = "rqId=A1&";
                String aaa = "jsonData=";//拼接字段
                String new_aaa = aa+aaa+yyyyy;
                new_requests=burpHelpers.stringToBytes(new_aaa);//因为请求必须是字节发送，所以要将字符串转换成字节
                new_requests=burpHelpers.buildHttpMessage(analyzeRequest.getHeaders(), new_requests);//通过bulidhttpmessage构造请求，请求头，请求体
                this.callbacks.printOutput(yyyy);//调用callbacks的日志输出
                this.callbacks.printOutput(yyyyy);
                qqq.setRequest(new_requests);//将请求转发出去
            }else {
                this.callbacks.printError("未找到联盟请求，解密失败");
            }
        }



    }
    public  String hmac(String uuu) throws Exception {
        // 得到一个ScriptEngine对象
        ScriptEngineManager maneger = new ScriptEngineManager();
        ScriptEngine engine = maneger.getEngineByName("JavaScript");
//        String path = this.getClass().getClassLoader().getResource("666666.js").getPath();
//        String path2=path.substring(5);
        // 读js文件/Users/gc/IdeaProjects/Myburp/src/main/java/burp/666666.js
//        String path1=this.getClass().getPackage().getName();
        String jsFile = ("/Users/gc/IdeaProjects/Myburp/src/main/java/burp/666666.js");
        FileInputStream fileInputStream = new FileInputStream(new File(jsFile));
        Reader scriptReader = new InputStreamReader(fileInputStream, "utf-8");
        // 调用JS方法
        engine.eval(scriptReader);
        Invocable invocable = (Invocable)engine;
        String result = (String)invocable.invokeFunction("hmacJson", uuu);
        System.out.println(result);
        System.out.println(result.length());

        scriptReader.close();

        return result;
    }



    private void requestOut(IHttpRequestResponse messageInfo) throws Exception {
        callbacks.printError("666666666666666");
        byte[] new_requests = messageInfo.getRequest();//从豹纹对象中获取请求包
        String req=burpHelpers.bytesToString(new_requests);//将请求转换从字节数组转换成
        if(req.contains("jsonData=")){
            IRequestInfo analyzeRequest=burpHelpers.analyzeRequest(messageInfo);//获取请求报文信息
            int a=analyzeRequest.getBodyOffset();//获取请求体内容
            String body=burpHelpers.bytesToString(new_requests).substring(a).trim();//利用substring截取豹纹体
            String ccc=body.substring(17);//利用substring截取要解密的字段
            String yyyy=body.substring(body.indexOf("jsonData=")+9,body.indexOf(",\"mac"));
            String yyyyy=hmac(yyyy+"}");
            String yyyyyy = (yyyyy);
            String cccc=URLEncoder.encode(yyyyyy,"UTF-8");//对解密的字段进行url转码,这儿不能使用burphelpers自带的urlEncode方法，
            //加密报文会编码失败
//            String cccc=burpHelpers.urlEncode(yyyyyy);//对解密的字段进行url转码
            new_requests=burpHelpers.stringToBytes(cccc);//对解密的字段进行base64转码
            String aaaa=burpHelpers.bytesToString(new_requests);//从字节转换成字符串
            String aa = "rqId=A1&";
            String aaa = "jsonData=";//拼接字段
            String new_aaa = aa+aaa+aaaa;
            callbacks.printError(new_aaa);
            new_requests=burpHelpers.stringToBytes(new_aaa);//因为请求必须是字节发送，所以要将字符串转换成字节
            new_requests=burpHelpers.buildHttpMessage(analyzeRequest.getHeaders(), new_requests);//通过bulidhttpmessage构造请求，请求头，请求体
            this.callbacks.printOutput(cccc);//调用callbacks的日志输出
            messageInfo.setRequest(new_requests);//将请求转发出去
        }else {
            this.callbacks.printError("未加密成功");
        }
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
