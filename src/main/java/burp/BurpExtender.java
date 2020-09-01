package burp;

import com.sun.xml.internal.messaging.saaj.util.Base64;

import java.awt.*;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.swing.*;
//new_requests=new_aaa.getBytes("UTF-8");//这儿必须要用getBytes（"UTF-8"）方法，不然会编码错误
//警告这儿如果将请求专成字符串，必须要用这个方法，不可用burphelpers的BytetoString方法
//如果字符串转byte也需要用String req=new String(new_requests,"UTF-8");
//总之字节转字符串，字符串转字节不可用burp自带的方法，需要用上面的转换方法才可以
//并且不要使用burp自带的encode和decode方法，没有做转码处理，会报错，使用java自带的URLencode.encode方法
public class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener ,ITab {
    private IExtensionHelpers burpHelpers = null;
    private PrintWriter debugLogger = null;
    private PrintWriter errorLogger = null;
    private DecryptView decryptView;
    private IBurpExtenderCallbacks callbacks;
    public String path;
    private IMessageEditorTab iMessageEditorTab;
    private IMessageEditorTabFactory factory;
    private IContextMenuFactory iContextMenuFactory;
    private IContextMenuInvocation currentInvocation;
    //关键点：：：
    //这儿是关键，因为burp插件会有编码问题，如果只用burphelpers的urldecode只进行了url解码，但是没处理utf-8,bgk
    //等编码问题，所以，还需要用java原生态的decode再解码一次，解码根据网页的编码来进行解码

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
            String req=new String(new_requests,"UTF-8");//将请求转换从字节数组转换成
            if(req.contains("jsonData=")){
                if(req.contains("&requestChannel=WX")){
                    callbacks.printOutput("微信银行请求获取成功");
                    IRequestInfo analyzeRequest=burpHelpers.analyzeRequest(message.getMessageInfo());//获取请求报文信息
                    List<String> yas=analyzeRequest.getHeaders();
                    String headerpar=yas.get(0);
                    callbacks.printOutput(req);
                    String rreq=URLDecoder.decode(req,"UTF-8");
                    callbacks.printOutput("微信请求：：："+rreq);
                    //微信请求头解密
                    if(headerpar.contains("&requestChannel=WX")) {
                        callbacks.printOutput("请求头微信银行解密成功");
                        String newheader=headerpar.substring(headerpar.indexOf("jsonData=")+9,headerpar.indexOf("&requestChannel=WX")+18);
                        String newheader1=burpHelpers.urlDecode(newheader);
                        String newheader2=URLDecoder.decode(newheader1,"UTF-8");
                        String yyyy=newheader2.substring(newheader2.indexOf("\"reqHead\""),newheader2.indexOf("&requestChannel=WX")-1);
                        String yyyyy=hmac("{"+yyyy+"}");
                        String oldmac=yyyyy.substring(yyyyy.indexOf(",\"mac\":")+1,yyyyy.indexOf("=\"}")+2);
                        String newmac=(oldmac+",");
                        String xxx=("{"+newmac+yyyy+"}");
                        String post=headerpar.substring(headerpar.indexOf("/wbank/")-5,headerpar.indexOf("jsonData=")+9);
                        String PPost=post+xxx+"&requestChannel=WX HTTP/1.1";
                        callbacks.printError("微信银行请求头豹纹：：：："+PPost);
                        yas.set(0,PPost);
                        new_requests=burpHelpers.buildHttpMessage(yas,null);
                        qqq.setRequest(new_requests);

                    }else {
                        //微信请求体解密
                        int a=analyzeRequest.getBodyOffset();//获取请求体内容
                        String body=req.substring(a).trim();//利用substring截取豹纹体
                        String ccc=body.substring(9);//利用substring截取要解密的字段
                        //关键点：：：
                        //这儿是关键，因为burp插件会有编码问题，如果只用burphelpers的urldecode只进行了url解码，但是没处理utf-8,bgk
                        //等编码问题，所以，还需要用java原生态的decode再解码一次，解码根据网页的编码来进行解码
                        String cccc=URLDecoder.decode(ccc,"UTF-8");//对解密的字段进行url转码,这儿必须要用系统自带的url转换
                        //不能使用burphelps里的urldecode方法
                        String yyyy=cccc.substring(cccc.indexOf("\"reqHead\""),cccc.indexOf("&requestChannel=WX"));
                        String yyyyy=hmac("{"+yyyy);
                        String oldmac=yyyyy.substring(yyyyy.indexOf(",\"mac\":")+1,yyyyy.indexOf("=\"}")+2);
                        String newmac=(oldmac+",");
                        String xxx=("{"+newmac+yyyy);
                        String aa = "jsonData=";
                        String aaa = "&requestChannel=WX";
                        String new_aaa = aa+xxx+aaa;
                        new_requests=new_aaa.getBytes("UTF-8");//因为请求必须是字节发送，所以要将字符串转换成字节
                        new_requests=burpHelpers.buildHttpMessage(analyzeRequest.getHeaders(), new_requests);//通过bulidhttpmessage构造请求，请求头，请求体
                        qqq.setRequest(new_requests);//将请求转发出去

                    }
                }else {
                    //个人银行解密
                    IRequestInfo analyzeRequest=burpHelpers.analyzeRequest(message.getMessageInfo());//获取请求报文信息
                    int a=analyzeRequest.getBodyOffset();//获取请求体内容
                    String body=req.substring(a).trim();//利用substring截取豹纹体
                    String ccc=body.substring(17);//利用substring截取要解密的字段
                    //关键点：：：
                    //这儿是关键，因为burp插件会有编码问题，如果只用burphelpers的urldecode只进行了url解码，但是没处理utf-8,bgk
                    //等编码问题，所以，还需要用java原生态的decode再解码一次，解码根据网页的编码来进行解码

                    String cccc=URLDecoder.decode(ccc,"UTF-8");

                    //不能使用burphelps里的urldecode方法

                    String yyyy=cccc.substring(cccc.indexOf("jsonData=")+1,cccc.indexOf(",\"mac"));
                    String yyyyy=hmac(yyyy+"}");
//                    String y=burpHelpers.urlDecode(yyyyy);
//                    callbacks.printOutput("y的植为：：："+y);
                    String aa = "rqId=A1&";
                    String aaa = "jsonData=";//拼接字段
                    String new_aaa = aa+aaa+yyyyy;
                    new_requests=new_aaa.getBytes("UTF-8");//这儿必须要用getBytes（"UTF-8"）方法，不然会编码错误
//                    new_requests=burpHelpers.stringToBytes(new_aaa);//因为请求必须是字节发送，所以要将字符串转换成字节
                    new_requests=burpHelpers.buildHttpMessage(analyzeRequest.getHeaders(), new_requests);//通过bulidhttpmessage构造请求，请求头，请求体
                    qqq.setRequest(new_requests);//将请求转发出去
                }

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
        byte[] new_requests = messageInfo.getRequest();//从豹纹对象中获取请求包
        String req=new String(new_requests,"UTF-8");
//        String req=burpHelpers.bytesToString(new_requests);//将请求转换从字节数组转换成
        callbacks.printError("response的只为：：：++"+req);
        //是否是联盟请求
        if(req.contains("jsonData=")){
            //是否是微信请求
            if(req.contains("&requestChannel=WX")){
                callbacks.printOutput("微信银行请求获取成功");
                IRequestInfo analyzeRequest=burpHelpers.analyzeRequest(messageInfo);//获取请求报文信息
                List<String> yas=analyzeRequest.getHeaders();
                String headerpar=yas.get(0);
                callbacks.printOutput(req);
                String rreq=URLDecoder.decode(req,"UTF-8");
                callbacks.printOutput("微信请求：：："+rreq);
                //是否是微信银行请求头解密
                if(headerpar.contains("&requestChannel=WX")){
                    callbacks.printOutput("请求头微信银行解密成功");
                    String newheader=headerpar.substring(headerpar.indexOf("jsonData=")+9,headerpar.indexOf("&requestChannel=WX")+18);
                    String yyyy=newheader.substring(newheader.indexOf("\"reqHead\""),newheader.indexOf("&requestChannel=WX")-1);
                    String yyyyy=hmac("{"+yyyy+"}");
                    String oldmac=yyyyy.substring(yyyyy.indexOf(",\"mac\":")+1,yyyyy.indexOf("=\"}")+2);
                    String newmac=(oldmac+",");
                    String xxx=("{"+newmac+yyyy+"}");
                    String xxxx=URLEncoder.encode(xxx,"UTF-8");
                    String post=headerpar.substring(headerpar.indexOf("/wbank/")-5,headerpar.indexOf("jsonData=")+9);
                    String PPost=post+xxxx+"&requestChannel=WX HTTP/1.1";
                    callbacks.printError("微信银行请求头豹纹：：：："+PPost);
                    yas.set(0,PPost);
                    new_requests=burpHelpers.buildHttpMessage(yas,null);
                    messageInfo.setRequest(new_requests);
                }else{
                    //是否是微信银行请求体解密
                    int a=analyzeRequest.getBodyOffset();//获取请求体内容
                    String body=req.substring(a).trim();
                    String cccc=body.substring(9);//利用substring截取要解密的字段
//                String cccc=URLDecoder.decode(ccc,"UTF-8");//对解密的字段进行url转码,这儿必须要用系统自带的url转换
                    //不能使用burphelps里的urldecode方法
                    String yyyy=cccc.substring(cccc.indexOf("\"reqHead\""),cccc.indexOf("&requestChannel=WX")-1);
                    String yyyyy=hmac("{"+yyyy+"}");
                    String oldmac=yyyyy.substring(yyyyy.indexOf(",\"mac\":")+1,yyyyy.indexOf("=\"}")+2);
                    String newmac=(oldmac+",");
                    String xxx=("{"+newmac+yyyy);
                    String aa = "jsonData=";
                    String aaa = "&requestChannel=WX";
                    String xxxx=URLEncoder.encode(xxx,"UTF-8");
                    String new_aaa = aa+xxxx+"}"+aaa;
                    new_requests=new_aaa.getBytes("UTF-8");//因为请求必须是字节发送，所以要将字符串转换成字节
                    new_requests=burpHelpers.buildHttpMessage(analyzeRequest.getHeaders(), new_requests);//通过bulidhttpmessage构造请求，请求头，请求体
                    messageInfo.setRequest(new_requests);//将请求转发出去
                }
            }else{
                //个人银行请求
                IRequestInfo analyzeRequest=burpHelpers.analyzeRequest(messageInfo);//获取请求报文信息
                int a=analyzeRequest.getBodyOffset();//获取请求体内容
                String body=req.substring(a).trim();//利用substring截取豹纹体
                String ccc=body.substring(17);//利用substring截取要解密的字段
                String yyyy=body.substring(body.indexOf("jsonData=")+9,body.indexOf(",\"mac"));
                String yyyyy=hmac(yyyy+"}");
                String yyyyyy = (yyyyy);
                String cccc=URLEncoder.encode(yyyyyy,"UTF-8");//对解密的字段进行url转码,这儿不能使用burphelpers自带的urlEncode方法，
                //加密报文会编码失败
                String aa = "rqId=A1&";
                String aaa = "jsonData=";//拼接字段
                String new_aaa = aa+aaa+cccc;
                new_requests=new_aaa.getBytes("UTF-8");//因为请求必须是字节发送，所以要将字符串转换成字节
                new_requests=burpHelpers.buildHttpMessage(analyzeRequest.getHeaders(), new_requests);//通过bulidhttpmessage构造请求，请求头，请求体
                messageInfo.setRequest(new_requests);//将请求转发出去
            }

        }else {
            this.callbacks.printError("非联盟请求，忽略加密");
        }
    }
    public  String ByteString(byte[] bytes) throws UnsupportedEncodingException {
        String sendString=new String(bytes ,"UTF-8");
        return sendString;
    }

    private void responseIn(IHttpRequestResponse messageInfo) {

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
