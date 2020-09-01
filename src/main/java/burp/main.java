package burp;

import java.io.*;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.List;


import java.util.Scanner;

import javax.script.*;

public class main  {

    public static void main(String[] args) throws FileNotFoundException, ScriptException, NoSuchMethodException, UnsupportedEncodingException {
        IExtensionHelpers burpHelpers = null;
        String nn=burpHelpers.urlDecode("%7B%22reqData%22%3A%7B%22queryFlag%22%3A%220%22%2C%22bdfName%22%3A%22%E8%BD%AC%E8%B4%A6%22%2C%22turnPageBeginPos%22%3A1%2C%22turnPageShowNum%22%3A%2210%22%2C%22turnPageValue%22%3A%221%7C%7C10%22%2C%22turnPageFlag%22%3A%220%22%7D%2C%22reqHead%22%3A%7B%22rqId%22%3A%22A1%22%2C%22referer%22%3A%22https%3A%2F%2F866.ebanktest.com.cn%3A6866%2Fpbank%2F%23%2Findex%2Fsearch%22%2C%22sn%22%3Anull%2C%22transId%22%3A%22490000000%22%2C%22bkId%22%3A%22866%22%2C%22stime%22%3A%2220200827112621229%22%2C%22sid%22%3Anull%2C%22rspFmt%22%3A%22json%22%2C%22submitKey%22%3Anull%2C%22version_num%22%3A%22PB_V4%22%2C%22appVer%22%3A%22chrome%2F84.0.4147.135%22%2C%22dNo%22%3A%22e7a9402609fe7f6f26634b49db7b36aeff0a0ff6aa77b625e3c28bb3b37872cd%22%2C%22isPassword%22%3Atrue%2C%22flag%22%3Atrue%2C%22opId%22%3A%22ebus_functionSearch%22%7D%2C%22mac%22%3A%221yKkC2blDwM1v%3CT6jhY5BybbBpWpdMizjMe450kjLzs%3D%22%7D");
        String name=URLDecoder.decode(nn,"UTF-8");
        String nnmae=URLEncoder.encode(name,"UTF-8");
        System.out.println(nn);
        System.out.println(name);
        System.out.println(nnmae);

//        callbacks.printOutput("微信银行请求获取成功");
//        IRequestInfo analyzeRequest=burpHelpers.analyzeRequest(message.getMessageInfo());//获取请求报文信息
//        List<String> yas=analyzeRequest.getHeaders();
//        String headerpar=yas.get(0);
//        callbacks.printOutput(yas.get(3));
//        //微信请求头解密
//        if(headerpar.contains("&requestChannel=WX")) {
//            callbacks.printOutput("请求头微信银行解密成功");
//            String newheader=headerpar.substring(headerpar.indexOf("jsonData=")+9,headerpar.indexOf("&requestChannel=WX")+18);
//            String newheader1=burpHelpers.urlDecode(newheader);
//            String newheader2=URLDecoder.decode(newheader1,"UTF-8");
//            String yyyy=newheader2.substring(newheader2.indexOf("\"reqHead\""),newheader2.indexOf("&requestChannel=WX")-1);
//            String yyyyy=hmac("{"+yyyy+"}");
//            String oldmac=yyyyy.substring(yyyyy.indexOf(",\"mac\":")+1,yyyyy.indexOf("=\"}")+2);
//            String newmac=(oldmac+",");
//            String xxx=("{"+newmac+yyyy+"}");
//
//            String post=headerpar.substring(headerpar.indexOf("/wbank/")-5,headerpar.indexOf("jsonData=")+9);
//            String PPost=post+xxx+"&requestChannel=WX HTTP/1.1";
//            callbacks.printError("微信银行请求头豹纹：：：："+PPost);
//            yas.set(0,PPost);
//            new_requests=burpHelpers.buildHttpMessage(yas,null);
//            qqq.setRequest(new_requests);




//        callbacks.printOutput("请求头微信银行解密成功");
//        String head=rreq.substring(rreq.indexOf("POST"),rreq.indexOf("jsonData=")+9);
//        String weixinheader=rreq.substring(rreq.indexOf("\"reqHead\""),rreq.indexOf("&requestChannel=WX"));
//        String wwxinheader =("{"+weixinheader);
//        String wwwhead=hmac(wwxinheader);
//        String wwwww=wwwhead.substring(wwwhead.indexOf("\"mac\":"),wwwhead.indexOf("=\"}")+2);
//        String ww=wwwww+",";
//        String w = ("{"+ww+weixinheader);
//        String aaa ="&requestChannel=WX HTTP/1.1";
//        String new_aaa=head+w+aaa;
//        callbacks.printError("55555"+wwwhead);
//        callbacks.printError("6666666666"+w);
//
//        yas.set(0,new_aaa);
//        callbacks.printError("7777777"+yas.get(0));
//        new_requests=burpHelpers.buildHttpMessage(yas,null);
//        qqq.setRequest(new_requests);
    }


}
