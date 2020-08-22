package burp;

import java.io.*;
import java.net.URL;
import java.util.List;


import java.util.Scanner;

import javax.script.*;

public class main  {

    public static void main(String[] args) throws FileNotFoundException, ScriptException, NoSuchMethodException {

//        callbacks.printOutput(message.toString());
//        IHttpRequestResponse qqq=message.getMessageInfo();
//        byte[] new_requests = qqq.getRequest();
//        String req=burpHelpers.bytesToString(new_requests);
//        IRequestInfo analyzeRequest=burpHelpers.analyzeRequest(message.getMessageInfo());
//        int a=analyzeRequest.getBodyOffset();
//        String body=burpHelpers.bytesToString(new_requests).substring(a).trim();
//        byte[]aaa=burpHelpers.base64Decode(body);
//        this.callbacks.printOutput(body);
//        qqq.setRequest(aaa);
        // 获取JS执行引擎
        ScriptEngine se = new ScriptEngineManager().getEngineByName("javascript");
        // 获取变量
        Bindings bindings = se.createBindings();
        bindings.put("number", 3);
        se.setBindings(bindings, ScriptContext.ENGINE_SCOPE);
        Scanner sc = new Scanner(System.in);
        while (sc.hasNextInt()) {
            int a = sc.nextInt();
            int b = sc.nextInt();
            System.out.println("输入的参数【" + a + "】 + 【" + b + "】");
            se.eval(new FileReader("\\Users\\gc\\Downloads\\666.js"));
            // 是否可调用
            if (se instanceof Invocable) {
                Invocable in = (Invocable) se;
                Integer result = (Integer) in.invokeFunction("add", a, b);
                System.out.println("获得的结果：" + result);

            }

        }
//        public static String hmac(String uuu) throws Exception {
//            // 得到一个ScriptEngine对象
//            ScriptEngineManager maneger = new ScriptEngineManager();
//            ScriptEngine engine = maneger.getEngineByName("JavaScript");
//
//            // 读js文件
//            String jsFile = "/Users/gc/Downloads/666666.js";
//            FileInputStream fileInputStream = new FileInputStream(new File(jsFile));
//            Reader scriptReader = new InputStreamReader(fileInputStream, "utf-8");
//            // 调用JS方法
//            Invocable invocable = (Invocable)engine;
//            String result = (String)invocable.invokeFunction("hmacJson", uuu);
//            System.out.println(result);
//            System.out.println(result.length());
//
//            scriptReader.close();
//
//            return result;
//        }


    }


}
