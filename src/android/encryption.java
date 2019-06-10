package cordova.encryption;

import android.content.Context;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;

import org.json.JSONArray;
import org.json.JSONException;

import com.nisc.Olym_CrossDomain_SecurityEngine;
import com.nisc.Olym_Device_SecurityEngine;
import com.nisc.Olym_Cipher_SecurityEngine;
import com.nisc.SecurityEngine;
import com.nisc.SecurityEngineAlg;
import com.nisc.api.SecEngineException;

import android.util.Log;

import java.nio.charset.Charset;
import java.util.concurrent.TimeUnit;

import okhttp3.Call;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.alibaba.fastjson.*;
import com.sun.mail.imap.IMAPMessage;
import com.sun.mail.util.MailSSLSocketFactory;
// import com.sun.xml.internal.ws.policy.privateutil.PolicyUtils;
import org.apache.commons.lang3.StringEscapeUtils;

import javax.mail.*;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

/**
 * This class echoes a string called from JavaScript.
 */
public class encryption extends CordovaPlugin {

    public static final String MULTIPART_MIME_TYPE = "multipart/";
    private static final String STYLES =
            "body {font-family: 'Roboto', 'Calibri',  sans-serif; font-size: 1rem; color: #333}" +
                    "h1 {margin: 6px 0 16px 0; font-size: 3rem; font-weight: normal}" +
                    "h2 {margin: 6px 0 12px 0; font-size: 2.5rem; font-weight: normal}" +
                    "h3 {margin: 6px 0 8px 0; font-size: 1.5rem; font-weight: bold}" +
                    "blockquote {border-left: 5px solid #ebebeb; font-style: italic; margin: 0; padding: 0 32px}" +
                    "pre.code {background-color: #ebebeb; margin: 0; padding: 8px}";
    public static final String HEADER_IN_REPLY_TO = "In-Reply-To";
    public static final String HEADER_REFERENCES = "References";
    private static final Pattern DATA_URI_IMAGE_PATTERN = Pattern.compile("\"data:(image\\/[^;]*?);base64,([^\\\"]*?)\"");

    public static String extractContent( Multipart multipart) throws MessagingException, IOException {
        String ret = "";
        for (int it = 0; it < multipart.getCount(); it++) {
            final BodyPart bp = multipart.getBodyPart(it);
            if ((ret == null || ret.isEmpty())
                    && bp.getContentType().toLowerCase().startsWith("text/plain")) {
                ret = String.format("<pre>%s</pre>", StringEscapeUtils.escapeHtml4(bp.getContent().toString()));
            }
            if (bp.getContentType().toLowerCase().startsWith("text/html")) {
                ret = (bp.getContent().toString());
            }
            if (bp.getContentType().toLowerCase().startsWith(MULTIPART_MIME_TYPE)) {
                ret = extractContent((Multipart) bp.getContent());
            }
        }
        return ret;
    }
    public static javax.mail.Address[] getRecipientAddresses(MessageMail message, javax.mail.Message.RecipientType type) {
        if (message.getRecipients() == null || message.getRecipients().isEmpty()) {
            return new Address[0];
        }
        return message.getRecipients().stream()
                .filter(r -> type.toString().equals(r.getType()))
                .map(r -> {
                    try {
                        return new InternetAddress(r.getAddress());
                    } catch(AddressException ex) {
                        return null;
                    }
                })
                .toArray(InternetAddress[]::new);
    }
    void transform(MessageMail message, String absolutePath, String fromUser)
    {
        try {
            final Charset currentCharset = Charset.defaultCharset();
            Properties props = new Properties();
            Session session = Session.getDefaultInstance(props, null);
            final MimeMessage mimeMessage = new MimeMessage(session);
            mimeMessage.setFrom(fromUser);
            mimeMessage.setSentDate(new Date());
            for (javax.mail.Message.RecipientType type : new javax.mail.Message.RecipientType[]{
                    MimeMessage.RecipientType.TO, MimeMessage.RecipientType.CC, MimeMessage.RecipientType.BCC
            }) {
                mimeMessage.setRecipients(type, getRecipientAddresses(message, type));
            }
            mimeMessage.setSubject(message.getSubject(), currentCharset.name());

            if (message.getInReplyTo() != null) {
                mimeMessage.setHeader(HEADER_IN_REPLY_TO, "");
            }
            if (message.getReferences() != null) {
                mimeMessage.setHeader(HEADER_REFERENCES, "");
            }
//            String.join(" ", message.getReferences())
            final MimeMultipart multipart = new MimeMultipart();

            // Extract data-uri images to inline attachments
            final String originalContent = message.getContent();
            String finalContent = originalContent;
            final Matcher matcher = DATA_URI_IMAGE_PATTERN.matcher(originalContent);
            while(matcher.find()) {
                final String cid = UUID.randomUUID().toString().replace("-", "");
                final String contentType = matcher.group(1);
                final InternetHeaders headers = new InternetHeaders();
                headers.addHeader("Content-Type", contentType);
                headers.addHeader("Content-Transfer-Encoding", "base64");
                final MimeBodyPart cidImagePart = new MimeBodyPart(headers, matcher.group(2).getBytes());
                multipart.addBodyPart(cidImagePart);
                cidImagePart.setDisposition(MimeBodyPart.INLINE);
                cidImagePart.setContentID(String.format("<%s>",cid));
                cidImagePart.setFileName(String.format("%s.%s", cid, contentType.substring(contentType.indexOf('/') + 1)));
                finalContent = finalContent.replace(matcher.group(), "\"cid:" +cid +"\"");
            }

            // Create body part
            final MimeBodyPart body = new MimeBodyPart();
            multipart.addBodyPart(body);
            body.setContent(new String(String.format("<html><head><style>%1$s</style></head><body><div id='scoped'>"
                            + "<style type='text/css' scoped>%1$s</style>%2$s</div></body></html>",
                    STYLES, finalContent).getBytes(), currentCharset),
                    String.format("%s; charset=\"%s\"", "text/html", currentCharset.name()));
            mimeMessage.setContent(multipart);

            mimeMessage.saveChanges();
            mimeMessage.writeTo(new FileOutputStream(new File(absolutePath)));

        } catch(MessagingException | IOException ex) {
            return;
        }
    }

    public static void SendEncryptMessage(String plainFilename) throws FileNotFoundException, MessagingException, IOException
    {
        //String plainFilename = "AAABBBB.eml";
        InputStream inputStream = new FileInputStream(plainFilename);
        BufferedInputStream bis = new BufferedInputStream(inputStream);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        int date = -1;
        while ((date = bis.read()) != -1) {
            bos.write(date);
        }
        byte[] bytes = bos.toByteArray();
        InputStream sbs = new ByteArrayInputStream(bytes);
        Properties props = new Properties();
        Session session = Session.getDefaultInstance(props, null);
        InputStream inMsg = new ByteArrayInputStream(bytes);
        MimeMessage mimeMessageEn = new MimeMessage(session, inMsg);


        String url = "http://192.168.30.234:8080/api/v1/smtp/sendencrypt";
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        mimeMessageEn.writeTo(baos);
        byte[] bytesMime = baos.toByteArray();
        String jar = com.alibaba.fastjson.JSONArray.toJSONString(bytesMime);
        com.alibaba.fastjson.JSONObject jsonObject = new com.alibaba.fastjson.JSONObject();
        jsonObject.put("mail", jar);
        jsonObject.put("sender_id", mimeMessageEn.getFrom()[0].toString());

        OkHttpClient client = new OkHttpClient.Builder().readTimeout(20, TimeUnit.SECONDS).build();
        MediaType JSON = MediaType.parse("application/json; charset=utf-8");
        RequestBody body = RequestBody.create(JSON, jsonObject.toJSONString());
        Request request = new Request.Builder().url(url).addHeader("Isotope-Salt", "9f18db035e3c1c28")
                .addHeader("Isotope-Credentials", "4de62c9072b47359e6aa0dd4489f0650eaa35188d71d15d6dfece9561aa32104e8e0a3604e4c262edc6fc739f315ec7b93cab8e20d4a93753dfb783bba6aa034e1559a3e13a7a77b141de3833c264efef3a71ed00f565dc11da47e5130f6413f5ea14f4a3a6b97bca1e86edf0fb58973b63e8805dd77b18411bbf64e58b607536507582cc3c62c4fdc78ae5cd0143f5960f0b3fb8371223fcee8b1f86f0267338ce9a2541b5ac04ecf987ff778f1bf6c5c4af8e820e8a00e106138cbe34d2284328ed1111b138b84f9c9f97e7191147709bea0b91cfff975288962cfb17ac65e7aa5289d1b764977437e52054f08644615e36cec47459970c38564bfd2e1312c2a6b6c9abf74744faa0972901e2fe8547ba2cf5a79d1605e6f5acf7fac68bac3a2ddeb6dba56faff5fa58bf53ea6028a5c50f684baa426d862a5c89897ed742d37be8843185c981e0cb0f4d89c98f3940f236e1284e885ef4206ce72de81a8f433f614fd1c56e3620a53169120002769af866dc5b85e849c32aacbd3706b998e31b6216a46565631d736601e8fce58ed")
                .post(body).build();
        Call call = client.newCall(request);
        try {
            Response response = call.execute();
            System.out.println(response.body().toString());
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
    @Override
    public boolean execute(String action, org.json.JSONArray args, CallbackContext callbackContext) throws org.json.JSONException {
        if (action.equals("coolMethod")) {
            String message = args.getString(0);
            this.coolMethod(message, callbackContext);
            return true;
        }else if(action.equals("Decrypt")) {
            String decryptParameter = args.getString(0);
            // 调用解密接口
            this.Decrypt(decryptParameter, callbackContext);
        }else if(action.equals("Encrypt")) {
            String encryptParameter = args.getString(0);
            // 调用加密接口
            this.Encrypt(encryptParameter, callbackContext);
        }
        return false;
    }

//     public static String extractContent( Multipart multipart) throws MessagingException, IOException {
//	 	String ret = "";
//         String MULTIPART_MIME_TYPE = "multipart/";
//	 	for (int it = 0; it < multipart.getCount(); it++) {
//	 		final BodyPart bp = multipart.getBodyPart(it);
//	 		if ((ret == null || ret.isEmpty())
//	 				&& bp.getContentType().toLowerCase().startsWith("text/plain")) {
//	 			ret = String.format("<pre>%s</pre>", StringEscapeUtils.escapeHtml4(bp.getContent().toString()));
//	 		}
//	 		if (bp.getContentType().toLowerCase().startsWith("text/html")) {
//	 			ret = (bp.getContent().toString());
//	 		}
//	 		if (bp.getContentType().toLowerCase().startsWith(MULTIPART_MIME_TYPE)) {
//	 			ret = extractContent((Multipart) bp.getContent());
//	 		}
//	 	}
//	 	return ret;
//	 }

    private void coolMethod(String message, CallbackContext callbackContext) {
        if (message != null && message.length() > 0) {

            String IbcServer = "192.168.30.147:443";
            Olym_Device_SecurityEngine olymDeviceSecurityEngine;

            try {
                Context context=this.cordova.getActivity().getApplicationContext();
            //设备参数初始化
            olymDeviceSecurityEngine = Olym_Device_SecurityEngine.getInstance();
            olymDeviceSecurityEngine.initSecurityEngineWithNtls(context);
            //设置IBC平台地址（私钥下载地址）
            olymDeviceSecurityEngine.setIBCServer(IbcServer);

            boolean isUserExit = false;
            //检查是否用户私钥存在在设备上上
            String[] users = olymDeviceSecurityEngine.enumUsers();
            for (String user : users){
                if(user.toUpperCase().equals(user.toUpperCase())){
                    isUserExit = true;
                    break;
                }
            }
            if (isUserExit) {
                //存在密钥
            } else {
                //不存在此密钥
            }

            int ret = -1;
            ret = olymDeviceSecurityEngine.loginLocalDeviceMultiEx("6580440@qq.com", "admin123", "", 1);
            if(ret >= 0) { 
                
            }
            else {
                callbackContext.error(ret);
            }
            
            // if(ret) {
            //     callbackContext.error(ret);
            // }else if() {
            //     callbackContext.error(e);
            // }else {
            //     callbackContext.error(e);
            // }
            // olymCipherSecurityEngine = Olym_Cipher_SecurityEngine.getInstance();

            } catch (SecEngineException e) {

            }
            callbackContext.success(message);
        } else {

            callbackContext.error("Expected one non-empty string argument.");
            
        }
    }

    private Olym_Device_SecurityEngine ConnectIbcServer(String IbcServerAddr) {

        Olym_Device_SecurityEngine olymDeviceSecurityEngine;

        try {
            Context context=this.cordova.getActivity().getApplicationContext();
            //设备参数初始化
            olymDeviceSecurityEngine = Olym_Device_SecurityEngine.getInstance();
            olymDeviceSecurityEngine.initSecurityEngineWithNtls(context);
            //设置IBC平台地址（私钥下载地址）
            olymDeviceSecurityEngine.setIBCServer(IbcServerAddr);

            boolean isUserExit = false;
            //检查是否用户私钥存在在设备上上
            String[] users = olymDeviceSecurityEngine.enumUsers();
            for (String user : users){
                if(user.toUpperCase().equals(user.toUpperCase())){
                    isUserExit = true;
                    break;
                }
            }
            if (isUserExit) {
                //存在密钥
            } else {
                //不存在此密钥
            }
            return olymDeviceSecurityEngine;
        // int ret = -1;
        // ret = olymDeviceSecurityEngine.loginLocalDeviceMultiEx("6580440@qq.com", "admin123", "", 1);
        // callbackContext.error(ret);
        // if(ret) {
        //     callbackContext.error(ret);
        // }else if() {
        //     callbackContext.error(e);
        // }else {
        //     callbackContext.error(e);
        // }
        // olymCipherSecurityEngine = Olym_Cipher_SecurityEngine.getInstance();
        } catch (SecEngineException e){
            return null;
        }
    }

    private void Decrypt(String decryptParameter, CallbackContext callbackContext) {

        // String IbcServer = "60.205.94.181:443";
        //userId="6580440@qq.com", pwd="admin123"
        // "postmaster@mail.example.com" "00000000"
        String IbcServer ="192.168.30.147:443";
        
        try {
            com.alibaba.fastjson.JSONObject jsonDecrypt = com.alibaba.fastjson.JSONObject.parseObject(decryptParameter);
             String strUserId = jsonDecrypt.getString("userId");
             String strPwd = jsonDecrypt.getString("pwd");
             String strFolderId = jsonDecrypt.getString("folderId");
             String strMessageId = jsonDecrypt.getString("messageId");
             String strHeaderSalt = jsonDecrypt.getString("headerSalt");
             String strHeaderCredentials = jsonDecrypt.getString("headerCredentials");
            // connect IBC server
            Olym_Device_SecurityEngine m_DeviceSecurityEngine = ConnectIbcServer(IbcServer);
            // Login Device
            int ret = -1;
            
            ret = m_DeviceSecurityEngine.loginLocalDeviceMultiEx("postmaster@mail.example.com", "00000000", "", 1);
            if(ret >= 0) {
                
                //  download path:  /storage/emulated/0/Android/data/com.fudiansoft.mail/files/  EncryptTemp.eml
                Context context=this.cordova.getActivity().getApplicationContext();
                String AppPath = context.getExternalFilesDir(null).getAbsolutePath();
                File directory_encryptTemp = new File(AppPath + "/EncryptTemp.eml");
                //String url = "http://192.168.30.234:8080/api/v1/folders/aW1hcHM6Ly9wb3N0bWFzdGVyJTQwbWFpbC5leGFtcGxlLmNvbUAxOTIuMTY4LjMwLjE0OTo5OTMvVHJhc2g=/messages/373";
                // "Isotope-Salt", "0a046c264e1dbcde"   Isotope-Credentials", "6e688732c78e53799ba93fc24f5f5741293d47d173bb55d4f22fa817ef8c049c8ff3df80379f44f788bca162c03d08d986e03c39a5ba6823bf232ff22113752a05f29c76a8a9c209dd2fac5fd0c8edf96e38f6cf52a9fe6db7d3fb35b853df069f27d41a7b7930a3f576b1e048ff1ee26765e9ed81c8b245e845b6ce0caaa3a8c383d9ba38a61262addf1ca4e1d4bce9fd63b7e19937dc319ecbcd16fd8718ad376db87207e489a8288eecc7f6bc650ef7aa8cdef94714db20ae954350560b3c8270869694c7c72a99c4625a4e762ad387d9cfec02c4523771cae787ad18708b870885980b2dba1105bb002ba3b670462b654998dab25aad239b9adc77e8a7c322c6a6c2660411d4f92b17f699ab92ef45232cb9bbbdf81126689af646179eb9b8d24da644435f8ed5135ad58637a065d66f1f52a0f393ead198e59158ee1bc63b697913d0a533a99d6500d5d1c730427c94f04ab786664fc82450227d67b78c7a2ff6c2debb416c654dfa8cc3d24408d169dcbe865616c3a8e9829a87b59df7694eb4e0408021f55e7a014745f5fac4"
                String url = "http://192.168.30.234:8080/api/v1/folders/" + strFolderId + "/messages/" + strMessageId;
                OkHttpClient client = new OkHttpClient.Builder().readTimeout(5, TimeUnit.SECONDS).build();
                Request request = new Request.Builder().url(url).addHeader("Accept", "message/rfc822").addHeader("Isotope-Salt", strHeaderSalt)
                        .addHeader("Isotope-Credentials", strHeaderCredentials)
                        .get().build();
                Call call = client.newCall(request);
                Response response = call.execute();
 //System.out.println(response.body().bytes());
                byte[] bs = response.body().bytes();
                OutputStream out = new FileOutputStream(directory_encryptTemp.getAbsolutePath());
                InputStream is = new ByteArrayInputStream(bs);
                byte[] buff = new byte[1024];
                int len = 0;
                while((len=is.read(buff))!=-1){
                    out.write(buff, 0, len);
                }
                is.close();
                out.close();

                // 获取解密单实例，调用解密SDK
                Olym_Cipher_SecurityEngine olymCipherSecurityEngine = Olym_Cipher_SecurityEngine.getInstance();
                String strSign = olymCipherSecurityEngine.decryptSignMailFile(directory_encryptTemp.getAbsolutePath(), AppPath+ "/decryptTempFile.eml");
                Log.d("decryptSign", strSign);

                // 将解密后的eml文件转换成JSON串，回传给detail界面用于明文展示
                try{
                    File file = new File(AppPath+ "/decryptTempFile.eml");
//                    MimeMessage mimeMessageEn = MimeMessageUtils.createMimeMessage(null, file);

                     InputStream inputStream = new FileInputStream(AppPath+ "/decryptTempFile.eml");
                     BufferedInputStream bis = new BufferedInputStream(inputStream);
                     ByteArrayOutputStream bos = new ByteArrayOutputStream();
                     int date = -1;
                     while ((date = bis.read()) != -1) {
                         bos.write(date);
                     }
                     byte[] bytes = bos.toByteArray();
                     InputStream sbs = new ByteArrayInputStream(bytes);
                     Properties props = new Properties();
                     Session session = Session.getDefaultInstance(props, null);
                     InputStream inMsg = new ByteArrayInputStream(bytes);
                     MimeMessage mimeMessageEn = new MimeMessage(session, inMsg);
                     MessageMail message = new MessageMail();
                    final Object content = mimeMessageEn.getContent();
                     if (content instanceof Multipart) {
                         message.setContent(extractContent((Multipart) content));
                         //TODO:附件未处理
                     } else if (content instanceof MimeMessage
                             && ((MimeMessage) content).getContentType().toLowerCase().contains("html")) {
                         message.setContent(content.toString());
                     } else if (mimeMessageEn.getContentType().indexOf("text/html") == 0){
                         message.setContent(content.toString());
                     } else {
                         //Preserve formatting
                         message.setContent(content.toString()
                                 .replace("\r\n", "<br />" )
                                 .replaceAll("[\\r\\n]", "<br />"));
                     }
			        
                    try
                    {
                        // 设置联系人列表
                        javax.mail.Address[] toList = mimeMessageEn.getAllRecipients();
//                        List<Address> ccList = parser.getCc();
//                        List<Address> bccList = parser.getBcc();
                        List<Recipient> sendList = new ArrayList<>();
                        for(int i=0; i<toList.length; i++) {
                            Recipient toRecipient = new Recipient("To", (toList[i]).toString());
                            sendList.add(toRecipient);
                        }
                        message.setRecipients(sendList);

                        message.setSubject(mimeMessageEn.getSubject());
                        
                        String jsonMessage = com.alibaba.fastjson.JSONObject.toJSON(message).toString();
                        
                        // String jsonString = JSONObject.toJSONString(message);
                        // System.out.println(jsonString);

                        callbackContext.success(jsonMessage);
                    }
                    catch ( Exception e)
                    {
                        callbackContext.error("parser Error");
                    }
                }
                catch (Exception e)
                {

                }
            }else {
                callbackContext.error("LoginLocalDevice false");
            }
        } catch (Exception e) {
            //callbackContext.error("SecEngineException error");
            Log.d("Decrypt", "error");
        }     
    }

    // 发送加密邮件
    private void Encrypt(String encryptParameter, CallbackContext callbackContext) {

        String IbcServer = "192.168.30.147:443";

        try{
            com.alibaba.fastjson.JSONObject jsonDecrypt = com.alibaba.fastjson.JSONObject.parseObject(encryptParameter);
            String strUserId = jsonDecrypt.getString("userId");
            String strPwd = jsonDecrypt.getString("pwd");
            String strMessage = jsonDecrypt.getString("message");
            //MessageMail messageMail = com.alibaba.fastjson.JSONObject.parseObject(strMessage, MessageMail.class);
            // 邮件格式转换
            MessageMail messageMail = new MessageMail();
            com.alibaba.fastjson.JSONObject jsonTempMsg = com.alibaba.fastjson.JSONObject.parseObject(strMessage);
            List<String> fromList = new ArrayList<>();
            fromList.add(strUserId);
            messageMail.setFrom(fromList);
            messageMail.setSubject(jsonTempMsg.getString("subject"));
            messageMail.setContent(jsonTempMsg.getString("content"));
            List<Recipient> recipientList = new ArrayList<>();
            com.alibaba.fastjson.JSONArray jsonRecipients = jsonTempMsg.getJSONArray("recipients");

            for(int i=0; i<jsonRecipients.size(); i++) {
                com.alibaba.fastjson.JSONObject obj = jsonRecipients.getJSONObject(i);
                String type = obj.getString("type");
                String address = obj.getString("address");
                Recipient recipient = new Recipient(type, address);
                recipientList.add(recipient);
            }
            messageMail.setRecipients(recipientList);
            List<String> replyToList = new ArrayList<>();
            replyToList.add("");
            messageMail.setReplyTo(replyToList);
            List<String> referenceList = new ArrayList<>();
            referenceList.add("");
            messageMail.setReferences(referenceList);

            // 连接IBC平台
            Olym_Device_SecurityEngine m_DeviceSecurityEngine = ConnectIbcServer(IbcServer);
            int ret = -1;
            // 用户密码登录
            ret = m_DeviceSecurityEngine.loginLocalDeviceMultiEx("postmaster@mail.example.com", "00000000", "", 1);
            if(ret >= 0) {
                Context context=this.cordova.getActivity().getApplicationContext();
                String AppPath = context.getExternalFilesDir(null).getAbsolutePath();
                // 将邮件内容转换成eml文件格式
                transform(messageMail, AppPath + "/mail.eml", strUserId);
                // 获取解密单实例，调用加密SDK  Flag=3: P7格式无签名，非ZDM格式加密
                Olym_Cipher_SecurityEngine olymCipherSecurityEngine = Olym_Cipher_SecurityEngine.getInstance();
                olymCipherSecurityEngine.encryptSignMailFile(AppPath + "/mail.eml", SecurityEngine.PKCS7_ENVELOPED_DATA, AppPath + "/encryptMail.eml", "");

                // 发送加密邮件到服务器
                SendEncryptMessage(AppPath+"/encryptMail.eml");

                callbackContext.success("success");
            }else {
                callbackContext.error("Encrypt Login failed");
            }
        }catch( SecEngineException see){
            callbackContext.error("Encrypt Error");
        }
        catch (Exception e){
            callbackContext.error("Encrypt Error");
        }
    }


}
