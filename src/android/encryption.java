package cordova.encryption;

import android.content.Context;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;

import org.apache.cordova.PluginResult;
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
import com.sun.mail.imap.IMAPFolder;
import com.sun.mail.imap.IMAPMessage;
import com.sun.mail.util.BASE64DecoderStream;
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
import javax.mail.internet.MimeUtility;
import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.mail.util.ByteArrayDataSource;
import android.util.Base64;

import static javax.mail.Folder.READ_ONLY;

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
    private static final long EMBEDDED_IMAGE_SIZE_THRESHOLD_DEFAULT_50KB = 51200L;
    private static final int DEFAULT_BUFFER_SIZE = 1024 * 4;
    public static final int EOF = -1;
    static final byte[] CHUNK_SEPARATOR = {'\r', '\n'};

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

    private static MimeBodyPart toBodyPart( Attachment attachment)
            throws MessagingException, IOException {

        final MimeBodyPart mimeAttachment = new MimeBodyPart();
        mimeAttachment.setDisposition(MimeBodyPart.ATTACHMENT);
        final String mimeType = attachment.getContentType() != null && !attachment.getContentType().isEmpty() ?
                attachment.getContentType() : "application/octet-stream";
        final DataSource dataSource;
        if (attachment.getContent() != null) {
            dataSource = new ByteArrayDataSource(attachment.getContent(), mimeType);
            mimeAttachment.setDataHandler(new DataHandler(dataSource));
            mimeAttachment.setFileName(MimeUtility.encodeText(attachment.getFileName()));
        }
        else {
            //处理URL
            if(attachment.get_links() != null){
                com.alibaba.fastjson.JSONObject jsonLinks = com.alibaba.fastjson.JSONObject.parseObject(attachment.get_links());
                String downloadPath = jsonLinks.getJSONObject("download").getString("href");
                if(downloadPath.startsWith("http")){
                    // 服务器连接，需要获取附件
                    OkHttpClient client = new OkHttpClient.Builder().readTimeout(20, TimeUnit.SECONDS).build();
                    MediaType JSON = MediaType.parse("application/json; charset=utf-8");
                    //RequestBody body = RequestBody.create(JSON, jsonObject.toJSONString());
                    Request request = new Request.Builder().url(downloadPath).addHeader("Isotope-Salt", "9f18db035e3c1c28")
                            .addHeader("Isotope-Credentials", "4de62c9072b47359e6aa0dd4489f0650eaa35188d71d15d6dfece9561aa32104e8e0a3604e4c262edc6fc739f315ec7b93cab8e20d4a93753dfb783bba6aa034e1559a3e13a7a77b141de3833c264efef3a71ed00f565dc11da47e5130f6413f5ea14f4a3a6b97bca1e86edf0fb58973b63e8805dd77b18411bbf64e58b607536507582cc3c62c4fdc78ae5cd0143f5960f0b3fb8371223fcee8b1f86f0267338ce9a2541b5ac04ecf987ff778f1bf6c5c4af8e820e8a00e106138cbe34d2284328ed1111b138b84f9c9f97e7191147709bea0b91cfff975288962cfb17ac65e7aa5289d1b764977437e52054f08644615e36cec47459970c38564bfd2e1312c2a6b6c9abf74744faa0972901e2fe8547ba2cf5a79d1605e6f5acf7fac68bac3a2ddeb6dba56faff5fa58bf53ea6028a5c50f684baa426d862a5c89897ed742d37be8843185c981e0cb0f4d89c98f3940f236e1284e885ef4206ce72de81a8f433f614fd1c56e3620a53169120002769af866dc5b85e849c32aacbd3706b998e31b6216a46565631d736601e8fce58ed")
                            //.post(body).build();
                            .build();
                    Call call = client.newCall(request);
                    try {
                        Response response = call.execute();
                        System.out.println(response.body().toString());
                        // 将返回的附件数据设置到mimeAttachment结构中
                        dataSource = new ByteArrayDataSource(response.body().bytes(), mimeType);
                        mimeAttachment.setDataHandler(new DataHandler(dataSource));
                        mimeAttachment.setFileName(MimeUtility.encodeText(attachment.getFileName()));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }else if(downloadPath.startsWith("/storage")){
                    // 本地连接，从本地存储路径读取数据
                    File file = new File(downloadPath);
                    if (file.exists()) {
                        InputStream inputStream = new FileInputStream(downloadPath);
                        BufferedInputStream bis = new BufferedInputStream(inputStream);
                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        int date = -1;
                        while ((date = bis.read()) != -1) {
                            bos.write(date);
                        }
                        byte[] bytes = bos.toByteArray();
                        // 将返回的附件数据设置到mimeAttachment结构中
                        dataSource = new ByteArrayDataSource(bytes, mimeType);
                        mimeAttachment.setDataHandler(new DataHandler(dataSource));
                        mimeAttachment.setFileName(MimeUtility.encodeText(attachment.getFileName()));
                    }
                }else{
                    // TODO: 未知连接
                    Log.d("未知连接", downloadPath);
                }
            }
        }

        return mimeAttachment;
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

            // Include attachments
            if (message.getAttachments() != null && !message.getAttachments().isEmpty()) {
                for (Attachment attachment : message.getAttachments()) {
                    multipart.addBodyPart(toBodyPart(attachment));
                }
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

    public static void SendEncryptMessage(String plainFilename, String strHeaderSalt, String strHeaderCredentials) throws FileNotFoundException, MessagingException, IOException
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


        String url = "http://192.168.30.234:81/api/v1/smtp/sendencrypt";
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
//        Request request = new Request.Builder().url(url).addHeader("Isotope-Salt", "9f18db035e3c1c28")
//                .addHeader("Isotope-Credentials", "4de62c9072b47359e6aa0dd4489f0650eaa35188d71d15d6dfece9561aa32104e8e0a3604e4c262edc6fc739f315ec7b93cab8e20d4a93753dfb783bba6aa034e1559a3e13a7a77b141de3833c264efef3a71ed00f565dc11da47e5130f6413f5ea14f4a3a6b97bca1e86edf0fb58973b63e8805dd77b18411bbf64e58b607536507582cc3c62c4fdc78ae5cd0143f5960f0b3fb8371223fcee8b1f86f0267338ce9a2541b5ac04ecf987ff778f1bf6c5c4af8e820e8a00e106138cbe34d2284328ed1111b138b84f9c9f97e7191147709bea0b91cfff975288962cfb17ac65e7aa5289d1b764977437e52054f08644615e36cec47459970c38564bfd2e1312c2a6b6c9abf74744faa0972901e2fe8547ba2cf5a79d1605e6f5acf7fac68bac3a2ddeb6dba56faff5fa58bf53ea6028a5c50f684baa426d862a5c89897ed742d37be8843185c981e0cb0f4d89c98f3940f236e1284e885ef4206ce72de81a8f433f614fd1c56e3620a53169120002769af866dc5b85e849c32aacbd3706b998e31b6216a46565631d736601e8fce58ed")
//                .post(body).build();
        Request request = new Request.Builder().url(url).addHeader("Isotope-Salt", strHeaderSalt)
                .addHeader("Isotope-Credentials", strHeaderCredentials)
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
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    callbackContext.sendPluginResult(Decrypt(args));
                }
            });
//            String decryptParameter = args.getString(0);
//            this.Decrypt(decryptParameter, callbackContext);
            return true;
        }else if(action.equals("Encrypt")) {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    callbackContext.sendPluginResult(Encrypt(args));
                }
            });
            return true;
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

    public static boolean isContainAttachment(Part part) throws MessagingException, IOException {
        boolean flag = false;
        if (part.isMimeType("multipart/*")) {
            MimeMultipart multipart = (MimeMultipart) part.getContent();
            int partCount = multipart.getCount();
            for (int i = 0; i < partCount; i++) {
                BodyPart bodyPart = multipart.getBodyPart(i);
                String disp = bodyPart.getDisposition();
                if (disp != null && (disp.equalsIgnoreCase(Part.ATTACHMENT) || disp.equalsIgnoreCase(Part.INLINE))) {
                    flag = true;
                } else if (bodyPart.isMimeType("multipart/*")) {
                    flag = isContainAttachment(bodyPart);
                } else {
                    String contentType = bodyPart.getContentType();
                    if (contentType.indexOf("application") != -1) {
                        flag = true;
                    }

                    if (contentType.indexOf("name") != -1) {
                        flag = true;
                    }
                }

                if (flag) break;
            }
        } else if (part.isMimeType("message/rfc822")) {
            flag = isContainAttachment((Part)part.getContent());
        }
        return flag;
    }

    // 文本解码
    public static String decodeText(String encodeText) throws UnsupportedEncodingException {
        if (encodeText == null || "".equals(encodeText)) {
            return "";
        } else {
            return MimeUtility.decodeText(encodeText);
        }
    }

    // 保存流数据到指定目录
    private static void saveFile(InputStream is, String destDir, String fileName) throws FileNotFoundException, IOException {
        BufferedInputStream bis = new BufferedInputStream(is);
        BufferedOutputStream bos = new BufferedOutputStream(
                new FileOutputStream(new File(destDir + fileName)));
        int len = -1;
        while ((len = bis.read()) != -1) {
            bos.write(len);
            bos.flush();
        }
        bos.close();
        bis.close();
    }

    // 保存附件
//    public static void saveAttachment(Part part, String destDir, List<Attachment> attachments) throws UnsupportedEncodingException, MessagingException,
//            FileNotFoundException, IOException {
//        if (part.isMimeType("multipart/*")) {
//            Multipart multipart = (Multipart) part.getContent();    //复杂体邮件
//            //复杂体邮件包含多个邮件体
//            int partCount = multipart.getCount();
//            for (int i = 0; i < partCount; i++) {
//                //获得复杂体邮件中其中一个邮件体
//                BodyPart bodyPart = multipart.getBodyPart(i);
//                //某一个邮件体也有可能是由多个邮件体组成的复杂体
//                String disp = bodyPart.getDisposition();
//                if (disp != null && (disp.equalsIgnoreCase(Part.ATTACHMENT) || disp.equalsIgnoreCase(Part.INLINE))) {
//                    //InputStream is = bodyPart.getInputStream();
//                    //saveFile(is, destDir, decodeText(bodyPart.getFileName()));
////                    JSONObject attachmentJson = com.alibaba.fastjson.JSONObject.parseObject(disp);
//                    Attachment attachment = new Attachment();
//                    attachment.setContentId(String.valueOf(i));
//                    attachment.setContentType(bodyPart.getContentType());
//                    attachment.setFileName(decodeText(bodyPart.getFileName()));
//                    attachment.set_links(destDir + decodeText(bodyPart.getFileName()));
//                    String type = "UTF-8";
//                    String strType = bodyPart.getContentType();
//                    String[] typeParaList = strType.split(";");
//                    if(typeParaList.length >= 2){
//                        String[] typeList = typeParaList[1].split("=");
//                        if(typeList.length >= 2) {
//                            type = typeList[1];
//                        }
//                    }
////                    attachment.setContent(Base64.encodeToString(bodyPart.getContent().toString().getBytes(type), Base64.DEFAULT));
//                    attachment.setSize(Base64.encode(bodyPart.getContent().toString().getBytes(), Base64.DEFAULT).length);
//                    attachments.add(attachment);
//                } else if (bodyPart.isMimeType("multipart/*")) {
//                    saveAttachment(bodyPart,destDir, attachments);
//                } else {
//                    String contentType = bodyPart.getContentType();
//                    if (contentType.indexOf("name") != -1 || contentType.indexOf("application") != -1) {
//                        //saveFile(bodyPart.getInputStream(), destDir, decodeText(bodyPart.getFileName()));
//                        Attachment attachment = new Attachment();
//                        attachment.setContentId(String.valueOf(i));
//                        attachment.setContentType(bodyPart.getContentType());
//                        attachment.setFileName(decodeText(bodyPart.getFileName()));
//                        attachment.set_links(destDir + decodeText(bodyPart.getFileName()));
////                        attachment.setContent(Base64.encodeToString(bodyPart.getContent().toString().getBytes(), Base64.DEFAULT));
//                        attachment.setSize(bodyPart.getSize());
//                        attachments.add(attachment);
//                    }
//                }
//            }
//        } else if (part.isMimeType("message/rfc822")) {
//            saveAttachment((Part) part.getContent(),destDir, attachments);
//        }
//    }

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

    private static BodyPart extractEmbeddedBodypart(Multipart multipart, String contentId)
            throws MessagingException, IOException {

        for (int it = 0; it < multipart.getCount(); it++) {
            final BodyPart bp = multipart.getBodyPart(it);
            if (bp.getContentType().toLowerCase().startsWith(MULTIPART_MIME_TYPE)) {
                final BodyPart nestedBodyPart = extractEmbeddedBodypart((Multipart) bp.getContent(), contentId);
                if (nestedBodyPart != null){
                    return nestedBodyPart;
                }
            }
            if (bp.getContentType().toLowerCase().startsWith("image/") && bp instanceof MimeBodyPart
                    && contentId.equals(((MimeBodyPart) bp).getContentID())) {
                return bp;
            }
        }
        return null;
    }

    private static BodyPart extractAttachmentBodypart(Multipart multipart, String id)
            throws MessagingException, IOException {

        for (int it = 0; it < multipart.getCount(); it++) {
            final BodyPart bp = multipart.getBodyPart(it);
            if (bp.getDisposition() != null && Part.ATTACHMENT.equalsIgnoreCase(bp.getDisposition())) {
                // Regular file
                if (id.equals(MimeUtility.decodeText(bp.getFileName()))) {
                    return bp;
                }
                // Embedded message
                if(bp.getContentType().toLowerCase().startsWith("message/") && bp.getContent() instanceof MimeMessage
                        && ((MimeMessage)bp.getContent()).getSubject().equals(id)) {
                    return bp;
                }
            }
        }
        return null;
    }

    public static BodyPart extractBodypart(Multipart mp, String id, Boolean contentId)
            throws MessagingException, IOException {

        return Boolean.TRUE.equals(contentId) ?
                extractEmbeddedBodypart(mp, id) : // Embedded contentId
                extractAttachmentBodypart(mp, id); // Attachment
    }

    public static long copyLarge(final InputStream input, final OutputStream output)
            throws IOException {
        return copy(input, output, DEFAULT_BUFFER_SIZE);
    }

    public static long copyLarge(final InputStream input, final OutputStream output, final byte[] buffer)
            throws IOException {
        long count = 0;
        int n;
        while (EOF != (n = input.read(buffer))) {
            output.write(buffer, 0, n);
            count += n;
        }
        return count;
    }

    public static int copy(final InputStream input, final OutputStream output) throws IOException {
        final long count = copyLarge(input, output);
        if (count > Integer.MAX_VALUE) {
            return -1;
        }
        return (int) count;
    }

    public static long copy(final InputStream input, final OutputStream output, final int bufferSize)
            throws IOException {
        return copyLarge(input, output, new byte[bufferSize]);
    }

    public static byte[] toByteArray(final InputStream input) throws IOException {
        try (final ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            copy(input, output);
            return output.toByteArray();
        }
    }

    public static String replaceEmbeddedImage(String content, MimeBodyPart imageBodyPart)
            throws MessagingException, IOException {

        final String cid = imageBodyPart.getContentID().replaceAll("[<>]", "");
        if (content != null && content.contains(cid)) {
            String contentType = imageBodyPart.getContentType();
            if (contentType.contains(";")) {
                contentType = contentType.substring(0, contentType.indexOf(';'));
            }

            final String base64 = Base64.encodeToString(toByteArray(imageBodyPart.getInputStream()), imageBodyPart.getSize())
                    .replace("\r", "").replace("\n", "");
            return content.replace("cid:" + cid,
                    String.format("data:%s;%s,%s",
                            contentType,
                            imageBodyPart.getEncoding(),
                            base64));
        }
        return content;
    }

    private List<Attachment> extractAttachments(
            MessageMail finalMessage, Multipart mp, List<Attachment> attachments)
            throws MessagingException, IOException {

        if (attachments == null){
            attachments = new ArrayList<>();
        }
        for (int it = 0; it < mp.getCount(); it++) {
            final BodyPart bp = mp.getBodyPart(it);
            // Multipart message with embedded parts
            if (bp.getContentType().toLowerCase().startsWith(MULTIPART_MIME_TYPE)) {
                extractAttachments(finalMessage, (Multipart) bp.getContent(), attachments);
            }
            // Image attachments
            else if (bp.getContentType().toLowerCase().startsWith("image/")
                    && bp instanceof MimeBodyPart
                    && ((MimeBodyPart) bp).getContentID() != null) {
                // If image is "not too big" embed as base64 data uri - successive IMAP connections will be more expensive
                if (bp.getSize() <= EMBEDDED_IMAGE_SIZE_THRESHOLD_DEFAULT_50KB) {
                    finalMessage.setContent(replaceEmbeddedImage(finalMessage.getContent(), (MimeBodyPart)bp));
                } else {
                    attachments.add(new Attachment(
                            ((MimeBodyPart) bp).getContentID(), bp.getFileName(), bp.getContentType(), bp.getSize()));
                }
            }
            // Embedded messages
            else if (bp.getContentType().toLowerCase().startsWith("message/")) {
                final Object nestedMessage = bp.getContent();
                if (nestedMessage instanceof MimeMessage) {
                    attachments.add(new Attachment(null, ((MimeMessage)nestedMessage).getSubject(),
                            bp.getContentType(), ((MimeMessage)nestedMessage).getSize()));
                }
            }
            // Regular files
            else if (bp.getDisposition() != null && bp.getDisposition().equalsIgnoreCase(Part.ATTACHMENT)) {
                attachments.add(new Attachment(
                        null, MimeUtility.decodeText(bp.getFileName()), bp.getContentType(), bp.getSize()));
            }
        }
        return attachments;
    }
    private PluginResult Decrypt(org.json.JSONArray args){
        // String IbcServer = "60.205.94.181:443";
        //userId="6580440@qq.com", pwd="admin123"
        // "postmaster@mail.example.com" "00000000"
        String IbcServer ="192.168.30.147:443";
        Log.d("Decrypt start", String.valueOf(System.currentTimeMillis()));
        try {
            com.alibaba.fastjson.JSONObject jsonDecrypt = com.alibaba.fastjson.JSONObject.parseObject(args.getString(0));
             String strUserId = jsonDecrypt.getString("userId");
             String strPwd = jsonDecrypt.getString("pwd");
             String strFolderId = jsonDecrypt.getString("folderId");
             String strMessageId = jsonDecrypt.getString("messageId");
             String strHeaderSalt = jsonDecrypt.getString("headerSalt");
             String strHeaderCredentials = jsonDecrypt.getString("headerCredentials");
            // connect IBC server
            Log.d("Decrypt ConnectIbcServer start", String.valueOf(System.currentTimeMillis()));
            Olym_Device_SecurityEngine m_DeviceSecurityEngine = ConnectIbcServer(IbcServer);
            Log.d("Decrypt ConnectIbcServer end", String.valueOf(System.currentTimeMillis()));
            // Login Device
            int ret = -1;
            Log.d("Decrypt LonginDev start", String.valueOf(System.currentTimeMillis()));
            ret = m_DeviceSecurityEngine.loginLocalDeviceMultiEx(strUserId, "00000000", "", 1);
            Log.d("Decrypt LonginDev end", String.valueOf(System.currentTimeMillis()));
            if(ret >= 0) {
                Log.d("Decrypt download eml start", String.valueOf(System.currentTimeMillis()));
                //  download path:  /storage/emulated/0/Android/data/com.fudiansoft.mail/files/  EncryptTemp.eml
                Context context=this.cordova.getActivity().getApplicationContext();
                String AppPath = context.getExternalFilesDir(null).getAbsolutePath();
                File directory_encryptTemp = new File(AppPath + "/EncryptTemp.eml");
                //String url = "http://192.168.30.234:81/api/v1/folders/aW1hcHM6Ly9wb3N0bWFzdGVyJTQwbWFpbC5leGFtcGxlLmNvbUAxOTIuMTY4LjMwLjE0OTo5OTMvVHJhc2g=/messages/373";
                // "Isotope-Salt", "0a046c264e1dbcde"   Isotope-Credentials", "6e688732c78e53799ba93fc24f5f5741293d47d173bb55d4f22fa817ef8c049c8ff3df80379f44f788bca162c03d08d986e03c39a5ba6823bf232ff22113752a05f29c76a8a9c209dd2fac5fd0c8edf96e38f6cf52a9fe6db7d3fb35b853df069f27d41a7b7930a3f576b1e048ff1ee26765e9ed81c8b245e845b6ce0caaa3a8c383d9ba38a61262addf1ca4e1d4bce9fd63b7e19937dc319ecbcd16fd8718ad376db87207e489a8288eecc7f6bc650ef7aa8cdef94714db20ae954350560b3c8270869694c7c72a99c4625a4e762ad387d9cfec02c4523771cae787ad18708b870885980b2dba1105bb002ba3b670462b654998dab25aad239b9adc77e8a7c322c6a6c2660411d4f92b17f699ab92ef45232cb9bbbdf81126689af646179eb9b8d24da644435f8ed5135ad58637a065d66f1f52a0f393ead198e59158ee1bc63b697913d0a533a99d6500d5d1c730427c94f04ab786664fc82450227d67b78c7a2ff6c2debb416c654dfa8cc3d24408d169dcbe865616c3a8e9829a87b59df7694eb4e0408021f55e7a014745f5fac4"
                String url = "http://192.168.30.234:81/api/v1/folders/" + strFolderId + "/messages/" + strMessageId;
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
                Log.d("Decrypt download eml end", String.valueOf(System.currentTimeMillis()));
                // 获取解密单实例，调用解密SDK
                Log.d("Decrypt ecryptSignMailFile start", String.valueOf(System.currentTimeMillis()));
                Olym_Cipher_SecurityEngine olymCipherSecurityEngine = Olym_Cipher_SecurityEngine.getInstance();
                String strSign = olymCipherSecurityEngine.decryptSignMailFile(directory_encryptTemp.getAbsolutePath(), AppPath+ "/decryptTempFile.eml");
                Log.d("Decrypt ecryptSignMailFile end", String.valueOf(System.currentTimeMillis()));
                // 将解密后的eml文件转换成JSON串，回传给detail界面用于明文展示
                try{
                    Log.d("Decrypt MailtoJson start", String.valueOf(System.currentTimeMillis()));
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

//                     MessageMail messageMail = MessageMail.from()
//                    MessageMail message = new MessageMail();
                    // 从当前所有信息中获取信封展示内容
                    MessageMail messageView = MessageMail.from(mimeMessageEn);

                    final Object content = mimeMessageEn.getContent();
                     if (content instanceof Multipart) {
                         // 解析并设置邮件正文内容
                         messageView.setContent(extractContent((Multipart) content));
                         // 如果有附件
                         boolean isContainerAttachment = isContainAttachment(mimeMessageEn);
                         if(isContainerAttachment){
                            // 解析JSON
                             messageView.setAttachments(extractAttachments(messageView, (Multipart) content, null));
                             // 存文件
                             for (Attachment itemAttachment:messageView.getAttachments()) {
                                 boolean isContentId = itemAttachment.getContentId() != null && !itemAttachment.getContentId().isEmpty();
                                 final BodyPart bp = extractBodypart((Multipart)content, decodeText(itemAttachment.getFileName()), isContentId);
                                 if (bp != null) {
                                     String filePath = AppPath + "/" + decodeText(bp.getFileName());
                                     com.alibaba.fastjson.JSONObject jsonHref = new com.alibaba.fastjson.JSONObject();
                                     com.alibaba.fastjson.JSONObject jsonDownload = new com.alibaba.fastjson.JSONObject();
                                     //com.alibaba.fastjson.JSONObject jsonLinks = new com.alibaba.fastjson.JSONObject();
                                     jsonHref.put("href", filePath);
                                     jsonDownload.put("download", jsonHref);
//                                     jsonLinks.put("links", jsonDownload);
                                     itemAttachment.set_links(jsonDownload.toJSONString());
                                     FileOutputStream  fps = new FileOutputStream(filePath);
                                     bp.getDataHandler().writeTo(fps);
                                     fps.flush();
                                     fps.close();
                                 } else {
                                     // todo 附件内容未找到
                                 }
                             }

                         }
                         //ToDO: save attachments修改
//                         List<Attachment> attachments = new ArrayList<>();
//                         if (isContainerAttachment) {
//                             saveAttachment(mimeMessageEn, AppPath + "/", attachments); //保存附件
//                             messageView.setAttachments(attachments);
//                         }else {
//                             messageView.setAttachments(attachments);
//                         }
                     } else if (content instanceof MimeMessage
                             && ((MimeMessage) content).getContentType().toLowerCase().contains("html")) {
                         messageView.setContent(content.toString());
                     } else if (mimeMessageEn.getContentType().indexOf("text/html") == 0){
                         messageView.setContent(content.toString());
                     } else {
                         //Preserve formatting
                         messageView.setContent(content.toString()
                                 .replace("\r\n", "<br />" )
                                 .replaceAll("[\\r\\n]", "<br />"));
                     }
			        
                   try
                   {
                      // 设置联系人列表
//                        javax.mail.Address[] toList = mimeMessageEn.getAllRecipients();
////                        List<Address> ccList = parser.getCc();
////                        List<Address> bccList = parser.getBcc();
//                        List<Recipient> sendList = new ArrayList<>();
//                        for(int i=0; i<toList.length; i++) {
//                            Recipient toRecipient = new Recipient("To", (toList[i]).toString());
//                            sendList.add(toRecipient);
//                        }
//                       messageView.setRecipients(sendList);
//
//                       messageView.setSubject(mimeMessageEn.getSubject());
                        
                        String jsonMessage = com.alibaba.fastjson.JSONObject.toJSON(messageView).toString();
                        
                        // String jsonString = JSONObject.toJSONString(message);
                        // System.out.println(jsonString);
                       Log.d("Decrypt MailtoJson end", String.valueOf(System.currentTimeMillis()));
                       return new PluginResult(PluginResult.Status.OK, jsonMessage);
                       //callbackContext.success(jsonMessage);
                    }
                    catch ( Exception e)
                    {
                        return new PluginResult(PluginResult.Status.ERROR, e.toString());
                        //callbackContext.error("parser Error");
                    }
                }
                catch (Exception e)
                {
                    return new PluginResult(PluginResult.Status.ERROR, e.toString());
                }
            }else {
                return new PluginResult(PluginResult.Status.ERROR);
            }
        } catch (Exception e) {
            //callbackContext.error("SecEngineException error");
            return new PluginResult(PluginResult.Status.ERROR, e.toString());
        }     
    }

    // 发送加密邮件
    private PluginResult Encrypt(org.json.JSONArray args) {

        String IbcServer = "192.168.30.147:443";
        Log.d("Encrypt start", String.valueOf(System.currentTimeMillis()));
        try{
            com.alibaba.fastjson.JSONObject jsonDecrypt = com.alibaba.fastjson.JSONObject.parseObject(args.getString(0));
            String strUserId = jsonDecrypt.getString("userId");
            String strPwd = jsonDecrypt.getString("pwd");
            String strHeaderSalt = jsonDecrypt.getString("headerSalt");
            String strHeaderCredentials = jsonDecrypt.getString("headerCredentials");
            String strMessage = jsonDecrypt.getString("message");
            //MessageMail messageMail = com.alibaba.fastjson.JSONObject.parseObject(strMessage, MessageMail.class);
            // 邮件格式转换
           // MessageMail messageMail = new MessageMail();
            com.alibaba.fastjson.JSONObject jsonTempMsg = com.alibaba.fastjson.JSONObject.parseObject(strMessage);
            MessageMail messageMailView = jsonTempMsg.toJavaObject(MessageMail.class);
//            List<String> fromList = new ArrayList<>();
//            fromList.add(strUserId);
//            messageMail.setFrom(fromList);
//            messageMail.setSubject(jsonTempMsg.getString("subject"));
//            messageMail.setContent(jsonTempMsg.getString("content"));
//            List<Recipient> recipientList = new ArrayList<>();
//            com.alibaba.fastjson.JSONArray jsonRecipients = jsonTempMsg.getJSONArray("recipients");
//
//            for(int i=0; i<jsonRecipients.size(); i++) {
//                com.alibaba.fastjson.JSONObject obj = jsonRecipients.getJSONObject(i);
//                String type = obj.getString("type");
//                String address = obj.getString("address");
//                Recipient recipient = new Recipient(type, address);
//                recipientList.add(recipient);
//            }
//            messageMail.setRecipients(recipientList);
//            List<String> replyToList = new ArrayList<>();
//            replyToList.add("");
//            messageMail.setReplyTo(replyToList);
//            List<String> referenceList = new ArrayList<>();
//            referenceList.add("");
//            messageMail.setReferences(referenceList);
//            // 解析附件
//            com.alibaba.fastjson.JSONArray jsonAttachments = jsonTempMsg.getJSONArray("attachments");
//            List<Attachment> attachmentList = new ArrayList<>();
//            for(int i=0; i< jsonAttachments.size(); i++){
//                Attachment attachment = new Attachment();
//                com.alibaba.fastjson.JSONObject obj = jsonAttachments.getJSONObject(i);
//                attachment.setContentId(String.valueOf(i));
//                attachment.setFileName(obj.getString("fileName"));
//                attachment.setContentType(obj.getString("contentType"));
//                // 附件正文编码格式转换
////                attachment.setContent(obj.getString("content"));
//                attachment.setSize(obj.getIntValue("size"));
//                attachmentList.add(attachment);
//            }
//            messageMail.setAttachments(attachmentList);

            // 连接IBC平台
            Log.d("Encrypt ConnectIbcServer start", String.valueOf(System.currentTimeMillis()));
            Olym_Device_SecurityEngine m_DeviceSecurityEngine = ConnectIbcServer(IbcServer);
            Log.d("Encrypt ConnectIbcServer end", String.valueOf(System.currentTimeMillis()));
            int ret = -1;
            // 用户密码登录
            Log.d("Encrypt loginLocalDev start", String.valueOf(System.currentTimeMillis()));
            ret = m_DeviceSecurityEngine.loginLocalDeviceMultiEx(strUserId, "00000000", "", 1);
            Log.d("Encrypt loginLocalDev end", String.valueOf(System.currentTimeMillis()));
            if(ret >= 0) {
                Log.d("Encrypt transform start", String.valueOf(System.currentTimeMillis()));
                Context context=this.cordova.getActivity().getApplicationContext();
                String AppPath = context.getExternalFilesDir(null).getAbsolutePath();
                // 将邮件内容转换成eml文件格式
                transform(messageMailView, AppPath + "/mail.eml", strUserId);
                Log.d("Encrypt transform end", String.valueOf(System.currentTimeMillis()));
                // 获取解密单实例，调用加密SDK  Flag=3: P7格式无签名，非ZDM格式加密
                Log.d("Encrypt encryptSignMailFile start", String.valueOf(System.currentTimeMillis()));
                Olym_Cipher_SecurityEngine olymCipherSecurityEngine = Olym_Cipher_SecurityEngine.getInstance();
                olymCipherSecurityEngine.encryptSignMailFile(AppPath + "/mail.eml", SecurityEngine.PKCS7_ENVELOPED_DATA, AppPath + "/encryptMail.eml", "");
                Log.d("Encrypt encryptSignMailFile end", String.valueOf(System.currentTimeMillis()));

                // 发送加密邮件到服务器
                Log.d("Encrypt SendEncryptMessage start", String.valueOf(System.currentTimeMillis()));
                SendEncryptMessage(AppPath+"/encryptMail.eml", strHeaderSalt, strHeaderCredentials);
                Log.d("Encrypt SendEncryptMessage end", String.valueOf(System.currentTimeMillis()));
                return new PluginResult(PluginResult.Status.OK, "success");
            }else {
                return new PluginResult(PluginResult.Status.ERROR, "Encrypt Login failed");
            }
        }catch( SecEngineException see){
            return new PluginResult(PluginResult.Status.ERROR, "Encrypt Error");
        }
        catch (Exception e){
            return new PluginResult(PluginResult.Status.ERROR, "Encrypt Error");
        }
    }


}
