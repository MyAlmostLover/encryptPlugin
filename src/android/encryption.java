package cordova.encryption;

import android.content.Context;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.nisc.Olym_CrossDomain_SecurityEngine;
import com.nisc.Olym_Device_SecurityEngine;
import com.nisc.SecurityEngine;
import com.nisc.SecurityEngineAlg;
import com.nisc.api.SecEngineException;


/**
 * This class echoes a string called from JavaScript.
 */
public class encryption extends CordovaPlugin {

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if (action.equals("coolMethod")) {
            String message = args.getString(0);
            this.coolMethod(message, callbackContext);
            return true;
        }
        return false;
    }

    private void coolMethod(String message, CallbackContext callbackContext) {
        if (message != null && message.length() > 0) {

            String IbcServer = "60.205.94.181:443";
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
            callbackContext.error(ret);
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
}
