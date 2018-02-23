package com.wolf.q750hook;

import android.content.Context;
import android.os.Bundle;
import android.util.Log;

import java.lang.reflect.Field;
import java.util.HashMap;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * for mobile qq V750
 * Created by GreyWolf on 2018/2/21.
 */

public class Main implements IXposedHookLoadPackage {
    static final String MobileQQPN = "com.tencent.mobileqq";
    static final String LOGTAG = "qqhook";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (!loadPackageParam.packageName.equals(MobileQQPN)) {
            return;
        }
        log("Hook MobileQQ Successful!");

        XposedHelpers.findAndHookMethod("oicq.wlogin_sdk.tools.EcdhCrypt", loadPackageParam.classLoader, "GenECDHKeyEx",
                String.class, String.class, String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String p1 = (String) param.args[0];
                        String p2 = (String) param.args[1];
                        String p3 = (String) param.args[2];

                        log("GenECDHKeyEx Papam 1 len=" + p1.length() / 2 + ":" + (p1));
                        log("GenECDHKeyEx Papam 2 len=" + p2.length() / 2 + ":" + (p2));
                        log("GenECDHKeyEx Papam 3 len=" + p3.length() / 2 + ":" + (p3));
                    }
                });

        XposedHelpers.findAndHookMethod("oicq.wlogin_sdk.tools.EcdhCrypt", loadPackageParam.classLoader, "set_c_pri_key",
                byte[].class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        byte[] p1 = (byte[]) param.args[0];
                        log("set_c_pri_key Papam 1 len=" + p1.length + ":" + bytesToHex(p1));

                    }
                });
        XposedHelpers.findAndHookMethod("oicq.wlogin_sdk.tools.EcdhCrypt", loadPackageParam.classLoader, "set_c_pub_key",
                byte[].class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        byte[] p1 = (byte[]) param.args[0];
                        log("set_c_pub_key Papam 1 len=" + p1.length + ":" + bytesToHex(p1));

                    }
                });
        XposedHelpers.findAndHookMethod("oicq.wlogin_sdk.tools.EcdhCrypt", loadPackageParam.classLoader, "set_g_share_key",
                byte[].class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        byte[] p1 = (byte[]) param.args[0];
                        log("set_g_share_key Papam 1 len=" + p1.length + ":" + bytesToHex(p1));

                    }
                });


        //Hook Session key
        XposedHelpers.findAndHookMethod("oicq.wlogin_sdk.request.WloginAllSigInfo", loadPackageParam.classLoader, "put_siginfo",
                long.class, long.class, long.class, long.class, long.class, byte[].class,
                byte[].class, byte[].class, byte[].class, byte[].class, byte[].class, byte[].class, byte
                        [].class, byte[].class, byte[].class, byte[].class, byte[].class, byte[][].class, long[]
                        .class, int.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        byte[][] data = (byte[][]) param.args[17];
                        byte[] sessionkey = data[3];
                        log("SessionKey len=" + sessionkey.length + ":" + bytesToHex(sessionkey));
                    }
                }
        );

        //Fix Tea Rand
        XposedHelpers.findAndHookMethod("oicq.wlogin_sdk.tools.a", loadPackageParam.classLoader, "b",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(50);
                    }
                });

        //Hook SessionKey Valid Time  单位/s
        XposedHelpers.findAndHookMethod("oicq.wlogin_sdk.tlv_type.tlv_t138", loadPackageParam.classLoader, "get_d2_chg_time",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        int validtimeSecond = (int) param.getResult();
                        log("SessionKey Valid " + validtimeSecond + " s");
                    }
                }
        );


        //Test
        //开启Native层调试  tag libboot
        XposedHelpers.findAndHookMethod("com.tencent.qphone.base.util.CodecWarpper", loadPackageParam.classLoader, "init",
                Context.class, boolean.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.args[1] = true;
                        log("Open libcodecwrapperV2.so Debug Logcat Successful!");
                    }
                });


        //开启oicq.wloginsdk 日志 TAG wlogin_sdk
        final String OICQCLASS = "oicq.wlogin_sdk.tools.util";
        final String wlogin_sdk_tag = "wlogin_sdk";
        XposedHelpers.findAndHookMethod(OICQCLASS, loadPackageParam.classLoader, "LOGD",
                String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String p1 = (String) param.args[0];

                        Log.d(wlogin_sdk_tag + getLineInfo(2), p1);
                    }
                }
        );
        XposedHelpers.findAndHookMethod(OICQCLASS, loadPackageParam.classLoader, "LOGD",
                String.class, String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String p1 = (String) param.args[0];
                        String p2 = (String) param.args[1];

                        Log.d(wlogin_sdk_tag + getLineInfo(2), p1 + ":" + p2);
                    }
                }
        );

        XposedHelpers.findAndHookMethod(OICQCLASS, loadPackageParam.classLoader, "LOGI",
                String.class, String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String p1 = (String) param.args[0];
                        String p2 = (String) param.args[1];

                        Log.i(wlogin_sdk_tag + getLineInfo(2), p1 + ":" + p2);
                    }
                }
        );
        XposedHelpers.findAndHookMethod(OICQCLASS, loadPackageParam.classLoader, "LOGI",
                String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String p1 = (String) param.args[0];

                        Log.i(wlogin_sdk_tag + getLineInfo(2), p1);
                    }
                }
        );
        XposedHelpers.findAndHookMethod(OICQCLASS, loadPackageParam.classLoader, "LOGW",
                String.class, String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String p1 = (String) param.args[0];
                        String p2 = (String) param.args[1];

                        Log.w(wlogin_sdk_tag + getLineInfo(2), p1 + ":" + p2);
                    }
                }
        );
        XposedHelpers.findAndHookMethod(OICQCLASS, loadPackageParam.classLoader, "LOGW",
                String.class, String.class, String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String p1 = (String) param.args[0];
                        String p2 = (String) param.args[1];
                        String p3 = (String) param.args[2];

                        Log.w(wlogin_sdk_tag + getLineInfo(2), p1 + ":" + p2 + ":" + p3);
                    }
                }
        );

        //开启QLog   基本是QQ全局log
        /**
         * CodeWrapper tag MSF.C.CodecWarpper
         */
        final String QLogClass = "com.tencent.qphone.base.util.QLog";
        XposedHelpers.findAndHookMethod(QLogClass, loadPackageParam.classLoader, "d",
                String.class, int.class, String.class, Throwable.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String arg1 = (String) param.args[0];
                        int arg2 = (int) param.args[1];
                        String arg3 = (String) param.args[2];
                        Throwable arg4 = (Throwable) param.args[3];
                        if (arg3 == null) {
                            arg3 = "";
                        }
                        if (arg4 == null) {
                            Log.d(arg1, arg3);
                        } else {
                            Log.d(arg1, arg3, arg4);
                        }
                    }
                });


        XposedHelpers.findAndHookMethod(QLogClass, loadPackageParam.classLoader, "e",
                String.class, int.class, String.class, Throwable.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String arg1 = (String) param.args[0];
                        int arg2 = (int) param.args[1];
                        String arg3 = (String) param.args[2];
                        Throwable arg4 = (Throwable) param.args[3];
                        if (arg3 == null) {
                            arg3 = "";
                        }
                        if (arg4 == null) {
                            Log.e(arg1, arg3);
                        } else {
                            Log.e(arg1, arg3, arg4);
                        }
                    }
                });

        XposedHelpers.findAndHookMethod(QLogClass, loadPackageParam.classLoader, "i",
                String.class, int.class, String.class, Throwable.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String arg1 = (String) param.args[0];
                        int arg2 = (int) param.args[1];
                        String arg3 = (String) param.args[2];
                        Throwable arg4 = (Throwable) param.args[3];
                        if (arg3 == null) {
                            arg3 = "";
                        }
                        if (arg4 == null) {
                            Log.i(arg1, arg3);
                        } else {
                            Log.i(arg1, arg3, arg4);
                        }
                    }
                });

//Test


        //Hook数据包
        final String CodecWarpperClass = "com.tencent.qphone.base.util.CodecWarpper";
        /**
         * 发送包
         */
        XposedHelpers.findAndHookMethod(CodecWarpperClass, loadPackageParam.classLoader, "nativeEncodeRequest",
                int.class, String.class, String.class, String.class, String
                        .class, String.class, byte[].class, int.class, int.class, String.class, byte.class, byte.class,
                byte[].class, byte[].class, boolean.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
//                        log("nativeEncodeRequest V2");
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        int requestSsoSeq = (int) param.args[0];
                        String imei = (String) param.args[1];
                        String subscriberId = (String) param.args[2];
                        String revision = (String) param.args[3];
                        String serviceCmd = (String) param.args[5];
                        String msgCookie = bytesToHex((byte[]) param.args[6]);
                        int appid = (int) param.args[7];
                        int msfappid = (int) param.args[8];
                        String uin = (String) param.args[9];
                        byte netWorkType = (byte) param.args[11];
                        byte[] pbtimestamp = (byte[]) param.args[12];
                        byte[] wupBuffer = (byte[]) param.args[13];

                        byte[] sendData = (byte[]) param.getResult();

                        if (serviceCmd.startsWith("wtlogin.")) {
                            log("SEND DATA->" +
                                    "serviceCmd:" + serviceCmd + "|" +
                                    "requestSsoSeq:" + requestSsoSeq + "|" +
                                    "imei:" + imei + "|" +
                                    "subscriberId:" + subscriberId + "|" +
                                    "revision:" + revision + "|" +
                                    "msgCookie:" + msgCookie + "|" +
                                    "appid:" + appid + "|" +
                                    "msfappid:" + msfappid + "|" +
                                    "uin:" + uin + "|" +
                                    "netWorkType:" + netWorkType + "|" +
                                    "pbtimestamp:" + bytesToHex(pbtimestamp) + "|" +
                                    "wupBuffer Length:" + (wupBuffer.length) + "|" +
                                    "wupBuffer:" + bytesToHex(wupBuffer) + "|" +
                                    "sendData Length:" + (sendData.length) + "|" +
                                    "sendData:" + bytesToHex(sendData) + "|");
                        } else {
                            log("SEND DATA->" +
                                    "serviceCmd:" + serviceCmd + "|" +
                                    "requestSsoSeq:" + requestSsoSeq + "|" +
                                    "msgCookie:" + msgCookie + "|" +
                                    "uin:" + uin + "|" +
                                    "pbtimestamp:" + bytesToHex(pbtimestamp) + "|" +
                                    "wupBuffer Length:" + (wupBuffer.length) + "|" +
                                    "wupBuffer:" + bytesToHex(wupBuffer) + "|" +
                                    "sendData Length:" + (sendData.length) + "|" +
                                    "sendData:" + bytesToHex(sendData) + "|");
                        }

                    }
                });


        //Hook 接收包
        XposedHelpers.findAndHookMethod(CodecWarpperClass, loadPackageParam.classLoader, "nativeOnReceData",
                byte[].class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        byte[] data = (byte[]) param.args[0];
                        log("RECEIVE DATA ->" +
                                "Buf Length:" + (data.length) + "|" +
                                "Buf:" + bytesToHex(data) + "|"
                        );
                    }
                });

        final Class FromServiceMsg = XposedHelpers.findClass("com.tencent.qphone.base.remote.FromServiceMsg", loadPackageParam.classLoader);
        XposedHelpers.findAndHookMethod("com.tencent.mobileqq.msf.core.af$a", loadPackageParam.classLoader, "onResponse",
                int.class, Object.class, int.class, byte[].class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        int p1 = (int) param.args[0];
                        Object fromServiceMsg = (Object) param.args[1];
                        int p3 = (int) param.args[2];
                        byte[] p4 = (byte[]) param.args[3];


                        int appId = 0;
                        int appSeq = 0;
                        HashMap attributes;
                        String errorMsg = null;
                        Bundle extraData;
                        int flag = 0;
                        byte fromVersion = 0;
                        Object msfCommand = null;
                        byte[] msgCookie = null;
                        int resultCode = 0;
                        String serviceCmd = null;
                        int ssoSeq = 0;
                        String uin = null;
                        byte[] wupBuffer = null;

                        //获取数据
                        for (Field f : FromServiceMsg.getDeclaredFields()) {
                            f.setAccessible(true);
                            switch (f.getName()) {
                                case "appId":
                                    appId = (int) f.get(fromServiceMsg);
                                    break;
                                case "appSeq":
                                    appSeq = (int) f.get(fromServiceMsg);
                                    break;
                                case "attributes":
                                    attributes = (HashMap) f.get(fromServiceMsg);
                                    break;
                                case "errorMsg":
                                    errorMsg = (String) f.get(fromServiceMsg);
                                    break;
                                case "extraData":
                                    extraData = (Bundle) f.get(fromServiceMsg);
                                    break;
                                case "flag":
                                    flag = (int) f.get(fromServiceMsg);
                                    break;
                                case "fromVersion":
                                    fromVersion = (byte) f.get(fromServiceMsg);
                                    break;
                                case "msgCookie":
                                    msgCookie = (byte[]) f.get(fromServiceMsg);
                                    break;
                                case "resultCode":
                                    resultCode = (int) f.get(fromServiceMsg);
                                    break;
                                case "serviceCmd":
                                    serviceCmd = (String) f.get(fromServiceMsg);
                                    break;
                                case "ssoSeq":
                                    ssoSeq = (int) f.get(fromServiceMsg);
                                    break;
                                case "uin":
                                    uin = (String) f.get(fromServiceMsg);
                                    break;
                                case "wupBuffer":
                                    wupBuffer = (byte[]) f.get(fromServiceMsg);
                                    break;
                                case "msfCommand":
                                    msfCommand = f.get(fromServiceMsg).toString();
                                    break;

                            }
                        }


                        log("RECEIVE -> onResponse ->" +
                                "serviceCmd:" + serviceCmd + "|" +
                                "appSeq:" + appSeq + "|" +
                                "uin:" + uin + "|" +
//                                "" + p1 + "|" +
//                                "" + fromServiceMsg + "|" +
                                "len:" + p3 + "|" +
//                                "" + bytesToHex(p4) + "|" +
                                "msName:" + msfCommand + "|" +
                                "ssoSeq:" + ssoSeq + "|" +
                                "resultCode:" + resultCode + "|" +
                                "errorMsg:" + errorMsg + "|" +
                                "appId:" + appId + "|" +
                                "flag:" + flag + "|" +
                                "fromVersion:" + fromVersion + "|" +
                                "msgCookie:" + bytesToHex(msgCookie) + "|" +
                                "wupBuffer Length:" + (wupBuffer.length) + "|"+
                                "wupBuffer:" + bytesToHex(wupBuffer) + "|"
                        );
                    }
                });

//        log("Fix Tea Rand value:50");


        log("Add All Hooks to MobileQQ Successful");

    }

    public static String getLineInfo(int arg3) {
        String v0;
        if (arg3 < 0) {
            v0 = "";
            return v0;
        }

        try {
            StackTraceElement v0_2 = new Throwable().getStackTrace()[arg3];
            v0 = "[" + v0_2.getFileName() + ":" + v0_2.getLineNumber() + "]";
        } catch (Throwable v0_1) {
            v0 = "";
        }

        return v0;
    }

    public static String getStack() {
        try {
            StringBuffer sb = new StringBuffer();
            StackTraceElement[] v0_2 = new Throwable().getStackTrace();
            for (StackTraceElement ele : v0_2) {
                sb.append(ele.toString())
                        .append("#");
            }
            return sb.toString();
        } catch (Exception e) {

        }
        return "get stack error";
    }

    public static void log(String msg) {
        Log.i(LOGTAG, msg);
        XposedBridge.log("qq-hook" + ":" + msg);
    }


    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
