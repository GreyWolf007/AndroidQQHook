package com.wolf.q750hook;

import android.app.Application;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.UUID;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * for mobile qq V8.0.0
 * Created by GreyWolf on 2018/2/21.
 */

public class Main implements IXposedHookLoadPackage {
    static final String MobileQQPN = "com.tencent.mobileqq";
    static final String LOGTAG = "qqhook";

    static final String LOGTAG_PACKET = "qqhook-packet";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (!loadPackageParam.packageName.equals(MobileQQPN)) {
            return;
        }
        log("Hook MobileQQ Successful!");

        XposedHelpers.findAndHookMethod(Application.class, "attach", Context.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                // this will be called before the clock was updated by the original method
            }

            @Override
            protected void afterHookedMethod(XC_MethodHook.MethodHookParam param) throws Throwable {
               /* ClassLoader cl = ((Context) param.args[0]).getClassLoader();
                Class<?> hookclass = null;
                final String class_name = "com.tencent.mobileqq.transfile.GroupPicUploadProcessor";
                try {
                    hookclass = cl.loadClass(class_name);
                } catch (Exception e) {
                    log("[Failed!]Can not find " + class_name);
                    return;
                }
                log("[success!]Find class " + class_name);

                XposedHelpers.findAndHookMethod(hookclass,
                        "b", StringBuilder.class, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                // this will be called before the clock was updated by the original method
                            }

                            @Override
                            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                // this will be called after the clock was updated by the original method
                                log("after hook:" + class_name + "---" + getStack());
                            }
                        });*/
            }
        });  // end of findAndHookMethod
//        log("hook attach successful!");

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
                        byte[] wtsessionticket = data[13];
                        byte[] wtsessionticketkey = data[13];
                        log("SessionKey len=" + sessionkey.length + ":" + bytesToHex(sessionkey));
                        log("wt session ticket:" + bytesToHex(wtsessionticket) + "|" + "wtsessionticket key:" + bytesToHex(wtsessionticketkey));

                        long curr = (long) param.args[2];// System.currentTimeMillis() / 1000;
                        long[] validTime = (long[]) param.args[18];

                        long _D2_expire_time = validTime[5];
                        long _sid_expire_time = validTime[6];
                        long _vKey_expire_time = validTime[2];
                        long _sKey_expire_time = validTime[1];
                        long _userStWebSig_expire_time = validTime[4];
                        long _userA8_expire_time = validTime[3];
                        long _lsKey_expire_time = validTime[0];

                        log(
                                "Original" +
                                        "_D2_expire_time:" + formatTimeUnix10(_D2_expire_time + curr) + " Valid:" + _D2_expire_time + " s|" +
                                        "_sid_expire_time:" + formatTimeUnix10(_sid_expire_time + curr) + " Valid:" + _sid_expire_time + " s|" +
                                        "_vKey_expire_time:" + formatTimeUnix10(_vKey_expire_time + curr) + " Valid:" + _vKey_expire_time + " s|" +
                                        "_sKey_expire_time:" + formatTimeUnix10(_sKey_expire_time + curr) + " Valid:" + _sKey_expire_time + " s|" +
                                        "_userStWebSig_expire_time:" + formatTimeUnix10(_userStWebSig_expire_time + curr) + " Valid:" + _userStWebSig_expire_time + " s|" +
                                        "_userA8_expire_time:" + formatTimeUnix10(_userA8_expire_time + curr) + " Valid:" + _userA8_expire_time + " s|" +
                                        "_lsKey_expire_time:" + formatTimeUnix10(_lsKey_expire_time + curr) + " Valid:" + _lsKey_expire_time + " s|"

                        );
                        /**
                         * log
                         * 02-24 08:50:15.343 I/qqhook  ( 2942): _D2_expire_time:2018/03/17 08:50:15 Valid:1814400 s|_sid_expire_time:2018/03/17 08:50:15 Valid:1814400 s|_vKey_expire_time:2018/03/17 08:50:15 Valid:1814400 s|_sKey_expire_time:2018/02/25 08:50:15 Valid:86400 s|_userStWebSig_expire_time:2018/02/24 10:50:15 Valid:7200 s|_userA8_expire_time:2018/02/25 08:50:15 Valid:86400 s|_lsKey_expire_time:2018/03/16 08:50:15 Valid:1728000 s|
                         */
                        //Get wtlogin.exchange_emp
//                        for (int i = 0; i < validTime.length; i++)
//                            validTime[i] = 10;
//                        validTime[5]=10;
//                        validTime[6] = 10;

                    }
                }
        );

        //Fix Tea Rand
        XposedHelpers.findAndHookMethod("oicq.wlogin_sdk.tools.b", loadPackageParam.classLoader, "b",
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
        //region 开启Native层调试  tag libboot
        XposedHelpers.findAndHookMethod("com.tencent.qphone.base.util.CodecWarpper", loadPackageParam.classLoader, "init",
                Context.class, boolean.class, boolean.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.args[1] = true;
                        log("Open libcodecwrapperV2.so Debug Logcat Successful!");
                    }
                });

        XposedHelpers.findAndHookMethod("com.tencent.qphone.base.util.CodecWarpper", loadPackageParam.classLoader, "getAppid",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        log("APPID==" + param.getResult());

                    }
                });
//endregion

        //region 开启oicq.wloginsdk 日志 TAG wlogin_sdk
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
        //endregion

        //region 开启QLog   基本是QQ全局log
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
//endregion
//Test


        //Hook数据包
        final String CodecWarpperClass = "com.tencent.qphone.base.util.CodecWarpper";
        /**
         * 发送包 V3
         */
        //	int i, String str, String str2, String str3,
        //		String str4, String str5,
        //		byte[] bArr, int i2,
        //		int i3, String str6, byte b, byte b2,
        //		byte[] bArr2, boolean z
        XposedHelpers.findAndHookMethod(CodecWarpperClass, loadPackageParam.classLoader, "nativeEncodeRequest",
                int.class,
                String.class,
                String.class,
                String.class,
                String.class,
                String.class,

                byte[].class,
                int.class,
                int.class,
                String.class,
                byte.class,
                byte.class,
                byte[].class,
                boolean.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        log("nativeEncodeRequest V3");
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
                        /*byte b = (byte) 0;
            if (NetConnInfoCenter.isWifiConn()) {
                b = (byte) 1;
            } else if (NetConnInfoCenter.isMobileConn()) {
                indexOf = NetConnInfoCenter.getMobileNetworkType() + 100;
                if (indexOf > 254) {
                    indexOf = 254;
                    if (QLog.isColorLevel()) {
                        QLog.d("MSF.C.NetConnTag", 2, "error,netWorkType is " + 254);
                    }
                }
                b = (byte) indexOf;
            }*/
                        byte netWorkType = (byte) param.args[11];
                        byte[] wupBuffer = (byte[]) param.args[12];

                        byte[] sendData = (byte[]) param.getResult();

                        if (serviceCmd.startsWith("wtlogin.")) {
                            log(LOGTAG_PACKET, "SEND DATA->" +
                                    "serviceCmd:" + serviceCmd + "|" +
                                    "requestSsoSeq:" + requestSsoSeq + "|" +
                                    "sendData Length:" + (sendData.length) + "|" +
                                    "wupBuffer Length:" + (wupBuffer.length) + "|" +
                                    "imei:" + imei + "|" +
                                    "subscriberId:" + subscriberId + "|" +
                                    "revision:" + revision + "|" +
                                    "msgCookie:" + msgCookie + "|" +
                                    "appid:" + appid + "|" +
                                    "msfappid:" + msfappid + "|" +
                                    "uin:" + uin + "|" +
                                    "netWorkType:" + netWorkType + "|" +
                                    "wupBuffer:" + bytesToHex(wupBuffer) + "|"
//                                    + "sendData:" + bytesToHex(sendData) + "|"
                            );
                        } else {
                            log(LOGTAG_PACKET, "SEND DATA->" +
                                    "serviceCmd:" + serviceCmd + "|" +
                                    "requestSsoSeq:" + requestSsoSeq + "|" +
                                    "sendData Length:" + (sendData.length) + "|" +
                                    "wupBuffer Length:" + (wupBuffer.length) + "|" +
                                    "msgCookie:" + msgCookie + "|" +
                                    "uin:" + uin + "|" +
                                    "wupBuffer:" + bytesToHex(wupBuffer) + "|"
//                                    + "sendData:" + bytesToHex(sendData) + "|"
                            );
                        }

                    }
                });


        /**
         * 发送包V2
         */
        //int i, String str, String str2, String str3, String str4, String str5,
        // byte[] bArr, int i2, int i3, String str6,
        // byte b, byte b2, byte[] bArr2, byte[] bArr3, byte[] bArr4, boolean z
        XposedHelpers.findAndHookMethod(CodecWarpperClass, loadPackageParam.classLoader, "nativeEncodeRequest",
                int.class, String.class, String.class, String.class, String
                        .class, String.class,
                byte[].class, int.class, int.class, String.class,
                byte.class, byte.class,
                byte[].class,
                byte[].class, byte[].class, boolean.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        log("nativeEncodeRequest V2");
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
                        byte[] wupBuffer = (byte[]) param.args[14];

                        byte[] sendData = (byte[]) param.getResult();

                        if (serviceCmd.startsWith("wtlogin.")) {
                            log(LOGTAG_PACKET, "SEND DATA->" +
                                    "serviceCmd:" + serviceCmd + "|" +
                                    "requestSsoSeq:" + requestSsoSeq + "|" +
                                    "sendData Length:" + (sendData.length) + "|" +
                                    "wupBuffer Length:" + (wupBuffer.length) + "|" +
                                    "imei:" + imei + "|" +
                                    "subscriberId:" + subscriberId + "|" +
                                    "revision:" + revision + "|" +
                                    "msgCookie:" + msgCookie + "|" +
                                    "appid:" + appid + "|" +
                                    "msfappid:" + msfappid + "|" +
                                    "uin:" + uin + "|" +
                                    "netWorkType:" + netWorkType + "|" +
                                    "pbtimestamp:" + bytesToHex(pbtimestamp) + "|" +
                                    "wupBuffer:" + bytesToHex(wupBuffer) + "|"
//                                    + "sendData:" + bytesToHex(sendData) + "|"
                            );
                        } else {
                            log(LOGTAG_PACKET, "SEND DATA->" +
                                    "serviceCmd:" + serviceCmd + "|" +
                                    "requestSsoSeq:" + requestSsoSeq + "|" +
                                    "sendData Length:" + (sendData.length) + "|" +
                                    "wupBuffer Length:" + (wupBuffer.length) + "|" +
                                    "msgCookie:" + msgCookie + "|" +
                                    "uin:" + uin + "|" +
                                    "pbtimestamp:" + bytesToHex(pbtimestamp) + "|" +
                                    "wupBuffer:" + bytesToHex(wupBuffer) + "|"
//                                    + "sendData:" + bytesToHex(sendData) + "|"
                            );
                        }

                    }
                });

        /**
         * 发送包V1
         */
        //int i, String str, String str2, String str3, String str4, String str5,
        // byte[] bArr, int i2, int i3, String str6,
        // byte b, byte b2, byte b3, byte[] bArr2, byte[] bArr3, byte[] bArr4, boolean z
        XposedHelpers.findAndHookMethod(CodecWarpperClass, loadPackageParam.classLoader, "nativeEncodeRequest",
                int.class, String.class, String.class, String.class, String.class, String.class,
                byte[].class,
                int.class, int.class, String.class,
                byte.class, byte.class, byte.class, byte[].class,
                byte[].class, byte[].class, boolean.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        log("nativeEncodeRequest V1");
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
                        byte activeNetworkIpType = (byte) param.args[12];
                        byte[] reserveFields = (byte[]) param.args[13];
                        byte[] wupBuffer = (byte[]) param.args[15];

                        byte[] sendData = (byte[]) param.getResult();

                        if (serviceCmd.startsWith("wtlogin.")) {
                            log(LOGTAG_PACKET, "SEND DATA->" +
                                    "serviceCmd:" + serviceCmd + "|" +
                                    "requestSsoSeq:" + requestSsoSeq + "|" +
                                    "sendData Length:" + (sendData.length) + "|" +
                                    "wupBuffer Length:" + (wupBuffer.length) + "|" +
                                    "imei:" + imei + "|" +
                                    "subscriberId:" + subscriberId + "|" +
                                    "revision:" + revision + "|" +
                                    "msgCookie:" + msgCookie + "|" +
                                    "appid:" + appid + "|" +
                                    "msfappid:" + msfappid + "|" +
                                    "uin:" + uin + "|" +
                                    "netWorkType:" + netWorkType + "|" +
                                    "activeNetworkIpType:" + activeNetworkIpType + "|" +
                                    "reserveFields:" + bytesToHex(reserveFields) + "|" +
                                    "wupBuffer:" + bytesToHex(wupBuffer) + "|"
//                                    + "sendData:" + bytesToHex(sendData) + "|"
                            );
                        } else {
                            log(LOGTAG_PACKET, "SEND DATA->" +
                                    "serviceCmd:" + serviceCmd + "|" +
                                    "requestSsoSeq:" + requestSsoSeq + "|" +
                                    "sendData Length:" + (sendData.length) + "|" +
                                    "wupBuffer Length:" + (wupBuffer.length) + "|" +
                                    "msgCookie:" + msgCookie + "|" +
                                    "uin:" + uin + "|" +
                                    "netWorkType:" + netWorkType + "|" +
                                    "activeNetworkIpType:" + activeNetworkIpType + "|" +
                                    "reserveFields:" + bytesToHex(reserveFields) + "|" +
                                    "wupBuffer:" + bytesToHex(wupBuffer) + "|"
//                                    + "sendData:" + bytesToHex(sendData) + "|"
                            );
                        }
                    }
                });
        //Hook 接收包
        XposedHelpers.findAndHookMethod(CodecWarpperClass, loadPackageParam.classLoader, "nativeOnReceData",
                byte[].class, int.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        byte[] data = (byte[]) param.args[0];
                        log(LOGTAG_PACKET, "RECEIVE DATA ->" +
                                "Buf Length:" + (data.length) + "|" +
                                "Buf:" + bytesToHex(data) + "|i=" + param.args[1]
                        );
                    }
                });

        final Class FromServiceMsg = XposedHelpers.findClass("com.tencent.qphone.base.remote.FromServiceMsg", loadPackageParam.classLoader);
        XposedHelpers.findAndHookMethod("com.tencent.mobileqq.msf.core.ae$a", loadPackageParam.classLoader, "onResponse",
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


                        log(LOGTAG_PACKET, "RECEIVE -> onResponse ->" +
                                        "serviceCmd:" + serviceCmd + "|" +
                                        "appSeq:" + appSeq + "|" +
                                        "ssoSeq:" + ssoSeq + "|" +
                                        "wupBuffer Length:" + (wupBuffer.length) + "|" +
                                        "uin:" + uin + "|" +
                                        "resultCode:" + resultCode + "|" +
//                                "" + p1 + "|" +
//                                "" + fromServiceMsg + "|" +
                                        "len:" + p3 + "|" +
//                                "" + bytesToHex(p4) + "|" +
                                        "msName:" + msfCommand + "|" +
                                        "errorMsg:" + errorMsg + "|" +
                                        "appId:" + appId + "|" +
                                        "flag:" + flag + "|" +
                                        "fromVersion:" + fromVersion + "|" +
                                        "msgCookie:" + bytesToHex(msgCookie) + "|" +
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

    final static int limit = 1023 * 3;

    public static void log(String msg) {
        log(LOGTAG, msg);
    }

    public static void log(String tag, String msg) {
        String uuid = UUID.randomUUID().toString();

        if (msg.length() > limit) {
            while (msg.length() > limit) {
                Log.i(tag, "uuid:" + uuid + ":" + msg.substring(0, limit));
                msg = msg.substring(limit);
            }
            Log.i(tag, "uuid:" + uuid + ":" + msg);
        } else {
            Log.i(tag, msg);
        }
    }

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String formatTimeUnix10(long timeunix) {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        return simpleDateFormat.format(timeunix * 1000);
    }
}
