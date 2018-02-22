package com.example.greywolf.qq750hook;

/**
 * Created by GreyWolf on 2018/2/21.
 */

public class Test {
    public static void main(String[] args) {
        System.out.println(getLineInfo(2));
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
}
