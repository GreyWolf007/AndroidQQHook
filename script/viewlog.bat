echo View Logcat
start cmd /c "echo startlog&&adb shell rm -f /sdcard/qq.log&&adb logcat -v time -f /sdcard/qq.log -s qqhook"
sleep 1
start cmd /c "adb shell tail -f /sdcard/qq.log"
