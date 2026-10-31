# lovelyspark-Hack
Rust + Themida 逆向练习，实现了 lovelyspark 的破解，免授权使用所有功能。

程序使用 Themida 壳，有反调试以及 RSA 验签相关函数的完整性检查。

反调试导致不能长时间附加，但是绕过方法也算简单，短附加即可，因此改造了一下我的 memoryeditor 库。

相关函数有完整性检查，所以不能随便patch和hook，绕过更简单，patch call 处即可。

main.py 是启动器，每次使用即可。
