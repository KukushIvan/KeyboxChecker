# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.** { *; }
-keep class okio.** { *; }

# Keep WorkManager worker
-keep class io.github.kukushivan.keyboxchecker.IntegrityWorker { *; }
-keep class io.github.kukushivan.keyboxchecker.SentinelService { *; }
-keep class io.github.kukushivan.keyboxchecker.BootReceiver { *; }