--- src/worker.c.orig	2026-10-02 00:00:00 UTC
+++ src/worker.c
@@ -17,7 +17,7 @@
 #include <sys/param.h>
 #include <sys/types.h>
 #include <sys/stat.h>
-#include <sys/shm.h>
+#include <sys/mman.h>
 #include <sys/wait.h>
 #include <sys/time.h>
 #include <sys/resource.h>
@@ -90,7 +90,6 @@
 static int				accept_avail;
 static struct kore_worker		*kore_workers;
 static int				worker_no_lock;
-static int				shm_accept_key;
 static struct wlock			*accept_lock;
 
 struct kore_worker		*worker = NULL;
@@ -120,11 +119,9 @@
 	len = sizeof(*accept_lock) +
 	    (sizeof(struct kore_worker) * worker_count);
 
-	shm_accept_key = shmget(IPC_PRIVATE, len, IPC_CREAT | IPC_EXCL | 0700);
-	if (shm_accept_key == -1)
-		fatal("kore_worker_init(): shmget() %s", errno_s);
-	if ((accept_lock = shmat(shm_accept_key, NULL, 0)) == (void *)-1)
-		fatal("kore_worker_init(): shmat() %s", errno_s);
+	if ((accept_lock = mmap(NULL, len, PROT_READ | PROT_WRITE,
+	    MAP_ANON | MAP_SHARED, -1, 0)) == MAP_FAILED)
+		fatal("kore_worker_init(): mmap() %s", errno_s);
 
 	accept_lock->lock = 0;
 	accept_lock->current = 0;
@@ -343,11 +340,6 @@
 		if (done == worker_count)
 			break;
 	}
-
-	if (shmctl(shm_accept_key, IPC_RMID, NULL) == -1) {
-		kore_log(LOG_NOTICE,
-		    "failed to deleted shm segment: %s", errno_s);
-	}
 }
 
 void
