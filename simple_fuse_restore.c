#define FUSE_USE_VERSION 35
#define MAX_TRACKED_PIDS 100
#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>     
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>     // readdir을 위해 추가
#include <limits.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/types.h>
#include "restore.h" 

// NOTE: 복구 로직 테스트를 위해 Kill 조건을 강제하고, Score/Analyzer 코드는 제외함
#define KILL_THRESHOLD 1 
static int base_fd = -1;

// **********************************************
// 1. 필수 유틸리티 함수
// **********************************************

// FUSE 경로를 백엔드 상대 경로로 변환 (blue2.c 원본)
static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/')
            path++;
        strncpy(relpath, path, PATH_MAX);
    }
}

// Kill 조건 강제 충족 함수 (테스트용)
static int is_malicious_enough_to_kill() {
    // 테스트를 위해 무조건 Kill 조건에 도달하도록 임의의 값을 반환합니다.
    return 2 * KILL_THRESHOLD; 
}


// **********************************************
// 2. 필수 FUSE 콜백 함수 (Pass-Through)
// **********************************************

// getattr 함수 구현 (blue2.c 원본)
static int myfs_getattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi) {
    (void) fi;
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    // blacklisting 로직은 제거하고 패스스루만 남김
    res = fstatat(base_fd, relpath, stbuf, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;

    return 0;
}

// readdir 함수 구현 (blue2.c 원본)
static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags) {
    DIR *dp;
    struct dirent *de;
    int fd;

    (void) offset;
    (void) fi;
    (void) flags;

    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    fd = openat(base_fd, relpath, O_RDONLY | O_DIRECTORY);
    if (fd == -1)
        return -errno;

    dp = fdopendir(fd);
    if (dp == NULL) {
        close(fd);
        return -errno;
    }

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, 0))
            break;
    }

    closedir(dp);
    return 0;
}

// open 함수 구현 (blue2.c 원본)
static int myfs_open(const char *path, struct fuse_file_info *fi) {
    // 화이트리스트 검사 로직은 제거하고 패스스루만 남김
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = openat(base_fd, relpath, fi->flags);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

// read 함수 구현 (blue2.c 원본)
static int myfs_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
    int res;

    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

// release 함수 구현 (blue2.c 원본)
static int myfs_release(const char *path, struct fuse_file_info *fi) {
    close(fi->fh);
    // Score 초기화 로직은 제거하고 파일 핸들 닫기만 남김
    return 0;
}


// **********************************************
// 3. 복구 로직 테스트 함수 (Kill 로직만 간소화)
// **********************************************

// write 함수 구현 (복구 테스트용)
static int myfs_write(const char *path, const char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    
    // 1. **[Restore 모듈] CoW 백업 호출** (변조 직전 원본 확보)
    restore_backup_on_write(path, base_fd); 
    
    // 2. Kill 조건 강제 실행
    if (is_malicious_enough_to_kill() >= KILL_THRESHOLD) {
        fprintf(stderr, "TEST: Write Kill 조건 충족! 롤백 시작.\n");
        
        // **[Restore 모듈] 롤백 호출** (Kill 시 원본 덮어쓰기)
        restore_backup_file(path, base_fd); 
        
        // Kill 실행은 건너뛰고 에러 반환
        return -EIO; 
    }

    // 3. 패스스루 쓰기 (암호화 시뮬레이션)
    int res = pwrite(fi->fh, buf, size, offset);
    if (res == -1) res = -errno;
    return res;
}

// unlink 함수 구현 (복구 테스트용)
static int myfs_unlink(const char *path) {
    
    // Kill 조건 강제 실행
    if(is_malicious_enough_to_kill() >= KILL_THRESHOLD) {
	    fprintf(stderr, "TEST: Unlink Kill 조건 충족! 롤백 시작.\n");
	    
        // **[Restore 모듈] 롤백 호출** (Kill 시 원본 복원)
        restore_backup_file(path, base_fd);

	    // Kill 및 연산 차단
	    return -EIO;
    }
    
    // 패스스루 삭제 (여기는 도달하지 않음)
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    res = unlinkat(base_fd, relpath, 0); 
    if (res == -1) return -errno;
    return 0;
}

// rename 함수 구현 (복구 테스트용)
static int myfs_rename(const char *from, const char *to, unsigned int flags) {
    
    // Kill 조건 강제 실행
    if(is_malicious_enough_to_kill() >= KILL_THRESHOLD) {
        fprintf(stderr, "TEST: Rename Kill 조건 충족! 롤백 시작.\n");
        
        // **[Restore 모듈] 롤백 호출**
        restore_backup_file(from, base_fd); 
            
        // Kill 및 연산 차단
        return -EIO;
    }
    
    // 패스스루 이름 변경 (여기는 도달하지 않음)
    int res;
    char relfrom[PATH_MAX];
    char relto[PATH_MAX];
    get_relative_path(from, relfrom);
    get_relative_path(to, relto);
    res = renameat(base_fd, relfrom, base_fd, relto);
    if (res == -1) return -errno;
    return 0;
}


// **********************************************
// 4. FUSE 연산 구조체 및 Main 함수
// **********************************************

// 파일시스템 연산자 구조체 (blue2.c 원본)
static const struct fuse_operations myfs_oper = {
    .getattr    = myfs_getattr,
    .readdir    = myfs_readdir,
    .open       = myfs_open,
    .create     = NULL, // create 함수는 테스트 편의를 위해 일단 제외
    .read       = myfs_read,
    .write      = myfs_write,
    .release    = myfs_release,
    .unlink     = myfs_unlink,
    .mkdir      = NULL, 
    .rmdir      = NULL,
    .rename     = myfs_rename,
    .utimens    = NULL,  
};


int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mountpoint>\n", argv[0]);
        return -1;
    }

    char *mountpoint = realpath(argv[argc - 1], NULL);
    if (mountpoint == NULL) {
        perror("realpath");
        return -1;
    }

    const char *home_dir = getenv("HOME");
    if (!home_dir) {
    	fprintf(stderr, "Error: HOME environment variable not set.\n");
        return -1;
    }
    
    char backend_path[PATH_MAX];
    snprintf(backend_path, PATH_MAX, "%s/workspace/target", home_dir);

    fprintf(stderr, "INFO: Protecting backend path: %s\n", backend_path);
    
    base_fd = open(backend_path, O_RDONLY | O_DIRECTORY);
    if (base_fd == -1) {
	perror("Error opening backend directory");
	return -1;
    }

    // [RESTORE] 초기화(경로) 호출
    if (restore_init(home_dir, backend_path) != 0) {
        close(base_fd);
        return -1;
    }

    // FUSE 파일시스템 실행
    int ret = fuse_main(args.argc, args.argv, &myfs_oper, NULL);

    close(base_fd);
    return ret;
}