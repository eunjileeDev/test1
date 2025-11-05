#define FUSE_USE_VERSION 35

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>     // realpath 함수 사용을 위해 추가
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/types.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#define MAX_TRACKED_PIDS 100 
#define KILL_THRESHOLD 80    

static int base_fd = -1; 

// --- B 역할: PID/Score 관리 구조체 ---
typedef struct {
    pid_t pid;             
    int malice_score;      
    time_t last_write_time; 
    char proc_name[32];    
} ProcessScore;

ProcessScore g_score_table[MAX_TRACKED_PIDS];
int g_process_count = 0; 

// B 역할 헬퍼 함수 선언
ProcessScore* find_or_create_score_entry(pid_t pid);
void update_malice_score(pid_t pid, int added_score);
int get_malice_score(pid_t pid);

// A 역할 함수 전방 선언
double calculate_entropy(const char *buffer, size_t size);
int monitor_operation(const char* operation, const char* buf, size_t size, pid_t current_pid);


// --------------------------------------------------------
// SECTION 2: A 역할 탐지 로직 (ENTROPY & ANALYZER IMPLEMENTATION)
// --------------------------------------------------------

// --- A 역할: ENTROPY 로직 구현 ---
double calculate_entropy(const char *buffer, size_t size) {
    if (size == 0) return 0.0;
    long long counts[256];
    memset(counts, 0, sizeof(counts));
    for (size_t i = 0; i < size; i++) counts[(unsigned char)buffer[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double probability = (double)counts[i] / size;
        entropy -= probability * log2(probability); 
    }
    return entropy;
}

// --- A 역할: ANALYZER 로직 정의 및 구현 ---
// 오타 수정 완료: 모든 WEIGTH_xxxx와 UNLINK_THRESHOLE_PER_1 등으로 통일
#define WEIGTH_WRITE 1 
#define WEIGTH_MALICIOUS 3      
#define WEIGHT_HIGH_ENTROPY 5 
#define ENTROPY_THRESHOLD 4.2 
#define TIME_SECONDS 1 
#define WRITE_THRESHOLD_PER_1 100 
#define UNLINK_THRESHOLD_PER_1 10 
#define RENAME_THRESHOLD_PER_1 10 
#define PENALTY_HIGH_WRITE 50 
#define PENALTY_HIGH_UNLINK 100 
#define PENALTY_HIGH_RENAME 100 
#define FINAL_MALICE_THRESHOLD 200 

// A 역할의 전역 상태 변수 (1초 단위 검사용)
static int write_count = 0;
static int unlink_count = 0;
static int rename_count = 0;
static int total_malice_score = 0;
static time_t start_time = 0;

// 1. 단일 연산에 대한 점수 계산 (content-based)
static int get_score(const char* operation, const char* buf, size_t size) { 
    int score_to_add = 0; // 변수 선언 누락 오류 해결

    if (strcmp(operation, "WRITE") == 0) {
        score_to_add += WEIGTH_WRITE; // WEIGTH_WRITE 사용
        if (buf != NULL && size > 0) {
            double entropy = calculate_entropy(buf, size);
            if (entropy > ENTROPY_THRESHOLD) {
                score_to_add += WEIGHT_HIGH_ENTROPY; // WEIGHT_HIGH_ENTROPY 사용
            }
        }
    }
    else if (strcmp(operation, "UNLINK") == 0 || strcmp(operation, "RENAME") == 0) {
        score_to_add += WEIGTH_MALICIOUS; // WEIGTH_MALICIOUS 사용
    }
    return score_to_add; 
}

// 2. 1초 단위로 빈도를 검사하고 벌점을 반환하는 함수
static int check_frequency_and_alert(pid_t current_pid) {
    time_t current_time = time(NULL);
    int penalty_score = 0; 

    if (start_time == 0) {
        start_time = current_time;
        return 0; 
    }
    if (current_time - start_time < TIME_SECONDS) {
        return 0;
    }

    // 1. 빈도 임계치 검사 및 벌점 추가 
    if (write_count > WRITE_THRESHOLD_PER_1) {
        penalty_score += PENALTY_HIGH_WRITE;
    }
    if (unlink_count > UNLINK_THRESHOLD_PER_1) { // UNLINK_THRESHOLD_PER_1 사용
        penalty_score += PENALTY_HIGH_UNLINK; // PENALTY_HIGH_UNLINK 사용
    }
    if (rename_count > RENAME_THRESHOLD_PER_1) {
        penalty_score += PENALTY_HIGH_RENAME;
    }

    // A 역할의 최종 Malice Score 판단 (디버깅용)
    if (total_malice_score + penalty_score > FINAL_MALICE_THRESHOLD) {
        fprintf(stderr, "A-ANALYZER: 1초간 누적 점수 %d로 악성 판단 (PID:%d)\n", total_malice_score + penalty_score, current_pid);
    }
    
    // 3. 다음 1초 검사를 위해 초기화 
    total_malice_score = 0;
    write_count = 0;
    unlink_count = 0;
    rename_count = 0;
    start_time = current_time;
    
    return penalty_score; 
}

// 3. B 역할이 호출하는 최종 통합 함수
int monitor_operation(const char* operation, const char* buf, size_t size, pid_t current_pid) {

    int content_score = get_score(operation, buf, size); 
    total_malice_score += content_score; 

    // 횟수 누적
    if (strcmp(operation, "WRITE") == 0) {
        write_count++;
    } else if (strcmp(operation, "UNLINK") == 0) {
        unlink_count++;
    } else if (strcmp(operation, "RENAME") == 0) {
        rename_count++;
    }
    // check_frequency_and_alert에 current_pid 인자 전달
    return check_frequency_and_alert(current_pid); 
}


// --------------------------------------------------------
// SECTION 3: B 역할 헬퍼 함수 구현 (SCORE MANAGEMENT)
// --------------------------------------------------------
// (이전과 동일한 Score 관리 헬퍼 함수)
ProcessScore* find_or_create_score_entry(pid_t pid) {
    for (int i = 0; i < g_process_count; i++) {
        if (g_score_table[i].pid == pid) {
            return &g_score_table[i];
        }
    }
    
    if (g_process_count < MAX_TRACKED_PIDS) {
        ProcessScore *new_entry = &g_score_table[g_process_count];
        new_entry->pid = pid;
        new_entry->malice_score = 0;
        new_entry->last_write_time = time(NULL);
        g_process_count++;
        return new_entry;
    }
    
    fprintf(stderr, "오류: 최대 PID 추적 개수 초과!\n"); 
    return NULL;
}

void update_malice_score(pid_t pid, int added_score) {
    ProcessScore *entry = find_or_create_score_entry(pid);
    
    if (entry) {
        entry->malice_score += added_score;
        entry->last_write_time = time(NULL);
    }
}

int get_malice_score(pid_t pid) {
    ProcessScore *entry = find_or_create_score_entry(pid);
    if (entry) {
        return entry->malice_score;
    }
    return 0;
}


// --------------------------------------------------------
// SECTION 4: FUSE 콜백 함수 구현 (CONTROL & PASS-THROUGH)
// --------------------------------------------------------
// (콜백 함수들은 이전과 동일하며, 경고는 모두 해결되었습니다.)

static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/')
            path++;
        strncpy(relpath, path, PATH_MAX);
    }
}

// getattr 함수 (경고 수정)
static int myfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void) fi; 
    int res; 
    char relpath[PATH_MAX]; 
    get_relative_path(path, relpath);
    res = fstatat(base_fd, relpath, stbuf, AT_SYMLINK_NOFOLLOW);
    if (res == -1) {
        return -errno; 
    }
    return 0;
}

static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    DIR *dp; struct dirent *de; int fd; (void) offset; (void) fi; (void) flags;
    char relpath[PATH_MAX]; get_relative_path(path, relpath);
    fd = openat(base_fd, relpath, O_RDONLY | O_DIRECTORY);
    if (fd == -1) return -errno;
    dp = fdopendir(fd);
    if (dp == NULL) { close(fd); return -errno; }
    while ((de = readdir(dp)) != NULL) {
        struct stat st; memset(&st, 0, sizeof(st)); st.st_ino = de->d_ino; st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, 0)) break;
    }
    closedir(dp); return 0;
}
static int myfs_open(const char *path, struct fuse_file_info *fi) {
    int res; char relpath[PATH_MAX]; get_relative_path(path, relpath);
    res = openat(base_fd, relpath, fi->flags);
    if (res == -1) return -errno;
    fi->fh = res; return 0;
}
static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    int res; char relpath[PATH_MAX]; get_relative_path(path, relpath);
    res = openat(base_fd, relpath, fi->flags | O_CREAT, mode);
    if (res == -1) return -errno;
    fi->fh = res; return 0;
}
static int myfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    int res; 
    res = pread(fi->fh, buf, size, offset);
    if (res == -1) {
        res = -errno;
    } 
    return res;
}

// write 함수 (Malice Score 로직 통합)
static int myfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;
    
    // 1. A 역할로부터 1초간 누적된 '벌점'을 받음 (Penalty Score)
    int penalty_score = monitor_operation("WRITE", buf, size, current_pid);

    // 2. B 역할의 PID별 누적 Score에 벌점을 반영
    update_malice_score(current_pid, penalty_score);

    // 3. 최종 Kill 판단
    if (get_malice_score(current_pid) >= KILL_THRESHOLD) {
        fprintf(stderr, "🚨 [KILL] 최종 누적 점수 %d, 임계값 %d 초과! PID %d 강제 종료.\n", 
                get_malice_score(current_pid), KILL_THRESHOLD, current_pid);
        
        if (kill(current_pid, SIGKILL) == -1) {
            fprintf(stderr, "킬 명령어 실패: %s\n", strerror(errno));
        }
        return -EIO; 
    }

    // 4. 정상 연산 실행 (Pass-through)
    int res;
    res = pwrite(fi->fh, buf, size, offset);
    if (res == -1) {
        res = -errno;
    }
    return res;
}

static int myfs_release(const char *path, struct fuse_file_info *fi) {
    close(fi->fh);
    return 0;
}

// unlink 함수 (A 역할 통합)
static int myfs_unlink(const char *path) {
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;
    
    int penalty_score = monitor_operation("UNLINK", NULL, 0, current_pid);
    update_malice_score(current_pid, penalty_score); 

    if (get_malice_score(current_pid) >= KILL_THRESHOLD) {
        fprintf(stderr, "🚨 [KILL] UNLINK 누적 점수 초과! PID %d 강제 종료.\n", current_pid);
        if (kill(current_pid, SIGKILL) == -1) {
            fprintf(stderr, "킬 명령어 실패: %s\n", strerror(errno));
        }
        return -EIO;
    }
    
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    res = unlinkat(base_fd, relpath, 0);
    if (res == -1) return -errno;
    return 0;
}

// rename 함수 (A 역할 통합)
static int myfs_rename(const char *from, const char *to, unsigned int flags) {
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;

    int penalty_score = monitor_operation("RENAME", NULL, 0, current_pid);
    update_malice_score(current_pid, penalty_score); 

    if (get_malice_score(current_pid) >= KILL_THRESHOLD) {
        fprintf(stderr, "🚨 [KILL] RENAME 누적 점수 초과! PID %d 강제 종료.\n", current_pid);
        if (kill(current_pid, SIGKILL) == -1) {
            fprintf(stderr, "킬 명령어 실패: %s\n", strerror(errno));
        }
        return -EIO;
    }
    
    int res;
    char relfrom[PATH_MAX];
    char relto[PATH_MAX];
    get_relative_path(from, relfrom);
    get_relative_path(to, relto);
    if (flags) return -EINVAL;
    res = renameat(base_fd, relfrom, base_fd, relto);
    if (res == -1) return -errno;
    return 0;
}

static int myfs_mkdir(const char *path, mode_t mode) {
    int res; char relpath[PATH_MAX]; get_relative_path(path, relpath); res = mkdirat(base_fd, relpath, mode);
    if (res == -1){ 
    return -errno;}
    return 0;
}
static int myfs_rmdir(const char *path) {
    int res; char relpath[PATH_MAX]; get_relative_path(path, relpath); res = unlinkat(base_fd, relpath, AT_REMOVEDIR);
    if (res == -1) {
    return -errno; }
    return 0;
}
static int myfs_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi) {
    int res; char relpath[PATH_MAX]; get_relative_path(path, relpath);
    if (fi != NULL && fi->fh != 0) { res = futimens(fi->fh, tv); } 
    else { res = utimensat(base_fd, relpath, tv, 0); }
    if (res == -1) {
    return -errno;}
    return 0;
}


// 파일시스템 연산자 구조체
static const struct fuse_operations myfs_oper = {
    .getattr    = myfs_getattr,
    .readdir    = myfs_readdir,
    .open       = myfs_open,
    .create     = myfs_create,
    .read       = myfs_read,
    .write      = myfs_write,
    .release    = myfs_release,
    .unlink     = myfs_unlink,
    .mkdir      = myfs_mkdir,
    .rmdir      = myfs_rmdir,
    .rename     = myfs_rename,
    .utimens    = myfs_utimens,  
};


int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mountpoint>\n", argv[0]);
        return -1;
    }

    // 마운트 포인트 경로를 저장
    char *mountpoint = realpath(argv[argc - 1], NULL);
    if (mountpoint == NULL) {
        perror("realpath");
        return -1;
    }

    // 1. 과제에서 지정한 공격 및 보호 대상 경로 획득 (백엔드 경로)
    const char *home_dir = getenv("HOME");
    if (!home_dir) {
    	fprintf(stderr, "Error: HOME environment variable not set.\n");
        return -1;
    }
    
    char backend_path[PATH_MAX];
    // '/home/계정명/workspace/target' 경로 구성
    snprintf(backend_path, PATH_MAX, "%s/workspace/target", home_dir);

    // 2. 백엔드 디렉터리를 엽니다. (base_fd 획득)
    fprintf(stderr, "INFO: Protecting backend path: %s\n", backend_path);
    
    base_fd = open(backend_path, O_RDONLY | O_DIRECTORY);
    if (base_fd == -1) {
	perror("Error opening backend directory");
	return -1;
    }

    // FUSE 파일시스템 실행
    int ret = fuse_main(args.argc, args.argv, &myfs_oper, NULL);

    close(base_fd);
    return ret;
}

