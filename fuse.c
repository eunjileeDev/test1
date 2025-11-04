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
#include "entropy.h" // 엔트로피 계산 선언
#include "analyzer.h" // 최종 모니터링 함수 선언

#define MAX_TRACKED_PIDS 100 // 최대 추적 가능 프로세스 개수 (제한적)
#define KILL_THRESHOLD 80    // Malice Score 강제 종료 임계값 ((임시))

static int base_fd = -1;


// PID별 Malice Score 및 행동 정보를 저장할 구조체
typedef struct {
    pid_t pid;             // 프로세스 ID
    int malice_score;      // 누적 악성도 점수
    time_t last_write_time; // 마지막 쓰기 연산 시각 (빈도 탐지용)
    char proc_name[32];  //  프로세스 이름 저장
} ProcessScore;

// 전역 Score 테이블 (배열로 구현)
ProcessScore g_score_table[MAX_TRACKED_PIDS];
int g_process_count = 0; // 현재 추적 중인 프로세스 개수

// B 역할 헬퍼 함수 선언 (본문에서 구현됨)
ProcessScore* find_or_create_score_entry(pid_t pid);
void update_malice_score(pid_t pid, int added_score);
int get_malice_score(pid_t pid);

//entropy로직(entropy.c통합함)
double calculate_entropy(const char *buffer, size_t size){
        if (size == 0) { // 데이터의 크기가 0이면 계산 안하기
                return 0.0;
        }

        long long counts[256]; //0~255 까지 256 개의 값이 각각 몇 번 등장했는지 저장하는 배열
        memset(counts, 0, sizeof(counts)); //mamset() 는 배열 256 개의 칸을 0으로 초기화하는 것

        for (size_t i =0; i<size; i++){ // 0번째부터 (size-1) 바이트까지 하나씩 순회
                counts[(unsigned char) buffer[i]]++; //unsigned로 음수값은 저장안되게
        } //예) i =65('A') 이면 counts[65] 의 값을 +1하는 것임

        double entropy = 0.0; //엔트로피 값을 누적하는 변수 선언

        for (int i = 0; i < 256; i++){
                if (counts[i] == 0){//바이트값이 데이터에 한 번도 등장하지 않으면 확률p =0 == 연산 안 함
                        continue;
                }

                double probability = (double)counts[i] / size; /*  왜 size로 나누는가?

counts[i]는 버퍼 안에서 특정 바이트 값이 등장한 횟수
예:

전체 데이터 크기 = 1000바이트

0x41('A') 바이트가 50번 등장

그러면 'A'가 등장할 확률은:
𝑝(′𝐴′)=50/1000=0.05

즉 전체 데이터 중에서 해당 바이트가 차지하는 비율을 구하는 것이기 때문에 총 데이터 크기인 size로 나눠주는 것
*/

                entropy -= probability * log2(probability); //엔트로피 공식에 의해 각 바이트를 누적한 최종 엔트로피 계산
        }
        return entropy;
}
/*만약 데이터가 'A'로만 가득 차 있다면 (예: "AAAAA"):
     * P('A') = 1.0, P(나머지) = 0.
     * entropy = - (1.0 * log2(1.0)) = - (1.0 * 0) = 0.0 */
//동일한 문자가 반복되면 엔트로피 낮아지는 저엔트로피 우회방법을 red 팀이 사용가능함 -> 막는 방법도 추가로 고려해봐야함


//탐지 분석 로직(재린) 
//임계치 및 가중치 정의
//행동(operation) 에 따라 가중치 부여
//가중치 고려해야 할 점-> red 팀한테 코드 받아보고 평균적인 임계치랑 가중치 점수 수정해야
#define WEIGTH_WRITE 1 //myfs_write 호출시 기본 점수 1
#define WEIGTH_MALICIOUS 3 // myfs_unlink 나 _rename 호출시 점수 3 (더 많은 가중치 부여)
#define WEIGHT_HIGH_ENTROPY 5 // 엔트로피 4.2 이상이면 5점 추가
#define ENTROPY_THRESHOLD 4.2 // 대략적으로 정한 엔트로피 임계치


//반복 행위에 대한  (빈도에 따라) 임계치
#define TIME_SECONDS 1 // 1초 단위 검사
#define WRITE_THRESHOLE_PER_1 100 //1초에 write 100회까지
#define UNLINK_THRESHOLE_PER_1 10 //1초에 unlink 10회까지
#define RENAME_THRESHOLE_PER_1 10 //1초에 rename 10회까지

//빈도가 임계치 넘었을 때  추가 벌점
#define PENALTY_HIGh_WRITE 50 // 쓰기 100회 넘었을 때 추가로 벌점 부여
#define PENALTY_HIGh_UNLINK 100 // 언링크 10회 넘었을 때 추가 벌점
#define PENALTY_HIGh_RENAME 100

#define FINAL_MALICE_THRESHOLD 200 // 총 누적 점수가 200이 넘으면 최종 악성 판단
static int write_count = 0;
static int unlink_count = 0;
static int rename_count = 0;
static int total_malice_score = 0;
static time_t start_time = 0;

//단일 연산에 대한 점수 계산
static int get_score(const char* operation, const char* buf, size_t size) { //operation은 기본함수 구현하는 사람한테 받아와
야함
        int score_to_add = 0;

        if (strcmp(operation, "WRITE") == 0) {
                score_to_add += WEIGHT_WRITE; //1점주추가하기

                if (buf != NULL && size > 0) {
                        double entropy = calculate_entropy(buf,size); //쓰기 했으니까 검사함
                        if (entropy > ENTROPY_THRESHOLD) {
                                score_to_add += WEIGTH_HIGH_ENTROPY; //5점 추가정

                        }
                }

        }

        else if (strcmp(operation, "UNLINK") == 0 || strcmp(operation, "RENAME") == 0) {

                score_to_add += WEIGHT_MALICIOUS; //3점 추가
        }

        return score_to_add; //일단은 쓰기, rename, unlink 만 점수부여 
}

//총 점수 계산 및 악성인지 판단하기 과정(1초 단위)
static int check_frequency_and_alert(pid_t current_pid){
        time_t current_time = time(NULL);
        int is_malicious = 0;

        if(start_time == 0) {
                start_time = current_time;
                return 0 ; // 첫 호출은 1초 대기
        }
        // 1초가 안 지났으면 검사 X
        if (current_time - start_time < TIME_SECONDS){
                return 0;
        }
        // 임계치 넘으면 50점 벌점 추가
        if (unlink_count > UNLINK_THRESHOLD_PER_1){
            total_malice_score += PENALTY_HIGH_UNLILNK;
        }
        }
        //임계치 넘으면 100점 벌점 추가
        if (unlink_count > UNLINK_THRESHOLD_PER_1){
                total_malice_score += PENALTY_HIGH_UNLILNK;
        }
        //임계치 넘으면 100점 벌점 추가
        if (rename_count > RENAME_THRESHOLD_PER_1){
                total_malice_score += PENALTY_HIGH_RENAME;
        }
       // 전체 총합 점수가 임계치 넘으면 악성으로 판
        if (total_malice_score > FINAL_MALICE_THRESHOLD) {
                printf("헉!!!!!!");
                printf("malice detected (PID:%d)\n", current_pid); //fuse 로부터 전달받아 저장해둔  공격자 pid
                printf("malice score : %d (threshold: %d)\n", total_malice_score, FINAL_MALICE_THRESHOLD);
                printf("각 행동 횟수 :(w : %d. U : %d, R:%d)\n", write_count, unlink_count, rename_count);

                is_malicious = 1; // 악성으로 판정
                }
        // 다시 다음 1초를 위해 초기화해줌
        total_malice_score = 0;
        write_count = 0;
        unlink_count = 0;
        rename_count = 0;
        start_time = current_time;
        
        return is_malicious;
}

int monitor_operation(const char* operation, const char* buf, size_t size){

        int content_score = get_score(operation, buf, size); //계산기로 단일 점수 계산
        total_malice_score += content_score; // 장부에 점수와 횟수 누적

        if (strcmp(operation, "WRITE") == 0) {
                write_count++;
        } else if (strcmp(operation, "UNLINK") == 0) {
                unlink_count++;
        } else if (strcmp(operation, "RENAME") == 0) {
                rename_count++;
        }
        return check_frequency_and_alert(current_pid); //monitor 가 1초마다 검사하고 결과 반환 (악성이면 1)
}

// ProcessScore 엔트리를 찾거나 새로 생성하여 포인터를 반환
ProcessScore* find_or_create_score_entry(pid_t pid) {
    // 1. 기존 엔트리 검색
    for (int i = 0; i < g_process_count; i++) {
        if (g_score_table[i].pid == pid) {
            // PID가 이미 존재하면 해당 엔트리 반환
            return &g_score_table[i];
        }
    }
    
    // 2. 새 엔트리 생성
    if (g_process_count < MAX_TRACKED_PIDS) {
        ProcessScore *new_entry = &g_score_table[g_process_count];
        // 새로운 엔트리 초기화
        new_entry->pid = pid;
        new_entry->malice_score = 0;
        new_entry->last_write_time = time(NULL);
        g_process_count++; // 추적 중인 프로세스 수 증가
        
        // fprintf(stderr, "Malice Score: 새 PID %d 추적 시작.\n", pid); // 디버깅용
        return new_entry;
    }
    
    // 3. 배열이 가득 찼을 때 (오류 처리: 널 포인터 반환)
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

//FUSE 콜백 함수
static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/')
            path++;
        strncpy(relpath, path, PATH_MAX);
    }
}

// getattr 함수 구현
static int myfs_getattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi) {
    (void) fi;
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = fstatat(base_fd, relpath, stbuf, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;

    return 0;
}

// readdir 함수 구현
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

// open 함수 구현
static int myfs_open(const char *path, struct fuse_file_info *fi) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = openat(base_fd, relpath, fi->flags);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

// create 함수 구현
static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = openat(base_fd, relpath, fi->flags | O_CREAT, mode);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

// read 함수 구현
static int myfs_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
    int res;

    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

// write 함수 구현
static int myfs_write(const char *path, const char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    // 1. PID 획득
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;
    
    // 2. Score 계산 및 Kill 판단 (친구 코드 통합)
    // monitor_operation 호출: 악성 판단 시 1을 반환합니다.
    int is_malicious = monitor_operation("WRITE", buf, size, current_pid);

    // ************* B 역할의 Malice Score 갱신/Kill 로직 변경 *************
    // A 역할 코드는 자체적으로 Score를 관리하고 최종 악성 여부(1/0)만 반환하도록 설계되었습니다.
    // 따라서 B 역할은 Score 누적 대신 'is_malicious'만 확인하여 Kill을 실행합니다.

    if (is_malicious == 1) { // A 역할의 monitor_operation이 악성으로 판단했으면
        fprintf(stderr, "[KILL] 랜섬웨어 행동 탐지 완료! PID %d 강제 종료됩니다.\n", current_pid);
        
        // 제한 조치: 강제 종료 실행
        if (kill(current_pid, SIGKILL) == -1) {
            fprintf(stderr, "킬 명령어 실패: %s\n", strerror(errno));
        }

        // 쓰기 연산 차단 및 에러 반환
        return -EIO; 
    }

    // 3. 정상 연산 실행 (Pass-through)
    int res;
    res = pwrite(fi->fh, buf, size, offset);
    if (res == -1) {
        res = -errno;
    }
    return res;
}

// release 함수 구현
static int myfs_release(const char *path, struct fuse_file_info *fi) {
    close(fi->fh);
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;

    reset_malice_score(current_pid); //파일 닫으면 해당 p의 score초기화
    return 0;
}

// unlink 함수 구현 (파일 삭제)
static int myfs_unlink(const char *path) {
    // A 역할의 monitor_operation 호출 및 Kill 로직 삽입 필요
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;

    if (monitor_operation("UNLINK", NULL, 0, current_pid) == 1) {
        fprintf(stderr, "[KILL] UNLINK 행동 탐지! PID %d 강제 종료됩니다.\n", current_pid);
        if (kill(current_pid, SIGKILL) == -1) {
            fprintf(stderr, "킬 명령어 실패: %s\n", strerror(errno));
        }
        return -EIO;
    }

    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    res = unlinkat(base_fd, relpath, 0);
    if (res == -1)
        return -errno;
    return 0;
}

// mkdir 함수 구현 (디렉터리 생성)
static int myfs_mkdir(const char *path, mode_t mode) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = mkdirat(base_fd, relpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

// rmdir 함수 구현 (디렉터리 삭제)
static int myfs_rmdir(const char *path) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = unlinkat(base_fd, relpath, AT_REMOVEDIR);
    if (res == -1)
        return -errno;

    return 0;
}

// rename 함수 구현 (파일/디렉터리 이름 변경)
static int myfs_rename(const char *from, const char *to, unsigned int flags) {
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;

    if (monitor_operation("RENAME", NULL, 0, current_pid) == 1) {
        fprintf(stderr, "[KILL] RENAME 행동 탐지! PID %d 강제 종료됩니다.\n", current_pid);
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
    if (flags)
        return -EINVAL;

    res = renameat(base_fd, relfrom, base_fd, relto);
    if (res == -1)
        return -errno;

    return 0;
}

// utimens 함수 구현
static int myfs_utimens(const char *path, const struct timespec tv[2],
                        struct fuse_file_info *fi) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    if (fi != NULL && fi->fh != 0) {
        // 파일 핸들이 있는 경우
        res = futimens(fi->fh, tv);
    } else {
        // 파일 핸들이 없는 경우
        res = utimensat(base_fd, relpath, tv, 0);
    }
    if (res == -1)
        return -errno;

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

