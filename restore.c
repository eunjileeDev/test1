#include "restore.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

//?? 전역 변수: 최종적으로 확인된 백업 디렉터리의 절대 경로
static char g_backup_dir[PATH_MAX] = {0};

//?? 파일 복사를 위한 내부 도우미 함수 (이후 구현)
static int copy_file_data(int src_fd, int dest_fd);

// 백업 경로 설정 및 생성 함수 (초기화)
int restore_init(const char *home_dir, const char *target_path) {
    char workspace_path[PATH_MAX];
    char backup_path[PATH_MAX];
    
    // 1. workspace 경로 설정: $HOME/workspace
    snprintf(workspace_path, PATH_MAX, "%s/workspace", home_dir);

    // 2. target 밖의 백업 디렉토리 경로 설정: $HOME/workspace/restore_backup
    snprintf(backup_path, PATH_MAX, "%s/restore_backup", workspace_path);

    // 3. workspace 디렉터리 생성 (없을 경우 대비)
    // 권한: 0755 (소유자:rwx, 그룹:r-x, 기타:r-x)
    if (mkdir(workspace_path, 0755) == -1 && errno != EEXIST) {
        perror("RESTORE: Error creating workspace directory");
        return -1;
    }
    
    // 4. 최종 백업 디렉터리 생성 (없을 경우 대비)
    // 권한: 0700 (소유자:rwx, 그룹:---, 기타:---)
    // -> 랜섬웨어 프로세스(다른 사용자)가 접근하지 못하도록 격리
    if (mkdir(backup_path, 0700) == -1 && errno != EEXIST) {
        perror("RESTORE: Error creating restore_backup directory");
        return -1;
    }

    // 5. 생성된 백업 경로를 전역 변수에 저장 (절대 경로로 변환)
    if (realpath(backup_path, g_backup_dir) == NULL) {
        perror("RESTORE: realpath for backup dir failed");
        return -1;
    }
    
    // FUSE 실행 로그에 백업 경로 초기화 완료 메시지 출력
    fprintf(stderr, "RESTORE: Backup path initialized successfully at: %s\n", g_backup_dir);
    
    return 0;
}

// --------------------------------------------------------
// 이후 구현될 함수들의 빈 (Stub) 정의
// --------------------------------------------------------

void restore_backup_on_write(const char *path, int base_fd) {
    // [TODO] CoW 백업 로직 구현
    // 1. g_backup_dir에 백업 파일이 이미 있는지 확인 (stat)
    // 2. 없으면, base_fd와 path를 이용해 원본 파일을 열기 (openat)
    // 3. g_backup_dir에 백업 파일 생성 (open)
    // 4. copy_file_data()로 내용 복사
    // 5. 시간 측정
}

void restore_backup_file(const char *path, int base_fd) {
    // [TODO] 롤백 복구 로직 구현
    // 1. g_backup_dir에 백업 파일이 있는지 확인 (stat)
    // 2. 있으면, 백업 파일을 열기 (open)
    // 3. base_fd와 path를 이용해 원본 파일 열기 (openat, O_TRUNC)
    // 4. copy_file_data()로 내용 덮어쓰기
    // 5. 시간 측정
}

static int copy_file_data(int src_fd, int dest_fd) {
    // [TODO] 파일 복사 로직 구현 (read/write 반복)
    return 0; 
}