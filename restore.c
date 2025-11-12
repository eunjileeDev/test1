#include "restore.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

//백업dir 주소(restore_init이 생성한) 저장
static char g_backup_dir[PATH_MAX] = {0};

//파일 복사를 위한 함수 (이후 구현)
static int copy_file_data(int src_fd, int dest_fd);

// 백업 경로 설정 및 생성 함수 (초기화)
int restore_init(const char *home_dir, const char *target_path) {
    char workspace_path[PATH_MAX];
    char backup_path[PATH_MAX];
    
    // workspace 경로 설정: $HOME/workspace
    snprintf(workspace_path, PATH_MAX, "%s/workspace", home_dir);

    // target 밖 백업dir 경로 설정: $HOME/workspace/restore_backup
    snprintf(backup_path, PATH_MAX, "%s/restore_backup", workspace_path);

    // workspace 디렉터리 생성 (혹시 없을때)
    // 권한: 0755 (소유자:rwx, 그룹:r-x, 기타:r-x)
    if (mkdir(workspace_path, 0755) == -1 && errno != EEXIST) {
        perror("RESTORE: Error creating workspace directory");
        return -1;
    }
    
    // 백업 디렉터리 생성
    // 권한: 0700 (소유자:rwx, 그룹:---, 기타:---)
    // -> 랜섬웨어 프로세스(다른 사용자)가 접근하지 못하도록 격리
    if (mkdir(backup_path, 0700) == -1 && errno != EEXIST) {
        perror("RESTORE: Error creating restore_backup directory");
        return -1;
    }

    //생성된 백업 경로를 전역 변수에 저장 (절대 경로로 변환)
    if (realpath(backup_path, g_backup_dir) == NULL) {
        perror("RESTORE: 백업 경로 저장에 실패했습니다.");
        return -1;
    }
    
    // FUSE 실행 로그에 백업 경로 초기화 완료 메시지 출력
    fprintf(stderr, "RESTORE: 백업 경로 초기화 완료: %s\n", g_backup_dir);
    
    return 0;
}

// 이후 구현할 함수 일단 정의
void restore_backup_on_write(const char *path, int base_fd) {
    // TODO: CoW 백업 로직 구현
    // 1. g_backup_dir에 백업 파일 이미 있는지 확인 (stat)
    // 2. 없으면 base_fd와 path 로 원본 파일 열기 (openat)
    // 3. g_backup_dir에 백업 파일 생성 (open)
    // 4. copy_file_data()로 내용 복사
    // 5. 시간 재기
}

void restore_backup_file(const char *path, int base_fd) {
    // TODO: 롤백 복구 로직 구현
    // 1. g_backup_dir에 백업 파일이 있는지 확인 (stat)
    // 2. 있으면, 백업 파일을 열기 (open)
    // 3. base_fd와 path를 이용해 원본 파일 열기 (openat, O_TRUNC)
    // 4. copy_file_data()로 내용 덮어쓰기
    // 5. 시간 측정
}

//카피 파일 복사 함수
static int copy_file_data(int src_fd, int dest_fd) {
    #define CHUNK_SIZE 4096 //4KB단위 복사
    char chunk[CHUNK_SIZE];
    ssize_t bytes_read;

    //원본 파일 포인터를 맨 앞으로
    if (lseek(src_fd, 0, SEEK_SET)==-1){
        perror("RESTORE: 파일 찾기 오류 발생");
        return -1;
    }

    //데이터 읽고 쓰기 반복
    while ((bytes_read = read(src_fd, chunk, CHUNK_SIZE)) > 0)
    {
        if(write(dest_fd, chunk, bytes_read) != bytes_read){
            perror("RESTORE: 목표 파일에 쓰기 실패");
            return -1;
        }
    }

    if (bytes_read == -1) {
        perror("RESTORE: 파일 읽기 실패");
        return -1; 
    }
    
    return 0; 
}