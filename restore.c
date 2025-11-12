#include "restore.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>

//백업dir 절대 주소(restore_init이 생성한) 저장
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
    
    fprintf(stderr, "RESTORE: 백업 경로 초기화 완료: %s\n", g_backup_dir);
    
    return 0;
}

// 이후 구현할 함수 일단 정의
void restore_backup_on_write(const char *path, int base_fd) {
    //루트 디렉토리(/)자체는 백업하지 않게 함
    if (strcmp(path, "/") == 0) {
        return;
    }
    //파일이름 추출
    const char *filename = strrchr(path, '/');
    if (filename) {
        filename++; // '/' 다음 문자(파일 이름)
    } else {
        filename = path; // '/'가 없는 경우 (경로 자체가 파일 이름)
    }

    // 백업 파일 경로 설정
    char backup_filepath[PATH_MAX];
    snprintf(backup_filepath, PATH_MAX, "%s/%s", g_backup_dir, filename);

    // 백업본 이미 있는지 확인
    struct stat st;
    if (stat(backup_filepath, &st) != -1) {
        return;
}

    //백업 시작(시간 측정 확인)
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    //원본 파일 열기
    char relpath[PATH_MAX];
    if (path[0] == '/') {
        strncpy(relpath, path + 1, PATH_MAX - 1);
        relpath[PATH_MAX - 1] = '\0';
    } else {
        strncpy(relpath, path, PATH_MAX - 1);
        relpath[PATH_MAX - 1] = '\0';
    }

    int src_fd = openat(base_fd, relpath, O_RDONLY);
    if (src_fd == -1) {
        fprintf(stderr, "RESTORE: 경고: 백업 위한 파일 %s 열기 불가: %s\n", relpath, strerror(errno));
        return;
    }

    //백업 파일 생성 (O_EXCL: 파일이 이미 있으면 열지말고 에러처리)
    int dest_fd = open(backup_filepath, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (dest_fd == -1) {
        close(src_fd);
        fprintf(stderr, "RESTORE: 경고: 백업파일 생성 불가 %s: %s\n", backup_filepath, strerror(errno));
        return;
    }

    //데이터 복사
    if (copy_file_data(src_fd, dest_fd) == 0) {
        fprintf(stderr, "RESTORE: 오리지널 파일 백업: %s\n", path);
    } else {
        // 복사 실패 시 생성된 파일 삭제
        unlink(backup_filepath);
        fprintf(stderr, "RESTORE: 백업 파일 쓰기 에러: %s\n", path);
    }
    close(src_fd);
    close(dest_fd);

    //시간 측정 결과 출력
    gettimeofday(&end_time, NULL); 
    long elapsed_us = (end_time.tv_sec - start_time.tv_sec) * 1000000L + 
                      (end_time.tv_usec - start_time.tv_usec);
    fprintf(stderr, "RESTORE: Backup/CoW time for %s: %ld us\n", path, elapsed_us);
}

//복구 함수
void restore_backup_file(const char *path, int base_fd) {
    
    //루트 디렉토리(/) 자체는 복구 대상 아님
    if (strcmp(path, "/") == 0) {
        return;
    }

    //파일 이름 추출
    const char *filename = strrchr(path, '/');
    if (filename) {
        filename++; // '/' 다음 문자
    } else {
        filename = path; // '/'가 없는 경우
    }

    //백업 파일 경로 설정
    char backup_filepath[PATH_MAX];
    snprintf(backup_filepath, PATH_MAX, "%s/%s", g_backup_dir, filename);

    // 원본 파일의 상대 경로 설정 (openat용)
    char relpath[PATH_MAX];
    if (path[0] == '/') {
        strncpy(relpath, path + 1, PATH_MAX - 1);
        relpath[PATH_MAX - 1] = '\0';
    } else {
        strncpy(relpath, path, PATH_MAX - 1);
        relpath[PATH_MAX - 1] = '\0';
    }

    struct stat st;
    if (stat(backup_filepath, &st) == -1) {
        fprintf(stderr, "RESTORE: 롤백 실패: 백업 파일 %s 없음\n", backup_filepath);
        return;
    }

    //롤백 시작 (시간 측정)
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);
    fprintf(stderr, "RESTORE: 롤백 시작... %s\n", path);

    //백업 파일 열기 (읽기 전용)
    int src_fd = open(backup_filepath, O_RDONLY);
    if (src_fd == -1) {
        perror("RESTORE: 롤백 실패: 백업 파일 열기 오류");
        return;
    }

    // 원본(target) 파일 열기 (덮어쓰기 + 생성)
    // O_TRUNC: 파일이 존재하면 내용을 지움 (암호화된 내용 삭제)
    // O_CREAT: 파일이 unlink로 삭제되었을 경우를 대비해 새로 생성
    int dest_fd = openat(base_fd, relpath, O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if (dest_fd == -1) {
        close(src_fd);
        perror("RESTORE: 롤백 실패: 원본 파일 열기 오류");
        return;
    }

    //데이터 복사 (롤백 실행)
    if (copy_file_data(src_fd, dest_fd) == 0) {
        fprintf(stderr, "RESTORE: 롤백 성공! 파일이 원본으로 복구됨: %s\n", path);
    } else {
        fprintf(stderr, "RESTORE: 롤백 중 데이터 복사 오류: %s\n", path);
    }

    close(src_fd);
    close(dest_fd);

    //시간 측정 결과 출력
    gettimeofday(&end_time, NULL);
    long elapsed_us = (end_time.tv_sec - start_time.tv_sec) * 1000000L +
                      (end_time.tv_usec - start_time.tv_usec);
    fprintf(stderr, "RESTORE: 롤백 소요 시간: %s: %ld us\n", path, elapsed_us);
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