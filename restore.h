#ifndef restore_h
#define restore_h

#include <stddef.h>

/* 복구 모듈 초기화 함수
 fuse가 마운트되기 전에 호출됨(= target열고 base_fd획득 후, 
 fuse_main()함수 호출 전) 
 - home_dir: 환경 변수 $HOME경로
 - target_path: fuse백엔드 경로 */
int restore_init(const char *home_dir, const char *target_path);

/* CoW(Copy-on-write) 백업 함수
- myfs_write에서 호출되어 파일이 변조 직전에 원본 백업*/
void restore_backup_on_write(const char *path, int base_fd);

#endif