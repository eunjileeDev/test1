#include <math.h>
#include <string.h>
#include <stddef.h>

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
/* 동일한 문자가 반복되면 엔트로피 낮아지는 저엔트로피 우회방법을 red 팀이 사용가능함 -> 막는 방법도 추가로 고려해봐야함
