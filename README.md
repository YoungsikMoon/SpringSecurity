# Spring Security · 세션 인증과 권한 제어

회원가입부터 폼 로그인·세션 관리·경로별 권한 검사까지 구현한 학습 프로젝트입니다. 사용자 조회와 비밀번호 검증이 Spring Security의 인증 흐름에 어떻게 연결되는지 살펴볼 수 있습니다.

**환경:** Java 17 · Spring Boot 3.4.5 · Spring Security · JPA · MySQL · Mustache

## 구현과 코드

- 회원가입 시 BCrypt 해시 저장과 기본 `ROLE_USER` 부여
- `/login` 폼과 `/loginProc` 인증 처리, `/logout` 로그아웃
- `/admin/**` ADMIN, `/my/**` USER 권한 설정
- 로그인 시 세션 ID 변경, 동시 세션 1개 제한 및 신규 로그인 차단 설정

- [SecurityConfig.java](src/main/java/com/example/testsecurity/config/SecurityConfig.java)
- [JoinService.java](src/main/java/com/example/testsecurity/service/JoinService.java)
- [CustomUserDetailsService.java](src/main/java/com/example/testsecurity/service/CustomUserDetailsService.java)
- [UserEntity.java](src/main/java/com/example/testsecurity/entity/UserEntity.java)

## 로컬 실행

JDK 17과 MySQL을 준비합니다. [application.properties](src/main/resources/application.properties)의 DB 연결은 자신의 개발 환경에 맞춰 수정하거나 `SPRING_DATASOURCE_URL`, `SPRING_DATASOURCE_USERNAME`, `SPRING_DATASOURCE_PASSWORD` 환경변수로 지정하세요. `ddl-auto=none`이므로 엔티티에 맞는 테이블을 미리 준비해야 합니다.

```sh
./gradlew bootRun
```

Windows에서는 `gradlew.bat bootRun`을 사용합니다. 실행 후 `/join`과 `/login`에서 가입·로그인 흐름을 확인할 수 있습니다.

## 현재 범위

기본 인증 동작을 익히기 위한 예제입니다. CSRF가 비활성화되어 있으므로 인터넷에 그대로 배포하기 위한 보안 설정은 아닙니다. 운영 적용 시 CSRF, 입력 검증, 실패 응답과 계정·권한 관리 정책을 별도로 설계해야 합니다.
