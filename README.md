# 함께하는 유한 · 임직원 사회공헌 페이지

GitHub 저장소를 Cloudflare **Worker**(정적 파일 + 서버 코드)로 배포하는 직원용 페이지예요.
화면은 `public/`, 서버(API)는 `src/`에 있어요. 관리자 화면은 아직 없고, 관리자용 API만 준비되어 있어요.

```
public/          직원용 화면 (index.html, 로고, 보안 헤더)
src/worker.js    시작 파일: /api/* 는 서버 코드로, 나머지는 화면 파일로
src/api.js       서버 API
schema.sql       데이터베이스(D1) 구조
seed/seed.sql         실제 공고 1건 + 푸터 문의처
seed/seed-sample.sql  화면 확인용 예시 공고·활동 기록 (선택)
seed/sample-photos/   예시 사진 (선택)
wrangler.toml    Cloudflare 설정 (D1 ID를 넣어야 해요)
```

---

## 배포 순서

1. **D1** `yuhan-csr` 만들기 → 콘솔에서 `schema.sql` → `seed/seed.sql` (→ 원하면 `seed/seed-sample.sql`) 실행
2. **R2** 버킷 `yuhan-csr-photos` 만들기 (공개 액세스는 켜지 않기)
3. D1 **개요**의 데이터베이스 ID를 복사해서, GitHub에서 `wrangler.toml`의 `database_id = "여기에-D1-데이터베이스-ID"` 자리에 붙여 넣고 커밋
4. **Workers 및 Pages → 만들기 → Git 저장소 가져오기** → 이 저장소 선택
   - 빌드 명령: 비워 두기
   - 배포 명령: `npx wrangler deploy` (기본값)
5. **Turnstile** 위젯 만들기 (도메인: 배포 후 받은 `yuhan-csr.<계정>.workers.dev`, 모드: 관리형) → 사이트 키·비밀 키 복사
6. Worker → **설정 → 변수 및 비밀** 에 추가
   | 이름 | 종류 | 값 |
   |---|---|---|
   | `TURNSTILE_SITE_KEY` | 텍스트 | Turnstile 사이트 키 |
   | `TURNSTILE_SECRET_KEY` | 비밀 | Turnstile 비밀 키 |
   | `ADMIN_PASSWORD` | 비밀 | 관리자 비밀번호 (16자 이상 권장) |
   | `SESSION_SECRET` | 비밀 | 아무 긴 무작위 문자열 (40자 이상) |
7. **배포** 탭에서 다시 배포 (또는 GitHub에 아무 커밋)
8. 회사 도메인을 쓰려면 Worker **도메인** 탭에서 연결하고, 같은 도메인을 Turnstile에도 추가

D1·R2 연결은 `wrangler.toml`에 적혀 있어서 대시보드에서 따로 바인딩하지 않아도 돼요.

### 확인
- 홈에 공고·활동 기록이 보이는지
- 사이트 신청 공고에서 신청 → 새로 고침해도 "신청이 완료되었어요"가 보이는지 → 취소
- 후기 올리기 → "담당자 확인 후 공개돼요" 메시지
- 아이디어 제안 → 공감

---

## 보안 장치

| 항목 | 내용 |
|---|---|
| 관리자 | 비밀번호는 서버 비밀값에만 저장. 로그인하면 8시간짜리 HttpOnly·Secure·SameSite=Strict 쿠키 발급. 15분에 5번 틀리면 잠금 |
| 신청 정보 | 이름·사번·답변은 관리자 API로만 조회. 공개 화면에는 인원수만 |
| 중복 신청 | 공고마다 사번 1번만 |
| 수정·취소 | 신청할 때 발급한 코드가 있어야 가능 (서버에는 해시만 저장, 코드는 신청한 브라우저에만) |
| 스팸 | Turnstile 로봇 확인, IP별 횟수 제한(원본 IP 대신 해시 저장), 링크 차단, 같은 글 반복 차단 |
| 후기·사진 | 관리자가 승인해야 공개. 승인 전 사진은 외부에서 열람 불가 |
| 업로드 | JPG·PNG·WEBP만, 파일 내용으로 형식 확인, 5MB 제한 |
| 입력 검증 | 화면과 같은 규칙을 서버에서 다시 검사 (사번 6자리, 소속 3종, 민감 문항 차단, 네이버폼 주소만 허용) |
| 다른 사이트 요청 | 다른 출처에서 보낸 쓰기 요청 차단 |
| 헤더 | CSP, HSTS, 클릭재킹 방지, 검색엔진 차단 (`public/_headers`) |

> 직원 로그인이 없어서 링크를 아는 사람은 누구나 들어올 수 있어요. 회사에 고정 IP가 있으면 Cloudflare **WAF 사용자 지정 규칙**으로 사내 IP만 허용하는 걸 권장해요.

---

## 관리자 화면이 생기기 전 임시 관리 (D1 콘솔)

후기 승인:
```sql
SELECT id, author, text, photos FROM stories WHERE status = 'pending';
UPDATE stories SET status = 'approved' WHERE id = '후기ID';
-- 그 후기에 사진이 있으면 사진도 공개
UPDATE photos SET status = 'public' WHERE key IN ('사진키1', '사진키2');
```

신청자 명단:
```sql
SELECT p.json_title, s.org, s.name, s.emp_no, s.answers, datetime(s.created_at/1000, 'unixepoch', '+9 hours') AS 신청시각
FROM signups s JOIN (SELECT id, json_extract(data, '$.title') AS json_title FROM programs) p ON p.id = s.program_id
ORDER BY s.program_id, s.created_at;
```

예시 데이터 지우기:
```sql
DELETE FROM programs WHERE json_extract(data, '$.sample') = 1;
DELETE FROM archive  WHERE json_extract(data, '$.sample') = 1;
```

문의처 바꾸기:
```sql
UPDATE config SET v = 'ESG2팀 김지은 사원(0663)' WHERE k = 'contact';
```

## 관리자 API (관리자 화면에서 쓸 주소)

모두 `/api/admin/...`, 로그인 쿠키 필요.

| 방식 | 주소 | 하는 일 |
|---|---|---|
| POST | `/login` `{password}` | 로그인 |
| POST | `/logout` | 로그아웃 |
| GET | `/all` | 공고·기록·후기(전체)·제안·신청자·관리 기록 |
| POST | `/upload` | 사진 업로드 (바로 공개) |
| PUT / DELETE | `/programs/:id` | 공고 저장 / 삭제 |
| PUT / DELETE | `/archive/:id` | 활동 기록 저장 / 삭제 |
| PATCH / DELETE | `/stories/:id` `{status}` | 후기 승인·숨김 / 삭제 |
| PATCH / DELETE | `/ideas/:id` `{status}` | 제안 상태 / 삭제 |
| DELETE | `/signups/:id` | 신청 삭제 |
| PUT | `/config` `{contact}` | 문의처 |

## 로컬에서 돌려 보기 (선택)
```bash
npm i -g wrangler
cp .dev.vars.example .dev.vars        # 로컬용 관리자 비밀번호
npx wrangler d1 execute yuhan-csr --local --file schema.sql
npx wrangler d1 execute yuhan-csr --local --file seed/seed.sql
npx wrangler dev
```
