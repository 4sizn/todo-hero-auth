# todo-hero-auth — 웹 계정 인증 핸드오프 페이지 (호스팅 미러)

todo-hero(게임)의 email/password 계정 인증을 처리하는 **정적 페이지**. GitHub Pages 로 서빙된다.

- **canonical 소스**: 메인 repo `todo-hero` 의 `web/auth/` (ADR-S-005). 이 repo 는 Pages 배포 미러.
- 게임이 시스템 브라우저로 `index.html#nonce=...&mode=...` 를 열면, 폼이 Supabase Edge Function
  `auth-handoff-submit` 으로 자격증명만 POST(토큰 미수신). 성공 시 `todohero://auth-done` 트리거.
- 임베드된 anon key 는 public-safe(publishable, RLS 보호). service_role 키는 없음.
- 배포 URL 을 Supabase Edge secret `AUTH_WEB_URL` 로 설정해야 begin 이 web_url 을 조립한다.
