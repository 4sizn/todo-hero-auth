// 정적 인증 핸드오프 페이지 공개 설정 (ADR-S-005 PR-2).
//
// 여기 값은 모두 public-safe 다 — anon key 는 공개용(publishable)이고 RLS 가 데이터를 보호한다.
// 게임/모바일 번들(apps/game/config/supabase.json, apps/mobile/assets/config/supabase.json)과
// 동일 프로젝트 값. 정적 호스팅(GitHub Pages)엔 빌드타임 env 가 없어 여기 임베드한다.
//
// 보안 주의: service_role key 는 절대 여기 넣지 말 것(서버 Edge Function 전용).
window.TODO_HERO_AUTH_CONFIG = {
  SUPABASE_URL: "https://zbqtdhaqwjfazznxlzhr.supabase.co",
  SUPABASE_ANON_KEY:
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InpicXRkaGFxd2pmYXp6bnhsemhyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODAwNDYzMTYsImV4cCI6MjA5NTYyMjMxNn0.SFKiVpzMcuqfLV8EnJuyd_ZEF200Ddmm0ZEIYHLiXbw",
  // 인증 완료 후 기기 앱을 포그라운드로 띄우는 딥링크(payload 없음, 트리거만). 기기는 nonce 폴링으로 완료 감지.
  APP_RETURN_URL: "todohero://auth-done",
  // 비밀번호 재설정 이메일의 redirect_to 고정값. location 기반은 접근 경로에 따라 달라지므로 명시.
  AUTH_PAGE_URL: "https://4sizn.github.io/todo-hero-auth/",
};
