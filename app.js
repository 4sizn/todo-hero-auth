// Todo Hero 정적 인증 핸드오프 (ADR-S-005 PR-2).
//
// 보안 불변식:
//  - 토큰을 절대 다루지 않는다. 이 페이지는 email/password 와 nonce 만 서버로 보낸다.
//    auth-handoff-submit 은 {ok} 만 반환(세션은 서버 보관 → 기기가 claim). 토큰은 이 페이지에 안 온다.
//  - nonce 는 URL fragment(#)로 들어오며, 읽은 즉시 history.replaceState 로 주소창/히스토리에서 지운다.
//  - 사용자 입력은 textContent 로만 출력(innerHTML 금지) → XSS 방지.
(function () {
  "use strict";

  // 클릭재킹 방어: 프레임 안에서 로드되면 최상위로 탈출(Pages는 X-Frame-Options 헤더를 못 줌).
  if (window.top !== window.self) {
    try { window.top.location = window.self.location; } catch (e) { /* cross-origin frame */ }
  }

  var CFG = window.TODO_HERO_AUTH_CONFIG || {};
  var FUNCTIONS_BASE = (CFG.SUPABASE_URL || "").replace(/\/+$/, "") + "/functions/v1";
  var ANON_KEY = CFG.SUPABASE_ANON_KEY || "";
  var APP_RETURN_URL = CFG.APP_RETURN_URL || "todohero://auth-done";

  // --- fragment 에서 nonce/mode/recovery 파싱 후 즉시 strip ---
  var nonce = "";
  var mode = "login";
  var recoveryToken = "";
  (function readAndStripFragment() {
    var hash = location.hash || "";
    if (hash.charAt(0) === "#") hash = hash.slice(1);
    var params = new URLSearchParams(hash);
    nonce = (params.get("nonce") || "").trim();
    var m = (params.get("mode") || "").trim();
    if (m === "link" || m === "login" || m === "signup") mode = m;
    // Supabase recovery 이메일 콜백: type=recovery + access_token
    if (params.get("type") === "recovery") {
      recoveryToken = params.get("access_token") || "";
    }
    // 주소창·브라우저 히스토리에서 토큰 제거(보안). pushState 아님 — 히스토리 항목 교체.
    try {
      history.replaceState(null, document.title, location.pathname + location.search);
    } catch (e) {
      try { location.hash = ""; } catch (e2) { /* 무시 */ }
    }
  })();

  // --- DOM ---
  var $ = function (id) { return document.getElementById(id); };
  var els = {
    formView: $("form-view"), recoverView: $("recover-view"), resetView: $("reset-view"), doneView: $("done-view"),
    title: $("title"), subtitle: $("subtitle"),
    form: $("auth-form"), email: $("email"), password: $("password"), submitBtn: $("submit-btn"),
    toSignup: $("to-signup"), toLogin: $("to-login"), toRecover: $("to-recover"),
    msg: $("msg"),
    recoverForm: $("recover-form"), recoverEmail: $("recover-email"), recoverBtn: $("recover-btn"),
    backToLogin: $("back-to-login"), recoverMsg: $("recover-msg"),
    resetForm: $("reset-form"), resetPassword: $("reset-password"), resetBtn: $("reset-btn"), resetMsg: $("reset-msg"),
    doneTitle: $("done-title"), doneSub: $("done-sub"),
  };

  var VIEW = {
    link:   { title: "게임 계정에 이메일 연결", sub: "현재 게임 진행이 이 이메일·비밀번호 계정에 연결됩니다.", btn: "연결하기", pwAuto: "new-password", showSignup: false, showLogin: true },
    login:  { title: "로그인", sub: "기존 Todo Hero 계정으로 로그인합니다.", btn: "로그인", pwAuto: "current-password", showSignup: true, showLogin: false },
    signup: { title: "새 계정 만들기", sub: "새 Todo Hero 계정을 만듭니다.", btn: "가입하기", pwAuto: "new-password", showSignup: false, showLogin: true },
  };

  function setMessage(el, text, kind) {
    el.textContent = text || "";
    el.className = "msg" + (text ? " " + kind : "");
  }

  function applyMode(next) {
    if (!VIEW[next]) next = "login";
    mode = next;
    var v = VIEW[mode];
    els.title.textContent = v.title;
    els.subtitle.textContent = v.sub;
    els.submitBtn.textContent = v.btn;
    els.password.setAttribute("autocomplete", v.pwAuto);
    els.toSignup.className = v.showSignup ? "" : "hidden";
    els.toLogin.className = v.showLogin ? "" : "hidden";
    setMessage(els.msg, "", "");
  }

  function showView(which) {
    els.formView.className = which === "form" ? "" : "hidden";
    els.recoverView.className = which === "recover" ? "" : "hidden";
    els.resetView.className = which === "reset" ? "" : "hidden";
    els.doneView.className = which === "done" ? "center" : "hidden";
  }

  var ERR_KO = {
    invalid_request: "입력을 확인해주세요.",
    expired: "세션이 만료되었습니다. 게임에서 계정 연결을 다시 시작해주세요.",
    email_taken: "이미 가입된 이메일입니다. ‘로그인’을 이용하세요.",
    invalid_credentials: "이메일 또는 비밀번호가 올바르지 않습니다.",
    link_not_allowed: "이 계정은 이미 연결되어 있어 연결할 수 없습니다. ‘로그인’을 이용하세요.",
    server_error: "일시적인 오류가 발생했습니다. 잠시 후 다시 시도해주세요.",
  };
  function errToKo(code) { return ERR_KO[code] || ERR_KO.server_error; }

  function validEmail(s) { return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s); }

  function showDone() {
    showView("done");
    if (mode === "link") {
      els.doneTitle.textContent = "연결 완료!";
    } else if (mode === "signup") {
      els.doneTitle.textContent = "가입 완료!";
    } else {
      els.doneTitle.textContent = "로그인 완료!";
    }
    els.doneSub.textContent = "게임으로 돌아가세요. 자동으로 로그인됩니다.";
    // 모바일: 앱을 포그라운드로 띄우는 트리거(payload 없음). 데스크톱은 핸들러 없어 무동작 — 안내만.
    // 보안: todohero:// scheme 만 허용(config 변조/임의 scheme 실행 방지). 그 외엔 네비게이트 안 함.
    try {
      if (/^todohero:\/\//.test(APP_RETURN_URL)) window.location.href = APP_RETURN_URL;
    } catch (e) { /* 무시 */ }
  }

  // --- 인증 제출(link/login/signup) ---
  els.form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    setMessage(els.msg, "", "");
    if (!nonce) {
      setMessage(els.msg, "잘못된 접근입니다. 게임에서 계정 연결/로그인을 다시 시작해주세요.", "err");
      return;
    }
    var email = els.email.value.trim();
    var password = els.password.value;
    if (!validEmail(email)) { setMessage(els.msg, "이메일 형식을 확인해주세요.", "err"); return; }
    if (password.length < 6) { setMessage(els.msg, "비밀번호는 6자 이상이어야 합니다.", "err"); return; }

    els.submitBtn.disabled = true;
    var original = els.submitBtn.textContent;
    els.submitBtn.textContent = "처리 중…";

    fetch(FUNCTIONS_BASE + "/auth-handoff-submit", {
      method: "POST",
      headers: { "Content-Type": "application/json", "apikey": ANON_KEY },
      body: JSON.stringify({ nonce: nonce, mode: mode, email: email, password: password }),
    })
      .then(function (r) { return r.json().catch(function () { return {}; }); })
      .then(function (data) {
        if (data && data.ok === true) {
          showDone();
          return;
        }
        var code = (data && data.error) || "server_error";
        setMessage(els.msg, errToKo(code), "err");
      })
      .catch(function () {
        setMessage(els.msg, "네트워크 오류입니다. 연결을 확인하고 다시 시도해주세요.", "err");
      })
      .then(function () {
        els.submitBtn.disabled = false;
        els.submitBtn.textContent = original;
      });
  });

  // --- 비밀번호 찾기(recover 메일 발송) — 토큰 없음, anon key 로 GoTrue recover 직접 호출 ---
  els.recoverForm.addEventListener("submit", function (ev) {
    ev.preventDefault();
    setMessage(els.recoverMsg, "", "");
    var email = els.recoverEmail.value.trim();
    if (!validEmail(email)) { setMessage(els.recoverMsg, "이메일 형식을 확인해주세요.", "err"); return; }

    els.recoverBtn.disabled = true;
    var original = els.recoverBtn.textContent;
    els.recoverBtn.textContent = "보내는 중…";

    fetch((CFG.SUPABASE_URL || "").replace(/\/+$/, "") + "/auth/v1/recover", {
      method: "POST",
      headers: { "Content-Type": "application/json", "apikey": ANON_KEY },
      body: JSON.stringify({ email: email, redirect_to: CFG.AUTH_PAGE_URL || (location.origin + location.pathname) }),
    })
      .then(function () {
        // GoTrue 는 열거 방지를 위해 항상 성공 응답 → 항상 동일 안내.
        setMessage(els.recoverMsg, "재설정 메일을 보냈습니다(가입된 계정인 경우). 메일을 확인해주세요.", "ok");
      })
      .catch(function () {
        setMessage(els.recoverMsg, "네트워크 오류입니다. 다시 시도해주세요.", "err");
      })
      .then(function () {
        els.recoverBtn.disabled = false;
        els.recoverBtn.textContent = original;
      });
  });

  // --- 비밀번호 재설정(recovery 토큰으로 새 비밀번호 설정) ---
  els.resetForm.addEventListener("submit", function (ev) {
    ev.preventDefault();
    setMessage(els.resetMsg, "", "");
    var password = els.resetPassword.value;
    if (password.length < 6) { setMessage(els.resetMsg, "비밀번호는 6자 이상이어야 합니다.", "err"); return; }

    els.resetBtn.disabled = true;
    var original = els.resetBtn.textContent;
    els.resetBtn.textContent = "변경 중…";

    fetch((CFG.SUPABASE_URL || "").replace(/\/+$/, "") + "/auth/v1/user", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "apikey": ANON_KEY,
        "Authorization": "Bearer " + recoveryToken,
      },
      body: JSON.stringify({ password: password }),
    })
      .then(function (r) { return r.json().catch(function () { return {}; }); })
      .then(function (data) {
        if (data && data.id) {
          setMessage(els.resetMsg, "비밀번호가 변경되었습니다. 게임에서 새 비밀번호로 로그인해주세요.", "ok");
          els.resetBtn.disabled = true;
        } else {
          setMessage(els.resetMsg, "변경에 실패했습니다. 링크가 만료되었을 수 있습니다. 비밀번호 찾기를 다시 시도해주세요.", "err");
        }
      })
      .catch(function () {
        setMessage(els.resetMsg, "네트워크 오류입니다. 다시 시도해주세요.", "err");
      })
      .then(function () {
        if (!els.resetBtn.disabled) {
          els.resetBtn.disabled = false;
          els.resetBtn.textContent = original;
        }
      });
  });

  // --- 뷰 전환 ---
  els.toSignup.addEventListener("click", function () { applyMode("signup"); });
  els.toLogin.addEventListener("click", function () { applyMode("login"); });
  els.toRecover.addEventListener("click", function () {
    setMessage(els.recoverMsg, "", "");
    els.recoverEmail.value = els.email.value.trim();
    showView("recover");
  });
  els.backToLogin.addEventListener("click", function () { showView("form"); });

  // --- 초기화 ---
  applyMode(mode);
  if (recoveryToken) {
    showView("reset");
  } else {
    showView("form");
    if (!nonce) {
      setMessage(els.msg, "이 페이지는 게임에서 ‘계정 연결/로그인’을 누르면 자동으로 열립니다. 직접 접근한 경우 게임에서 다시 시작해주세요.", "err");
    }
  }
})();
