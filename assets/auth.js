/* ============================================================
   비앤빛 리뉴얼 · 전달 문서 세트 — 로그인 게이트 (클라이언트)
   - 백엔드가 없는 정적 문서라 접근 제어를 브라우저에서 처리합니다.
   - 비밀번호는 평문 대신 SHA-256 해시로만 보관합니다.
   - file:// · http:// (비보안 컨텍스트)에서도 동작하도록
     Web Crypto가 없으면 순수 JS SHA-256으로 자동 대체합니다.

   ※ 보안 한계: 정적 파일에서의 클라이언트 인증은 소스를 열면
      계정 구조가 보이므로 "진짜 접근 차단"이 아닙니다.
      민감 문서라면 호스팅 단의 서버 인증(Basic Auth 등)을 함께 쓰세요.

   ── 계정 추가/변경법 ─────────────────────────────
   USERS 배열에 { id, pass } 항목을 넣습니다.
   pass 는 비밀번호의 SHA-256 해시(소문자 hex)입니다. 구하는 법:
     printf '%s' '새비밀번호' | sha256sum      (Git Bash / Linux)
   ============================================================ */
(function () {
  'use strict';

  var CONFIG = {
    ttlHours: 12,                 // 로그인 유지 시간
    storeKey: 'bnvit_doc_auth',
    loginPage: 'login.html',
    homePage: 'index.html'
  };

  // 등록 계정 — pass 는 비밀번호의 SHA-256 해시
  var USERS = [
    { id: 'admin', role: '관리자', pass: '03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4' }, // 1234
    { id: 'guest', role: '게스트', pass: '03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4' }  // 1234
  ];

  /* ── SHA-256 (UTF-8 입력) ───────────────────────── */
  async function sha256Hex(str) {
    var bytes = new TextEncoder().encode(str);
    if (window.crypto && window.crypto.subtle && window.isSecureContext) {
      try {
        var buf = await window.crypto.subtle.digest('SHA-256', bytes);
        return [].map.call(new Uint8Array(buf), function (b) {
          return b.toString(16).padStart(2, '0');
        }).join('');
      } catch (e) { /* 폴백으로 진행 */ }
    }
    return sha256Bytes(bytes);
  }

  // 순수 JS SHA-256 (표준 구현) — 비보안 컨텍스트 대비
  function sha256Bytes(bytes) {
    var K = new Uint32Array([
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ]);
    var h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,
        h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    var l=bytes.length, withOne=l+1, k=(56-withOne%64+64)%64, total=withOne+k+8;
    var m=new Uint8Array(total); m.set(bytes); m[l]=0x80;
    var bitLen=l*8, dv=new DataView(m.buffer);
    dv.setUint32(total-4, bitLen>>>0, false);
    dv.setUint32(total-8, Math.floor(bitLen/0x100000000), false);
    var w=new Uint32Array(64);
    function rr(x,n){ return (x>>>n)|(x<<(32-n)); }
    for (var off=0; off<total; off+=64) {
      for (var i=0;i<16;i++) w[i]=dv.getUint32(off+i*4,false);
      for (i=16;i<64;i++){
        var s0=rr(w[i-15],7)^rr(w[i-15],18)^(w[i-15]>>>3);
        var s1=rr(w[i-2],17)^rr(w[i-2],19)^(w[i-2]>>>10);
        w[i]=(w[i-16]+s0+w[i-7]+s1)|0;
      }
      var a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
      for (i=0;i<64;i++){
        var S1=rr(e,6)^rr(e,11)^rr(e,25);
        var ch=(e&f)^((~e)&g);
        var t1=(h+S1+ch+K[i]+w[i])|0;
        var S0=rr(a,2)^rr(a,13)^rr(a,22);
        var maj=(a&b)^(a&c)^(b&c);
        var t2=(S0+maj)|0;
        h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;
      }
      h0=(h0+a)|0;h1=(h1+b)|0;h2=(h2+c)|0;h3=(h3+d)|0;
      h4=(h4+e)|0;h5=(h5+f)|0;h6=(h6+g)|0;h7=(h7+h)|0;
    }
    return [h0,h1,h2,h3,h4,h5,h6,h7].map(function (x) {
      return (x>>>0).toString(16).padStart(8,'0');
    }).join('');
  }

  /* ── 세션 ───────────────────────────────────────── */
  function readSession() {
    try {
      var raw = localStorage.getItem(CONFIG.storeKey);
      if (!raw) return null;
      var s = JSON.parse(raw);
      if (!s || !s.exp || Date.now() > s.exp) { localStorage.removeItem(CONFIG.storeKey); return null; }
      return s;
    } catch (e) { return null; }
  }
  function isAuthed() { return !!readSession(); }
  function currentUser() { var s = readSession(); return s ? { id: s.id, role: s.role } : null; }
  function setSession(u) {
    localStorage.setItem(CONFIG.storeKey, JSON.stringify({
      id: u.id, role: u.role, exp: Date.now() + CONFIG.ttlHours * 3600 * 1000
    }));
  }
  function logout() {
    localStorage.removeItem(CONFIG.storeKey);
    location.replace(CONFIG.loginPage);
  }

  // 로그인 시도 → 성공하면 true
  async function login(id, pw) {
    var wantId = (id || '').trim().toLowerCase();
    var hash = await sha256Hex(pw || '');
    for (var i = 0; i < USERS.length; i++) {
      if (USERS[i].id === wantId && USERS[i].pass === hash) {
        setSession(USERS[i]);
        return true;
      }
    }
    return false;
  }

  /* ── 보호 페이지 가드 (head에서 동기 실행) ───────── */
  function guard() {
    if (isAuthed()) return;
    var here = location.pathname.split('/').pop() || '';
    var next = encodeURIComponent(here + location.hash);
    location.replace(CONFIG.loginPage + '?next=' + next);
  }

  /* ── 로그아웃 컨트롤 주입 ────────────────────────── */
  function injectLogout() {
    var u = currentUser();
    if (!u) return;
    var nav = document.querySelector('.docbar-nav');
    if (nav) {
      var sep = document.createElement('span');
      sep.className = 'auth-user';
      sep.textContent = u.id + ' · ' + u.role;
      nav.appendChild(sep);
      var a = document.createElement('a');
      a.href = '#'; a.textContent = '로그아웃'; a.className = 'auth-logout';
      a.addEventListener('click', function (e) { e.preventDefault(); logout(); });
      nav.appendChild(a);
    } else {
      // docbar 없는 페이지(목차 등): 우상단 고정 칩
      var box = document.createElement('div');
      box.className = 'auth-fab';
      var who = document.createElement('span');
      who.className = 'auth-user'; who.textContent = u.id + ' · ' + u.role;
      var b = document.createElement('a');
      b.href = '#'; b.textContent = '로그아웃'; b.className = 'auth-logout';
      b.addEventListener('click', function (e) { e.preventDefault(); logout(); });
      box.appendChild(who); box.appendChild(b);
      document.body.appendChild(box);
    }
  }

  window.SigAuth = {
    isAuthed: isAuthed,
    currentUser: currentUser,
    login: login,
    logout: logout,
    sha256Hex: sha256Hex,
    homePage: CONFIG.homePage,
    loginPage: CONFIG.loginPage
  };

  // data-guard 속성이 있는 <script>면: 즉시 가드 + 로그아웃 버튼 주입
  var cur = document.currentScript;
  if (cur && cur.hasAttribute('data-guard')) {
    guard();
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', injectLogout);
    } else {
      injectLogout();
    }
  }
})();
