# 비앤빛안과 홈페이지 리뉴얼 · 요구사항 전달 문서

비쥬웍스 → 시그 전달용 정적 문서 세트(PC/모바일 반응형). 개요 → 요약 → 요구사항(FR) → 트래킹 → SEO → 비기능(NFR) 순으로 구성됩니다.

## 배포

GitHub Pages: **https://cain776.github.io/si-dev-homepage/**

`main` 브랜치 루트를 그대로 서빙합니다. 진입 시 로그인 화면([`login.html`](login.html))을 거칩니다.

## 로그인 게이트

백엔드 없는 정적 문서라 접근 제어를 브라우저(클라이언트)에서 처리합니다. 계정은 [`assets/auth.js`](assets/auth.js) 상단 `USERS` 배열에서 관리하며, 비밀번호는 SHA-256 해시로만 저장합니다.

> ⚠️ **보안 한계** — 정적 파일의 클라이언트 인증은 소스를 열면 우회되므로 "진짜 접근 차단"이 아닙니다. 이 저장소가 **public**인 동안에는 문서가 사실상 전체 공개 상태입니다. 실질적 보호가 필요하면 저장소를 비공개로 전환하고 서버단 인증(Basic Auth, Cloudflare Access 등)을 함께 쓰세요.

## 구조

| 파일 | 내용 |
|------|------|
| `index.html` | 목차 |
| `1-overview.html` | 01 사업 개요 |
| `3-summary.html` | 02 기본 요청사항 |
| `4-requirements.html` | 03 요구사항 정리 (FR-01~16) |
| `5-tracking.html` | 04 GA·GTM·광고 트래킹 |
| `6-seo.html` | 05 SEO 실측 자산 |
| `7-nfr.html` | 06 비기능 요구사항 |
| `login.html` | 로그인 게이트 |
| `assets/style.css` | 공용 스타일 |
| `assets/auth.js` | 로그인 게이트 로직 |
