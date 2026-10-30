# 🛰️ Beacon — Security Log

Registro continuo y real de pentesting / code-review de seguridad sobre **[Beacon](https://github.com/R0drx69)**, una SaaS propia de growth para LinkedIn (perfil, contenido con IA, comentarios autónomos vía extensión de Chrome, pagos con Stripe).

No es un lab ni un CTF: es la auditoría real de una app propia en producción, hecha a medida que se construye. Cada entrada de abajo es un hallazgo confirmado en código, explotado o verificado con pruebas reales (curl, Playwright, tests unitarios), corregido, y re-verificado antes de desplegar.

- 👤 **Autor:** R0drx69 (Rodrigo)
- 🎯 **Objetivo:** Beacon (`apps/web`, `packages/engine`, `apps/extension`) — stack Node.js (`http` nativo, sin framework), SQLite, OAuth (LinkedIn/Google/Facebook), Stripe, API de Anthropic.
- 🔁 **Formato:** log vivo — se agrega una entrada por cada pasada de testing, no un informe único y cerrado.

---

## 📊 Resumen de severidad (pasada del 30 oct 2026)

| # | Hallazgo | Severidad | Estado |
|---|----------|-----------|--------|
| 1 | Account takeover vía OAuth sin verificar `email_verified` | 🔴 Alto | ✅ Corregido |
| 2 | Bypass de rate-limit vía `X-Forwarded-For` falsificado | 🔴 Alto | ✅ Corregido |
| 3 | Prompt injection en el comentario autónomo de LinkedIn | 🔴 Alto | ✅ Corregido |
| 10 | IDOR en `/api/extension/report` | 🔴 Alto | ✅ Corregido |
| 4 | Sin cabeceras de endurecimiento HTTP (CSP, X-Frame-Options...) | 🟠 Medio | ✅ Corregido |
| 5 | Path traversal — prefix bypass en `serveStatic()` | 🟠 Medio | ✅ Corregido |
| 6 | Replay del webhook de Stripe | 🟠 Medio | ✅ Corregido |
| 7 | Cookie de sesión sin flag `Secure` | 🟡 Bajo | ✅ Corregido |
| 8 | Comparación no constant-time del token de extensión | 🟡 Bajo | ✅ Corregido |
| 9 | XSS defensivo en `audit.html` (score sin escapar) | 🟡 Bajo | ✅ Corregido |

10/10 hallazgos corregidos y verificados. Detalle completo en [`reports/2026-10-30-beacon-audit.md`](./reports/2026-10-30-beacon-audit.md).

---

## 📁 Estructura

```
reports/
  2026-10-30-beacon-audit.md   # primera pasada completa (10 findings)
```

Cada nueva pasada de testing (manual, automatizada, o motivada por una feature nueva) se agrega como un archivo nuevo en `reports/`, nombrado `YYYY-MM-DD-beacon-<tema>.md`, y se refleja en este README.

---

## ⚠️ Alcance y disclaimer

Todo lo documentado acá es sobre **mi propia aplicación**, corrido en mi propio entorno. No contiene credenciales reales, API keys, ni datos de usuarios reales — solo hallazgos, código relevante y pasos de reproducción contra datos de prueba.

> 📫 Contacto: [LinkedIn](https://www.linkedin.com/in/rodrigocuevasveloso/) · [pentesting-portfolio](https://github.com/R0drx69/pentesting-portfolio)
