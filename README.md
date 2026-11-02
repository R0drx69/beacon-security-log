# 🛰️ Beacon — Security Audit Log

**Auditoría de seguridad continua sobre una SaaS propia en producción, con flujo de trabajo asistido por IA.**

---

## Resumen ejecutivo

Este repositorio documenta el proceso real de pentesting / code-review de seguridad sobre **Beacon**, una SaaS propia de growth para LinkedIn (auditoría de perfil con IA, generación de contenido, comentarios autónomos vía extensión de Chrome, suscripciones con Stripe). No es un laboratorio ni un CTF: es la auditoría de una aplicación propia, real, con usuarios y pagos reales, ejecutada a medida que el producto se construye y evoluciona.

A fecha de la última pasada, **14 hallazgos identificados, 14 corregidos y verificados** (4 de severidad Alta, 5 Media, 5 Baja) sobre dos pasadas de auditoría independientes, con regresión completa confirmada entre ellas.

| | |
|---|---|
| 👤 **Autor** | R0drx69 (Rodrigo Cuevas Veloso) |
| 🎯 **Objetivo** | Beacon — `apps/web` (backend Node.js), `packages/engine` (generación con IA), `apps/extension` (extensión de Chrome MV3) |
| 🧱 **Stack** | Node.js (`http` nativo, sin framework), SQLite (`node:sqlite`), OAuth 2.0 (LinkedIn/Google/Facebook), Stripe, API de Anthropic |
| 🔁 **Formato** | Log vivo — cada pasada de testing se agrega como una entrada nueva, nunca se reescribe el historial |
| 📅 **Pasadas realizadas** | [30 oct 2026](./reports/2026-10-30-beacon-audit.md) (10 hallazgos) · [2 nov 2026](./reports/2026-11-02-beacon-audit-pass2.md) (3 hallazgos + regresión completa) |

---

## Metodología

Cada pasada combina revisión manual de código con un agente de IA (Claude) operando con acceso de shell real sobre el código fuente y la instancia en producción (máquina propia del autor), bajo dirección explícita del autor en cada paso:

1. **Revisión de código dirigida** — lectura completa del código fuente relevante (no solo grep superficial), con foco en superficies de autenticación, autorización, manejo de secretos, y cualquier punto donde contenido no confiable de terceros llegue a un LLM o se renderice en el navegador.
2. **Verificación activa, no solo teórica** — cada hallazgo se confirma con una prueba real antes de considerarse válido: `curl` contra la instancia en vivo, tests unitarios dirigidos, o Playwright para el cliente — nunca "esto podría ser explotable" sin comprobarlo.
3. **Fix + reverificación** — cada corrección se despliega a la instancia real (verificada byte a byte tras el despliegue) y se vuelve a probar el mismo escenario de ataque para confirmar que ya no funciona.
4. **Regresión entre pasadas** — cada pasada nueva empieza re-verificando, uno por uno, que los hallazgos de la pasada anterior siguen corregidos antes de buscar hallazgos nuevos. Ningún hallazgo se da por cerrado permanentemente sin volver a comprobarlo cuando el código a su alrededor cambia.

El criterio de severidad en todo este log sigue una lógica de impacto × explotabilidad:

| Severidad | Criterio |
|---|---|
| 🔴 **Alto** | Compromiso de cuenta, bypass de autenticación/autorización, o ejecución de acción no autorizada con impacto directo sobre datos o fondos de un usuario |
| 🟠 **Medio** | Debilita una defensa real (rate-limiting, cabeceras de endurecimiento, integridad de webhooks) sin ser por sí solo un compromiso directo |
| 🟡 **Bajo** | Defensa en profundidad — el riesgo práctico es bajo o nulo dado el contexto (alta entropía, superficie reducida), pero la corrección es gratuita y mantiene la base de código consistente |

---

## Resumen consolidado de hallazgos

| # | Hallazgo | Severidad | Pasada | Estado |
|---|----------|:---:|:---:|---|
| 1 | Account takeover vía OAuth sin verificar `email_verified` | 🔴 Alto | 30 oct | ✅ Corregido |
| 2 | Bypass de rate-limit vía `X-Forwarded-For` falsificado | 🔴 Alto | 30 oct | ✅ Corregido |
| 3 | Prompt injection en el comentario autónomo de LinkedIn | 🔴 Alto | 30 oct | ✅ Corregido |
| 10 | IDOR en `/api/extension/report` | 🔴 Alto | 30 oct | ✅ Corregido |
| 4 | Sin cabeceras de endurecimiento HTTP (CSP, X-Frame-Options...) | 🟠 Medio | 30 oct | ✅ Corregido |
| 5 | Path traversal — prefix bypass en `serveStatic()` | 🟠 Medio | 30 oct | ✅ Corregido |
| 6 | Replay del webhook de Stripe | 🟠 Medio | 30 oct | ✅ Corregido |
| 11 | Flag de desarrollo activo en producción — otorgaba el plan de pago gratis | 🟠 Medio¹ | 30 oct | ✅ Corregido |
| 12 | Sin `.gitignore` — riesgo latente de subir `.env` con credenciales reales | 🟠 Medio | 2 nov | ✅ Corregido |
| 7 | Cookie de sesión sin flag `Secure` | 🟡 Bajo | 30 oct | ✅ Corregido |
| 8 | Comparación no constant-time del token de extensión | 🟡 Bajo | 30 oct | ✅ Corregido |
| 9 | XSS defensivo en `audit.html` (score sin escapar) | 🟡 Bajo | 30 oct | ✅ Corregido |
| 13 | Tokens de un solo uso sin comparación constant-time ni rate-limit | 🟡 Bajo | 2 nov | ✅ Corregido |
| 14 | Sin rate-limit en `/api/billing/checkout` | 🟡 Bajo | 2 nov | ✅ Corregido |

**14/14 corregidos y verificados.** Los 11 hallazgos de la primera pasada se re-confirmaron intactos — sin regresión — durante la segunda.

¹ *Clasificado como riesgo de negocio/monetización más que como vulnerabilidad de intrusión — ver detalle en el informe original.*

Detalle técnico completo, código antes/después y pasos de reproducción de cada hallazgo en:
- 📄 [`reports/2026-10-30-beacon-audit.md`](./reports/2026-10-30-beacon-audit.md) — primera pasada (10 hallazgos)
- 📄 [`reports/2026-11-02-beacon-audit-pass2.md`](./reports/2026-11-02-beacon-audit-pass2.md) — segunda pasada: regresión completa + 3 hallazgos nuevos

---

## Postura de seguridad actual

A fecha de la última pasada (2 nov 2026): autenticación OAuth con verificación de email, rate-limiting basado en IP real (no en headers falsificables), defensa en dos capas contra prompt injection en el pipeline autónomo de comentarios (instrucción al modelo + barrera técnica mecánica), cabeceras de endurecimiento HTTP en toda respuesta, verificación de firma y antigüedad en el webhook de Stripe, comparaciones constant-time en todo secreto comparado contra entrada del usuario, autorización por dueño de recurso verificada en cada ruta que toca datos por id, y sin credenciales de desarrollo activas en el entorno real.

---

## 📁 Estructura

```
reports/
  2026-10-30-beacon-audit.md         # primera pasada completa (10 hallazgos)
  2026-11-02-beacon-audit-pass2.md   # segunda pasada: regresión + 3 hallazgos nuevos
```

Cada nueva pasada de testing (manual, automatizada, o motivada por una feature nueva) se agrega como un archivo nuevo en `reports/`, nombrado `YYYY-MM-DD-beacon-<tema>.md`, y el resumen de arriba se actualiza para reflejarla.

---

## ⚠️ Alcance y disclaimer

Todo lo documentado en este repositorio es sobre **mi propia aplicación**, auditada en mi propio entorno, con mis propios datos de prueba. No contiene credenciales reales, API keys, ni datos de usuarios reales — solo hallazgos, código relevante (con comentarios y nombres de variables originales del proyecto) y pasos de reproducción verificados contra una instancia propia.

> 📫 Contacto: [LinkedIn](https://www.linkedin.com/in/rodrigocuevasveloso/) · [pentesting-portfolio](https://github.com/R0drx69/pentesting-portfolio)
