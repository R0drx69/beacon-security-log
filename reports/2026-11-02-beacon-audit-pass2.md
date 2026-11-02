# 🛰️ Beacon — Security Audit, pasada 2 (2 nov 2026)

- **Objetivo:** Beacon (SaaS de growth para LinkedIn — perfil, contenido con IA, comentarios autónomos vía extensión de Chrome, pagos con Stripe)
- **Tipo:** Code review + regresión de la pasada anterior contra una instancia propia (producción real del autor)
- **Alcance:** todo lo cubierto en la [pasada del 30 oct](./2026-10-30-beacon-audit.md) (re-verificado) **más** el código nuevo desde entonces: ecosistema de emails (`email.js` reescrito, job programado de recordatorio), `forgot-password`/`reset-password` (servidor + páginas), borrado de cuenta (`handleDeleteAccount`), `db-sqlite.js` (motor de base de datos real), `apps/extension/content-script.js` (no estaba en el alcance de la pasada 1), y el paso de Stripe de dos tiers (`content`/`engage`) a un plan único
- **Metodología:** revisión manual del código fuente completo + grep dirigido por patrón sobre todo el árbol; cada hallazgo nuevo corregido y verificado (sintaxis + desplegado a la instancia real) antes de cerrarlo
- **Autor:** R0drx69

---

## 📊 Resumen

| # | Hallazgo | Severidad | Estado |
|---|----------|-----------|--------|
| 12 | Sin `.gitignore` en el proyecto — riesgo latente de subir `.env` con credenciales reales | 🟠 Medio | ✅ Corregido |
| 13 | Comparación no constant-time + sin rate-limit en tokens de un solo uso (reset de contraseña, verificación de email) | 🟡 Bajo | ✅ Corregido |
| 14 | Sin rate-limit en `/api/billing/checkout` | 🟡 Bajo | ✅ Corregido |

Los hallazgos #1-11 de la pasada anterior se re-verificaron en el código actual: **los 11 siguen corregidos, ninguno regresionó** (detalle en la sección de regresión, abajo).

---

## 🟠 Hallazgo 12 — Sin `.gitignore` en todo el proyecto

**Dónde:** raíz del proyecto (`C:\Users\rodri\Desktop\beacon\beacon\`) y cada subcarpeta — no existía ningún `.gitignore`, en ningún nivel.

**Problema:**
El proyecto real no está bajo control de versiones todavía (no hay carpeta `.git`), así que hoy no hay ningún repositorio desde el que `.env` pueda filtrarse. Pero el autor sí usa git activamente para otro propósito relacionado (este mismo log de seguridad), y el patrón de "crear un repo cuando llega el momento de compartir/respaldar el código" ya se demostró real una vez: es exactamente lo que pasó con `RESEND_API_KEY.txt`, que vivió en texto plano sin ninguna protección hasta que se encontró y se pidió borrarlo a mano.

Si alguna vez se corre `git init` en este proyecto (para respaldarlo, abrir un PR, o compartirlo) y después un `git add -A` sin haber creado antes un `.gitignore`, **`.env` se subiría tal cual** — y `.env` contiene, hoy mismo, claves reales de Stripe (`STRIPE_SECRET_KEY`), Anthropic, Google OAuth, LinkedIn OAuth y Resend. A diferencia de `RESEND_API_KEY.txt` (una sola clave), esto expondría las cinco de golpe.

**Fix:** `.gitignore` en la raíz del proyecto, cubriendo `.env`/`.env.local` (en cualquier carpeta), el archivo de clave de Resend en texto plano por si vuelve a aparecer, la base de datos SQLite local (datos reales de usuarios una vez en uso) y los artefactos habituales (`node_modules/`, logs, archivos de SO).

```gitignore
# Secretos reales — nunca versionar
.env
.env.local
**/.env
**/.env.local
*RESEND_API_KEY*

# Base de datos local (contiene datos reales de usuarios una vez en uso)
apps/web/data/*.sqlite3
apps/web/data/*.sqlite3-shm
apps/web/data/*.sqlite3-wal
apps/web/data/db.json
apps/web/data/db.json.migrated-backup

node_modules/
*.log
.DS_Store
Thumbs.db
```

---

## 🟡 Hallazgo 13 — Comparación no constant-time + sin rate-limit en tokens de un solo uso

**Dónde:** `server.js` — `handleResetPassword()` y `handleVerifyEmail()`.

**Problema:**
Dos cosas, misma raíz que el hallazgo #8 de la pasada anterior (comparación no constant-time del token de extensión), aplicadas aquí a tokens más sensibles — el de reset de contraseña en concreto controla un cambio real de credencial, no solo una lectura:

1. **Comparación no constant-time:** `Object.values(data.users).find(u => u.passwordResetToken === token)` — un `===` plano sobre un secreto filtra tiempo proporcional a cuántos caracteres coinciden antes de la primera diferencia. El token es 192 bits de hex aleatorio (`crypto.randomBytes(24)`), así que esto es defensa en profundidad, no un ataque práctico por sí solo — mismo matiz que ya se documentó para el hallazgo #8.
2. **`handleResetPassword` no tenía ningún rate-limit**, a diferencia de `handleForgotPassword` (5/hora), `handleLogin` (15/15min) y `handleDeleteAccount` (10/15min por cuenta). Con 192 bits de entropía, el rate-limit tampoco es lo que hace inviable la fuerza bruta aquí — pero deja esta ruta inconsistente con el resto de rutas que manejan un secreto de un solo uso.

**Fix:** helper compartido `constantTimeTokenMatch(candidates, token, field)` (usa `crypto.timingSafeEqual`, comprobando longitud antes como ya hacía `userFromExtensionToken`), aplicado tanto en `handleResetPassword` como en `handleVerifyEmail`. Rate-limit nuevo en `handleResetPassword`, 10/hora por IP — holgado para no fastidiar un reintento legítimo, pero presente.

```js
function constantTimeTokenMatch(candidates, token, field) {
  if (!token) return null;
  const tokenBuf = Buffer.from(token);
  return (
    candidates.find((item) => {
      const stored = item[field];
      return !!stored && stored.length === token.length && crypto.timingSafeEqual(Buffer.from(stored), tokenBuf);
    }) || null
  );
}
```

---

## 🟡 Hallazgo 14 — Sin rate-limit en `/api/billing/checkout`

**Dónde:** `server.js` — `handleBillingCheckout()`.

**Problema:** cualquier cuenta autenticada (o una sesión robada vía XSS/dispositivo compartido) podía llamar a este endpoint en bucle sin ningún tope, cada llamada creando una Checkout Session real contra la API de Stripe. No mueve dinero hasta que alguien completa el pago en la página de Stripe, así que el daño práctico es ruido contra la API/dashboard de Stripe, no un riesgo financiero directo — pero es la única ruta autenticada de todo el archivo que no tenía ningún límite.

**Fix:** rate-limit de 20/hora por usuario, mismo patrón que el resto de rutas autenticadas del archivo.

---

## ✅ Regresión de la pasada anterior (30 oct 2026) — sin hallazgos nuevos, los 11 siguen en pie

Se re-verificó en el código actual, uno por uno:

| # | Hallazgo original | Estado ahora |
|---|---|---|
| 1 | Account takeover vía OAuth sin verificar `email_verified` | ✅ el chequeo `profile.email_verified !== false` sigue presente en `linkedin-oauth.js` y `google-oauth.js` |
| 2 | Bypass de rate-limit vía `X-Forwarded-For` falsificado | ✅ `clientIp()` sigue ignorando el header salvo `TRUST_PROXY=1` |
| 3 | Prompt injection en el comentario autónomo | ✅ `isSafeAutonomousComment()` intacta en `comment-picker.js`, mismas reglas (sin URL/@handle/teléfono, <600 chars) |
| 4 | Sin cabeceras de endurecimiento HTTP | ✅ CSP/X-Frame-Options/nosniff/Referrer-Policy siguen aplicándose a toda respuesta |
| 5 | Path traversal — prefix bypass en `serveStatic()` | ✅ el chequeo con separador de ruta sigue ahí |
| 6 | Replay del webhook de Stripe | ✅ tolerancia de 5 minutos sobre el timestamp sigue activa |
| 7 | Cookie de sesión sin flag `Secure` | ✅ `Secure` condicional a `isHttps(req)` sigue en `auth.js` |
| 8 | Comparación no constant-time del token de extensión | ✅ `userFromExtensionToken` sigue usando `crypto.timingSafeEqual` |
| 9 | XSS defensivo en `audit.html` | ✅ `item.score` sigue pasando por `escapeHtml()` |
| 10 | IDOR en `/api/extension/report` | ✅ el chequeo `plan.userId === user.id` / `c.userId === user.id` sigue presente |
| 11 | `DEV_FORCE_PRO` activo en el entorno real | ✅ confirmado `DEV_FORCE_PRO=0` en el `.env` real a fecha de esta pasada |

---

## ✅ Código nuevo revisado, sin hallazgos de seguridad

- **Ecosistema de emails** (`email.js` reescrito, job programado `checkStalePlansAndRemind`): no inserta nada controlado por el usuario en HTML sin escapar; los triggers de Stripe (bienvenida, aviso de baja) usan datos que ya pasaron por la verificación de firma del webhook, no entrada directa del llamador.
- **`forgot-password` / `reset-password`** (rutas + páginas): token de 192 bits, expira en 1h, invalida todas las sesiones activas al cambiar la contraseña, respuesta genérica que no confirma si un email existe — mismo patrón ya establecido para verificación de email. Los dos gaps menores encontrados aquí son los hallazgos #13 arriba.
- **Borrado de cuenta** (`handleDeleteAccount`): re-pide contraseña con su propio rate-limit por cuenta; borra sesiones, auditorías, planes y comentarios del usuario correcto únicamente.
- **`db-sqlite.js`**: todas las queries usan `.prepare()` con placeholders `?` — cero construcción de SQL por concatenación, sin superficie de inyección.
- **`apps/extension/content-script.js`** (primera vez en el alcance de esta auditoría): sin `innerHTML`/`insertAdjacentHTML`/`outerHTML` en ningún punto — mismo patrón limpio que `popup.js` y `background.js`, ya verificados en la pasada 1.
- **Paso de Stripe a plan único** (1 nov 2026): se revisó específicamente por posibles referencias colgantes tras quitar el split `content`/`engage` — ninguna encontrada; el helper `isEngageTier()` quedó sin ningún llamador tras el cambio y se eliminó en vez de dejarlo como alias muerto.
- **CORS**: no se fijan cabeceras `Access-Control-Allow-*` en ningún punto — correcto por omisión para una app same-origin; nada que cambiar.
- **Flujo OAuth (CSRF del `state`)**: `state` sigue siendo aleatorio de 128 bits, de un solo uso (se borra al consumirse) y con expiración — sin cambios desde la pasada 1, sin hallazgos nuevos.

## 🧩 Lecciones / takeaways de esta pasada

- Un hallazgo de pasada 1 (token sin comparación constant-time) es un patrón, no un caso aislado — aparece de nuevo en cuanto el proyecto suma una segunda ruta con un token de un solo uso. Vale la pena generalizarlo a un helper compartido la primera vez que aparece, no la tercera.
- La ausencia de `.gitignore` no era explotable hoy (no hay repo git local todavía), pero es exactamente el tipo de cosa que conviene arreglar *antes* de que haga falta, no después de un `git add -A` apresurado — mismo espíritu que llevó a crear este mismo log de seguridad en su propio repo.
- Una refactorización de producto (el paso de dos tiers de Stripe a uno) es también un buen momento para barrer código muerto: un helper que pierde todos sus llamadores en el mismo cambio es fácil de dejar "por si acaso" y es mejor quitarlo mientras se tiene el contexto fresco de por qué ya no hace falta.
