# ПР8 — JWT authentication і refresh flow на NestJS

Навчальна заготовка з робочою реалізацією для розбору: NestJS 11, Prisma Client 6.19, PostgreSQL 16. Для роботи потрібні Node.js 22+, npm і Docker Compose або власний PostgreSQL. Версії зафіксовані для відтворення лабораторної, це не заява про їхню актуальність для production.

## Що потрібно зрозуміти

1. Пароль зберігається як Argon2id hash. Під час login виконується verify, а не розшифрування.
2. Access token діє 15 хвилин і передається через `Authorization: Bearer ...`.
3. Refresh token є випадковим 256-бітним значенням. Він не є JWT. Сервер зберігає тільки SHA-256 hash.
4. Кожен login створює окрему Session. Кожне refresh позначає попередній токен використаним і видає новий.
5. Повтор старого токена відкликає всю його Session. Інші сесії користувача залишаються активними.
6. AuthGuard перевіряє JWT і стан Session у БД. Тому logout також блокує ще не прострочений access token.

## Запуск

```bash
npm ci
cp .env.example .env
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

Якщо порт 5432 зайнятий локальним PostgreSQL, задайте в `.env` `DB_PORT=5433` і змініть порт у `DATABASE_URL` на 5433 (compose.yaml читає `DB_PORT`).

Скопіюйте отримане випадкове значення в `JWT_SECRET` у `.env`. Приклад зі словом REPLACE застосунок навмисно відхиляє. `.env` не додавайте в Git.

```bash
docker compose up -d --wait
npm run db:generate
npm run db:deploy
npm run build
npm start
```

API: `http://localhost:3000/api`. `db:deploy` застосовує готову початкову міграцію. Коли самі змінюєте schema, створюйте нову міграцію: `npm run db:migrate -- --name describe_change`.

`npm run start:dev` компілює один раз і запускає Node у watch-режимі для dist. Для автоматичної перекомпіляції відкрийте другий термінал із `npx tsc --watch`. Найпростіше для лабораторної після змін знову виконати `npm run build` і `npm start`.

## Маршрути

| Метод і маршрут | Вхід | Результат |
|---|---|---|
| POST /api/auth/register | email, password | 201, безпечні поля користувача |
| POST /api/auth/login | email, password | 200, access JWT і refresh cookie |
| POST /api/auth/refresh | refresh cookie | 200, новий access і нова cookie |
| POST /api/auth/logout | refresh cookie | 204, revoke сесії та очищення cookie |
| GET /api/auth/me | Bearer access token | 200, id/email/createdAt |
| GET /api/auth/sessions | Bearer access token | 200, активні сесії: id/createdAt/expiresAt/current |

У цій заготовці `/me` розташовано під `/api/auth/me`. Якщо завдання вимагає саме `/api/me`, винесіть метод в окремий controller з `@Controller()` і `@Get('me')`.

Усі POST-запити потребують `X-CSRF-Protection: 1`. Коли браузер надсилає Origin, він повинен дорівнювати FRONTEND_ORIGIN. Не вмикайте wildcard CORS з credentials. Відсутня чи неправильна cookie повертає 401. Logout без cookie ідемпотентно повертає 204.

## Порядок розбору файлів

1. `prisma/schema.prisma`: User, Session та RefreshToken. Один User має багато Session, одна Session має історію refresh tokens.
2. `src/auth/dto.ts`: email нормалізується до нижнього регістру. Пароль реєстрації має 15–128 символів. Не обрізайте пробіли пароля.
3. `src/auth/crypto.ts`: Argon2id для пароля, криптографічна випадковість для токена, SHA-256 для його hash.
4. `src/auth/auth.service.ts`: register, login, refresh, logout.
5. `src/auth/auth.controller.ts`: HTTP та cookie. Raw refresh ніколи не повертається в JSON.
6. `src/auth/auth.guard.ts`: підпис, алгоритм, issuer, audience, exp, тип токена, sub, sid, активність сесії.
7. `src/bootstrap.ts`: validation, CORS, CSRF header, Helmet, no-store.
8. `test/auth.e2e.ts`: негативні сценарії та конкурентна ротація.

## Register і login

Register створює hash через Argon2id з memoryCost 19456 KiB, timeCost 2, parallelism 1. Argon2 генерує випадкову salt сам і включає її в збережений рядок. Email має UNIQUE в БД. Повтор email повертає 409.

Login перевіряє пароль і створює Session із фіксованим строком життя 7 днів. Для неіснуючого email виконується перевірка dummy hash, а повідомлення однакове: Invalid email or password. Це зменшує, але не гарантує усунення, різниць у часі відповіді.

JWT payload містить `sub` користувача, `sid` сесії та `type: access`, а також часові claims, issuer і audience. Пароля або refresh token в JWT немає. JWT підписаний, але його payload не зашифрований.

## Ротація крок за кроком

1. Сервер дістає cookie та перевіряє її формат.
2. Обчислює SHA-256 і знаходить збережений RefreshToken.
3. Починає транзакцію та блокує рядок Session через SELECT FOR UPDATE.
4. Повторно читає token і session всередині транзакції.
5. Якщо usedAt вже є, відкликає Session і повертає результат відмови.
6. Якщо token/session прострочені, відкликає Session.
7. Інакше встановлює usedAt, створює hash нового токена та завершує транзакцію.
8. Після commit видає JWT і нову cookie або повертає 401.

Важливий момент: після запису revokedAt не можна викидати помилку всередині transaction callback, інакше rollback скасує саме відкликання. Тут callback повертає результат, а exception виникає вже після commit.

Термін сесії абсолютний: refresh не подовжує його безкінечно. Історія використаних hash зберігається до завершення сесії для виявлення replay. Невідомий випадковий token не дозволяє знайти й відкликати чужу сесію.

Під час двох паралельних refresh один пройде, другий буде replay та відкличе Session. Навіть токен першої відповіді після цього не працює. Це свідома сувора політика. Клієнт має виконувати refresh через single-flight: тільки один refresh одночасно. Втрата відповіді та повтор того самого запиту також вимагатиме нового login. Grace period тут немає.

## Де зберігати токени на web

Access тримайте в пам’яті застосунку. Refresh браузер отримує через HttpOnly cookie, доступу JavaScript до неї немає. Після перезавантаження сторінки можна викликати refresh й відновити access у пам’яті.

```ts
const response = await fetch('http://localhost:3000/api/auth/refresh', {
  method: 'POST',
  credentials: 'include',
  headers: { 'X-CSRF-Protection': '1' },
});
// Спочатку перевірте response.ok. На 401 очистіть access та покажіть login.
```

Cookie: HttpOnly, SameSite=Strict, Path=/api/auth, Secure у NODE_ENV=production. Локальна HTTP-конфігурація навмисно має Secure=false. Для frontend localhost:5173 та API localhost:3000 схема й hostname однакові, origin різні, site спільний. Не змішуйте localhost і 127.0.0.1. Cross-site deployment потребує окремого дизайну cookie/CSRF, ця заготовка його не реалізує.

## Перевірка вручну

Повна послідовність запитів є у `docs/api.http` (VS Code REST Client) та `docs/CURL.md`. Refresh надсилайте з cookie, `/me` з access JWT. Не вставляйте реальні паролі чи токени у скриншоти звіту.

## Тести

```bash
npm test
```

Це тести Argon2 і токенів без БД. Для інтеграційних тестів створіть ОКРЕМУ базу, наприклад auth_lab_test:

```bash
docker compose exec db createdb -U student auth_lab_test
DATABASE_URL=postgresql://student:student@localhost:5432/auth_lab_test npm run db:deploy
DATABASE_URL_TEST=postgresql://student:student@localhost:5432/auth_lab_test npm run test:e2e
```

Тест створює унікального тестового користувача і видаляє тільки його. Проте завжди запускайте його в окремій тестовій БД. Без DATABASE_URL_TEST e2e позначається skipped, це не успішне проходження auth flow.

Тести перевіряють invalid credentials, protected route, прострочений access/refresh, rotation, повтор старого refresh, logout, незалежні сесії, паралельний refresh та CSRF. У тестах діє rate limit, тому вони виконуються послідовно і не повинні запускатися циклічно без пауз.

## Робота студентів

На парі: запустіть проєкт, зареєструйтеся, виконайте login → me → refresh → logout. У Prisma Studio переконайтеся, що немає raw password/token. Відтворіть повтор старої cookie й поясніть, чому нова теж перестала працювати.

Самостійно:
- Допишіть тест login для неіснуючого email.
- Допишіть тести невідомого body-поля і неправильних issuer/audience.
- Додайте GET /api/auth/sessions із безпечними полями без tokenHash.
- Додайте видалення прострочених сесій фоновою задачею з погодженим retention.

Здати: код, README із командами, результати тестів і коротку демонстрацію негативних сценаріїв. Кожен студент називає свою частину реалізації. Готовий код потрібно вміти пояснити, а не лише запустити.

## Виконані самостійні завдання

| Завдання | Де реалізовано |
|---|---|
| Тест login для неіснуючого email | `test/auth.e2e.ts`: 401, такий самий body, як для неправильного пароля, без Set-Cookie |
| Тест невідомого body-поля | `test/auth.e2e.ts`: `role` у register і `isAdmin` у login → 400 (`forbidNonWhitelisted`) |
| Тести неправильних issuer/audience | `test/auth.e2e.ts`: контрольний валідний JWT → 200; чужий issuer, audience, `type: refresh`, інший secret → 401 |
| GET /api/auth/sessions | `src/auth/auth.controller.ts`: тільки активні сесії поточного користувача, поля id/createdAt/expiresAt/current, без tokenHash і userId |
| Фонове видалення сесій | `src/auth/session-cleanup.service.ts` |

### Очищення сесій і retention

`SessionCleanupService` запускається при старті застосунку і далі кожні `SESSION_CLEANUP_INTERVAL_SECONDS` (за замовчуванням 3600 с). Він видаляє сесії, у яких `expiresAt` або `revokedAt` раніше за `now - SESSION_RETENTION_SECONDS` (погоджений retention — 7 днів, 604800 с). Історія RefreshToken видаляється каскадно (`ON DELETE CASCADE`).

- Активні сесії не видаляються, тому історія `usedAt` для виявлення replay зберігається до завершення сесії. Після видалення старий token просто невідомий і отримує 401.
- Таймер має `unref()`, паралельні запуски пропускаються, помилка логується без деталей і повторюється на наступному інтервалі.
- Для швидкого пошуку додано індекси `Session.expiresAt` і `Session.revokedAt` (міграція `20261111113333_session_cleanup_indexes`).
- При кількох інстансах API job виконується в кожному. `deleteMany` ідемпотентний, тому це безпечно, хоч і зайве.

Код відформатовано Prettier (`.prettierrc.json`): `npm run format` форматує `src` і `test`, `npm run format:check` перевіряє без змін.

Ліміт запитів винесено в `RATE_LIMIT_PER_MINUTE` (за замовчуванням 30). e2e-тест підвищує його до 200, бо робить понад 30 запитів за хвилину.

### Команди, якими перевірено

```bash
npm ci
cp .env.example .env
docker compose up -d --wait
npm run db:generate
npm run db:deploy
npm run build
npm test
docker compose exec db createdb -U student auth_lab_test
DATABASE_URL=postgresql://student:student@localhost:5433/auth_lab_test npm run db:deploy
DATABASE_URL_TEST=postgresql://student:student@localhost:5433/auth_lab_test npm run test:e2e
```

(Порт 5433, бо в середовищі перевірки 5432 був зайнятий; за замовчуванням — 5432.)

### Результати тестів (11.11.2026)

- `npm run build`: без помилок.
- `npm test`: tests 2, pass 2, fail 0.
- `npm run test:e2e` на окремій БД auth_lab_test: tests 14, pass 14, fail 0, skipped 0.

```
✔ register stores only hash and rejects short password
✔ invalid credentials and protected route return 401
✔ login cookie, me and expired JWT
✔ rotation, replay revokes session and newest token
✔ expired refresh returns 401
✔ logout revokes current session but not another login
✔ parallel refresh consumes token only once
✔ login with nonexistent email returns the same 401 as wrong password
✔ unknown body field is rejected with 400
✔ JWT with wrong issuer, audience, type or secret returns 401
✔ GET sessions lists only active sessions with safe fields
✔ cleanup deletes sessions ended before retention, keeps the rest
✔ CSRF header and origin are required/checked
✔ auth flow against PostgreSQL
```

### Демонстрація негативних сценаріїв (curl, запущений сервер)

| Запит | Відповідь |
|---|---|
| login з неіснуючим email | 401 `{"code":"INVALID_CREDENTIALS","message":"Invalid email or password"}` |
| login з полем `role` | 400 `property role should not exist` |
| GET /sessions після двох login | 200, дві сесії, одна `current: true`, без tokenHash |
| refresh | 200, нова cookie |
| повтор старої cookie | 401 `REFRESH_REUSED` |
| нова cookie після replay | 401, сесію відкликано |
| logout іншої сесії | 204 |
| POST без X-CSRF-Protection | 403 `CSRF_REJECTED` |

## Межі заготовки

Це навчальна реалізація, не готова production identity platform. Немає перевірки email, відновлення пароля, MFA та перевірки паролів за списком витоків. Rate limiter зберігає лічильники в пам’яті одного процесу і не є захистом розподіленого deployment. Перед reverse proxy потрібно правильно й обмежено налаштувати trust proxy. Не логувати Authorization, Cookie, Set-Cookie чи body auth запитів.

Перевірка сесії в БД на кожному protected request дає revoke, але додає DB-запит. Уже авторизований запит, що виконується паралельно з logout, не відкочується. Hash refresh обчислюється швидко, бо token має високу ентропію. Для паролів швидкий SHA-256 непридатний.

## Контрольні запитання

1. Чому password encryption не замінює hashing?
2. Чому для пароля Argon2id, а для випадкового refresh — SHA-256?
3. Що таке refresh replay і навіщо зберігати usedAt?
4. Чому revoke повинен закомітитися до exception?
5. Чим відрізняються JWT exp і expiresAt Session?
6. Чому HttpOnly не замінює CSRF-захист?
7. Як уникнути одночасних refresh у web-клієнті?

## Джерела

- https://docs.nestjs.com/security/authentication
- https://docs.nestjs.com/security/encryption-and-hashing
- https://docs.nestjs.com/security/rate-limiting
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- https://datatracker.ietf.org/doc/html/rfc9700#section-4.14

Цей застосунок є власним auth flow, а не повним OAuth authorization server. RFC використано як джерело принципу ротації та виявлення повторного використання.
