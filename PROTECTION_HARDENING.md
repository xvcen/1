# Как довести защиту xvcen до практически максимальной стойкости

> Документ описывает защиту клиентского Android/AArch64-приложения от патчинга, реверса, подмены сервера и повторного использования лицензий. Это план защиты, а не обещание абсолютной неуязвимости.
>
> **Главный вывод:** если атакующий полностью контролирует Android-процесс, его память, файловую систему и сетевой трафик, то «10/10» для чисто клиентского бинарника математически недостижимо. Клиент можно остановить, отладить, эмулировать или заменить. Практический эквивалент 10/10 достигается только архитектурой, в которой клиент не является источником доверия, а ценные права выдаются сервером после аппаратно подтверждённой проверки и быстро истекают.

---

## 1. Цель и модель угроз

### 1.1 Что именно нужно защищать

У xvcen есть несколько разных активов, и их нельзя защищать одним механизмом:

1. **Авторизация пользователя** — право запускать функции.
2. **Лицензия** — право конкретного пользователя или устройства.
3. **Версия offsets** — набор адресов и capability, соответствующий конкретной версии игры.
4. **Сессионные ключи** — ключи обмена, токены и ключи расшифровки.
5. **Алгоритм логики** — код, который определяет, что разрешено делать.
6. **Целостность приложения** — отсутствие подмены ELF/APK, библиотек и ресурсов.
7. **Анти-replay** — невозможность повторно использовать старый grant.
8. **Секреты поставщика** — приватные ключи подписи, ключи серверной базы и master secrets.

Эти активы имеют разную природу. Например, шифрование offsets защищает содержимое, но не защищает от патчинга функции, которая возвращает `AUTH_OK`. Серверная подпись защищает подлинность grant, но не спасает, если патч позволяет клиенту не проверять подпись.

### 1.2 Уровни атакующего

| Уровень | Возможности | Пример |
|---|---|---|
| L0 | Только просмотр UI и файлов | Обычный пользователь |
| L1 | Hex-патчинг, поиск строк, изменение ветвлений | Начинающий моддер |
| L2 | Capstone/Ghidra/IDA, динамическая трассировка, Frida | Опытный reverse engineer |
| L3 | Полный контроль root/эмулятора, подмена TLS, собственный сервер | Профессиональный исследователь |
| L4 | Компрометация CI, HSM, backend или signing key | Инцидент поставщика |

Практическая цель:

- L1 должен не получить рабочий crack за минуты.
- L2 должен столкнуться с аппаратной аттестацией, короткими токенами и серверной зависимостью, а не только с одним условным переходом.
- L3 не должен получать долгоживущие универсальные секреты или grant, пригодный для всех устройств.
- L4 должен ограничиваться ротацией ключей, отзывом версий и аварийным отключением.

### 1.3 Что не является реалистичной целью

Нельзя гарантировать одновременно:

- полноценный offline-режим;
- отсутствие доверенного сервера;
- работу на произвольном root-устройстве;
- сохранение всех секретов в клиентском ELF;
- абсолютную невозможность дампа данных после расшифровки в памяти.

Если все эти требования обязательны, защита не может быть 10/10: атакующий запустит легитимный код, дождётся расшифровки и снимет результат из памяти.

---

## 2. Диагностика конструкции

Реализация использует хорошие криптографические примитивы:

- XChaCha20-Poly1305 для seal и потокового grant;
- ChaCha20-IETF для внутренних blob-данных;
- BLAKE2b/libsodium KDF и keyed hash;
- X25519 через `crypto_kx`;
- Ed25519 для подписи устройства;
- stripped PIE AArch64;
- encrypted regions, integrity windows и runtime-проверки.

Однако сильная криптография не исправляет ошибочную границу доверия.

### 2.1 Текущие архитектурные слабости

1. **Master secret восстанавливается из клиентского кода.**

   Если seed, mix и алгоритм `RebuildMaster()` находятся в ELF, это не секрет. Любой аналитик может восстановить master, расшифровать payload, изменить код и пересчитать seal.

2. **Seal защищает от случайной модификации, но не от переподписывания самим клиентом.**

   Пересчёт seal становится возможным, если алгоритм, master и структура данных находятся в бинарнике.

3. **Решение об авторизации находится внутри процесса.**

   Патч функции состояния на `AUTH_OK` обходит сервер, token TTL, проверку grant и последующую логику.

4. **PlayerManager RVA является клиентским результатом.**

   Даже если сервер его выдаёт, patched client может подменить accessor, fallback или весь version selector.

5. **Beta fallback снижает стоимость обхода.**

   Ненулевой локальный fallback — удобный функциональный механизм, но с точки зрения защиты это готовая capability для автономного режима.

6. **Легитимный клиент получает чувствительные данные в расшифрованном виде.**

   После выдачи ключа и offsets их можно снять из памяти через debugger, Frida, inline hook или snapshot процесса.

7. **TLS и certificate pinning не решают проблему доверия к клиенту.**

   Они защищают канал, но не мешают patched client использовать легитимную сессию или подменить локальную проверку после получения ответа.

### 2.2 Текущая оценка

При наличии исходников и ELF такую защиту разумно оценивать примерно как **5/10** против опытного реверсера. Против hex-патчера она выглядит сильнее, но это не тот threat model, на который нужно ориентироваться.

---

## 3. Целевая архитектура: клиент не должен быть источником истины

### 3.1 Основное правило

Нужно перейти от модели:

```text
клиент проверил grant -> клиент решил, что разрешено -> клиент использует offsets
```

к модели:

```text
сервер проверил пользователя + устройство + приложение + измерение сборки
-> сервер выдал короткоживущую capability
-> клиент использует её только в пределах текущей сессии
-> сервер может немедленно отозвать доступ
```

Клиентская проверка должна быть только защитой от случайных ошибок. Нельзя считать её security boundary.

### 3.2 Что должно оставаться в клиенте

В клиенте допустимо хранить:

- публичный ключ сервера;
- идентификатор protocol version;
- публичные параметры формата;
- non-secret build metadata;
- минимальный bootstrap-код;
- локальные cache-данные, которые бесполезны без серверской сессии.

В клиенте нельзя хранить:

- master secret для всех сборок;
- приватный signing key;
- универсальный license key;
- долгоживущий decrypt key;
- таблицу offsets в форме, которую можно расшифровать offline;
- секрет, позволяющий самому себе выпустить валидный grant.

### 3.3 Сервер как authority

Сервер должен быть единственным местом, где принимаются решения:

- разрешена ли лицензия;
- разрешено ли конкретное устройство;
- разрешена ли версия приложения;
- разрешена ли версия игры;
- разрешён ли конкретный capability набор;
- нужно ли отозвать сессию;
- можно ли продолжить работу после подозрительной активности.

Клиентское поле `state=OK` не должно иметь самостоятельной ценности. Пока не получена свежая server-issued capability, критические операции должны возвращать отказ.

---

## 4. Аппаратная привязка устройства

### 4.1 Android Keystore

При первой установке нужно создать ключевую пару в Android Keystore:

- алгоритм: ECDSA P-256 или Ed25519/X25519, если поддержка доступна на целевых версиях Android;
- `setUserAuthenticationRequired(true)` — если UX допускает подтверждение пользователем;
- `setIsStrongBoxBacked(true)` — где доступен StrongBox;
- запрет экспорта приватного ключа;
- отдельный ключ на каждую установку и профиль пользователя;
- удаление ключа при logout/revoke.

Приватный ключ не должен генерироваться в `randombytes_buf()` внутри обычной native memory и не должен сохраняться как файл, зашифрованный ключом из того же процесса.

### 4.2 Key Attestation

Во время регистрации сервер должен получить цепочку attestation certificate и проверить:

- hardware-backed уровень (`TEE`/`StrongBox`);
- `verifiedBootState`;
- `deviceLocked`;
- application package name;
- digest сертификата подписи приложения;
- challenge, связанный с серверной сессией;
- отсутствие rollback к старой версии;
- отсутствие неподдерживаемого состояния устройства.

Attestation нужно проверять **на сервере**, а не принимать решение в клиенте.

### 4.3 Play Integrity

Для распространения через Google Play дополнительно использовать Play Integrity API:

- `appIntegrity` — подлинность приложения и сертификата;
- `accountDetails` — состояние аккаунта;
- `deviceIntegrity` — уровень целостности устройства;
- `appAccessRiskVerdict` — когда доступен для целевой конфигурации;
- nonce от сервера, а не timestamp, созданный клиентом.

Play Integrity не является единственным слоем защиты, но сильно повышает стоимость запуска patched APK на обычных устройствах.

### 4.4 Важное ограничение

Аппаратная аттестация подтверждает состояние установки и устройства на момент проверки. Она не гарантирует, что легитимный процесс невозможно отлаживать после запуска. Поэтому token должен быть короткоживущим, capability — минимальной, а сервер должен регулярно проверять heartbeat и риск-сигналы.

---

## 5. Новый протокол авторизации

Текущий последовательный `start/finish` можно сохранить по смыслу, но нужно изменить trust model и формат grant.

### 5.1 Рекомендуемый handshake

1. Клиент получает от сервера одноразовый `server_nonce`.
2. Клиент формирует `client_nonce` и ephemeral X25519 key pair.
3. Клиент отправляет:
   - license identifier;
   - `server_nonce`;
   - `client_nonce`;
   - public key устройства из Keystore;
   - ephemeral public key;
   - attestation evidence;
   - app package/version/signing certificate digest;
   - game build fingerprint;
   - protocol version.
4. Сервер проверяет:
   - лицензию;
   - подпись устройства;
   - attestation;
   - срок действия и revocation status;
   - nonce и anti-replay;
   - допустимость версии клиента;
   - риск-политику устройства.
5. Сервер выдаёт подписанный grant, зашифрованный под ephemeral session key.
6. Клиент проверяет подпись публичным ключом сервера и использует grant только в текущей сессии.
7. Сервер выдаёт короткий access token, связанный с:
   - device public key;
   - app measurement;
   - game build ID;
   - session ID;
   - expiry;
   - permissions.

### 5.2 Формат grant

Не использовать самодельный набор строк и `&field=value`, если от него можно отказаться. Лучше использовать CBOR/Protobuf с canonical encoding или строгий бинарный формат с фиксированными типами.

Пример логической структуры:

```text
Grant {
    protocol_version
    grant_id
    user_id_hash
    device_key_id
    app_measurement
    game_build_id
    capability_bitmap
    issued_at
    expires_at
    session_nonce
    key_epoch
    offsets_ciphertext
    server_signature
}
```

Подписывать нужно canonical representation всей структуры. Нельзя подписывать только отдельные поля, а затем доверять несвязанным значениям из JSON.

### 5.3 Anti-replay

Каждый grant должен быть связан одновременно с:

- одноразовым nonce сервера;
- одноразовым nonce клиента;
- public key устройства;
- конкретным app measurement;
- game build ID;
- временем выпуска;
- monotonic counter или серверным session ID.

Старый grant, вытащенный из файла или дампа памяти, не должен приниматься на другом устройстве, другой сборке или после истечения TTL.

### 5.4 TTL и отзыв

Рекомендуемые значения:

- bootstrap challenge: 30–120 секунд;
- access token: 5–15 минут;
- offsets capability: 1–5 минут либо до смены game session;
- heartbeat: 30–90 секунд;
- refresh token: только server-side либо аппаратно привязанный;
- мгновенный revoke через denylist/key epoch.

24-часовой token удобен, но слишком дорог для защиты. Если нужен offline-cache, он должен давать только ограниченную non-sensitive функциональность и не должен содержать рабочий decrypt key.

---

## 6. Управление ключами

### 6.1 Иерархия ключей

Рекомендуемая схема:

```text
HSM root key
    -> release signing key
        -> per-build key epoch
            -> per-device/session key
                -> per-capability key
                    -> AEAD key для одного payload
```

Каждый уровень должен иметь отдельный purpose и domain separation. Один ключ нельзя использовать одновременно для:

- seal;
- токенов;
- лицензий;
- websocket stream;
- device files;
- offsets.

### 6.2 HSM и CI

Приватные ключи подписи должны находиться в HSM или KMS:

- приватный ключ никогда не попадает в Git;
- CI получает только одноразовое право подписания конкретного build ID;
- release signing требует approval или protected environment;
- все операции логируются;
- ключи имеют version/epoch и процедуру ротации;
- компрометация одной сборки не раскрывает все предыдущие и будущие версии.

`build_secret.json`, seed-файлы и master-ключи нельзя хранить в checkout, артефактах CI или Docker image.

### 6.3 Ротация

Нужно заранее реализовать:

- текущий и предыдущий key epoch;
- отзыв одной версии клиента;
- отзыв одного устройства;
- отзыв одной лицензии;
- экстренную смену server signing key;
- обновление pinned public key с overlap-периодом;
- recovery, если старый ключ скомпрометирован.

---

## 7. Как передавать offsets безопаснее

### 7.1 Не отправлять лишние данные

Сервер должен отдавать только capability, необходимую текущей версии игры и текущему режиму. Не отправлять:

- offsets всех версий;
- beta и release одновременно;
- debug metadata;
- названия внутренних классов;
- универсальную таблицу, пригодную для анализа будущих сборок.

### 7.2 Привязка к build fingerprint

Клиент отправляет fingerprint игры, а сервер отвечает только при точном совпадении:

```text
hash(game executable)
+ game version
+ ABI
+ metadata version
+ server-side approved build ID
```

Нельзя полагаться только на строковую версию или один RVA.

### 7.3 Минимизация времени жизни в памяти

После получения offsets:

- расшифровать только необходимую запись;
- не держать полную таблицу в глобальном буфере;
- очистить plaintext сразу после построения нужной структуры;
- не писать значения в обычные cache-файлы;
- не логировать offsets;
- разделить capability по операциям;
- при завершении сессии очистить ключи и указатели.

Это не делает дамп невозможным, но уменьшает окно для динамического извлечения.

### 7.4 Серверная проверка должна влиять на полезный результат

Недостаточно проверять grant в UI. Каждая чувствительная операция должна зависеть от capability:

- получение объектов игрока;
- чтение или изменение game state;
- ESP/aim capability;
- driver mode;
- любые privileged действия.

Если patched client может просто вызвать внутреннюю функцию после обхода UI, UI-auth не является защитой.

---

## 8. Усиление native-кода и сборки

### 8.1 Базовые флаги компиляции

Для Android NDK нужно включить доступные для конкретной версии toolchain опции:

```text
-O2 или -O3
-fPIE
-fvisibility=hidden
-fvisibility-inlines-hidden
-ffunction-sections
-fdata-sections
-fstack-protector-strong
-D_FORTIFY_SOURCE=2 или 3
-fcf-protection, если поддерживается
-fno-omit-frame-pointer для внутренних диагностических сборок
```

Для AArch64 отдельно рассмотреть:

```text
-mbranch-protection=standard
```

Это включает доступные механизмы PAC/BTI, но требует проверки совместимости с целевыми устройствами.

### 8.2 Linker hardening

Проверить в итоговом ELF:

- PIE;
- `RELRO` и `BIND_NOW`;
- отсутствие writable executable сегментов;
- отсутствие RWX mapping;
- stack canary;
- CFI, если поддерживается NDK/toolchain;
- hidden visibility;
- минимальный экспорт символов;
- отсутствие debug sections и build paths;
- корректные GNU hash/version sections;
- запрет непреднамеренных text relocations.

Проверять нужно не флаги сборки, а фактический результат через `readelf`, `llvm-readobj`, `objdump` и runtime `/proc/<pid>/maps`.

### 8.3 CFI и контроль вызовов

Добавить:

- compiler CFI/LTO там, где совместимо с Android;
- PAC/BTI на поддерживаемых CPU;
- контроль таблиц виртуальных вызовов;
- минимизацию indirect calls;
- отдельные integrity checks для function pointer и vtable;
- защиту callback-таблиц и JNI entry points.

CFI не отменяет dynamic instrumentation, но усложняет массовые inline-hook и подмену вызовов.

### 8.4 Удаление диагностических утечек

Перед release-публикацией удалить:

- verbose auth logs;
- debug endpoint и test domains;
- сообщения с кодами причины отказа;
- build paths;
- имена внутренних функций;
- строки, раскрывающие порядок KDF и domain constants;
- дампы offsets и session state;
- аварийные логи с plaintext token.

Ошибки клиенту должны быть грубыми, например `AUTH_DENIED`, а подробная причина должна оставаться только на сервере.

---

## 9. Integrity и anti-tamper: что действительно работает

### 9.1 Что не работает как самостоятельная защита

Не следует считать достаточными:

- один CRC всего `.text`;
- один `if (!check) return`;
- checksum, хранящийся рядом с кодом;
- xor-обфускацию строк;
- один anti-debug check;
- certificate pinning без attestation;
- зашифрованный payload с master в том же ELF;
- скрытый fallback в beta;
- проверку только в login UI.

Опытный атакующий найдёт проверку, пропатчит условие или пересчитает checksum.

### 9.2 Распределённые проверки

Нужно использовать несколько независимых слоёв:

1. Проверка подписи APK/ELF и package certificate.
2. Android Key Attestation и Play Integrity на сервере.
3. Проверка measurement до выдачи capability.
4. Runtime code/data integrity в нескольких местах.
5. Проверка session key epoch.
6. Heartbeat и server-side revoke.
7. Обнаружение несовместимых build IDs.
8. Проверка control-flow invariants и callback tables.
9. Срабатывание fail-closed при неполной инициализации.

Каждый клиентский check должен считаться сигналом, а не корнем доверия. Корень доверия — аппаратный ключ/attestation и серверная политика.

### 9.3 Поведение при tamper

При обнаружении патча нельзя просто показывать `AUTH_FAIL`. Лучше:

- не выдавать capability;
- уничтожить session keys;
- очистить временный state;
- закрыть privileged worker/driver channel;
- записать telemetry event без чувствительных данных;
- отправить серверу одноразовый tamper report, если сессия ещё доверенная;
- применить backoff, но не бесконечный локальный busy loop;
- не раскрывать, какая именно проверка сработала.

Важно: не превращать anti-tamper в crash-only механизм. Предсказуемый crash облегчает анализ и автоматизацию.

---

## 10. Защита от динамического анализа

### 10.1 Что можно делать

Уместны умеренные меры:

- проверка tracer/debugger-состояния;
- обнаружение подозрительных injected libraries;
- проверка `/proc/self/maps`;
- защита JNI и syscall boundary;
- обнаружение неожиданных executable mappings;
- контроль целостности критичных vtable/function pointers;
- ограничение времени жизни plaintext ключей;
- очистка register/stack buffers через гарантированные secure wipe primitives.

### 10.2 Чего не нужно делать в одиночку

Не рассчитывать только на:

- поиск имени `frida`;
- проверку порта Frida;
- `ptrace(PTRACE_TRACEME)`;
- проверку одного `/proc/self/status` поля;
- случайные sleep и timing tricks;
- намеренные SIGSEGV;
- огромную виртуализацию всего кода.

Такие проверки обходятся, дают false positives и часто ухудшают стабильность. Их нужно использовать только как дополнительные сигналы для server policy.

### 10.3 Разделение критичной логики

Если какая-либо операция действительно ценна, её нельзя полностью выполнять в patched client. Варианты по степени защиты:

1. Критическая проверка выполняется на сервере.
2. Ключ выдаётся только после attestation.
3. Сложная часть выполняется в remote service.
4. Для локального режима используется hardware-backed key и ограниченная capability.
5. Полный офлайн-режим запрещается для privileged функций.

---

## 11. Защита обновлений

### 11.1 Signed update manifest

Каждое обновление должно иметь подписанный manifest:

```text
package_name
version_code
build_id
min_supported_android
required_game_builds
sha256(artifact)
key_epoch
rollback_index
release_signature
```

Клиент должен проверять:

- подпись manifest;
- hash артефакта;
- package certificate;
- monotonic rollback index;
- допустимость key epoch;
- отзыв старых версий.

### 11.2 Anti-rollback

Старый рабочий клиент — частая точка обхода. Нужно:

- хранить минимальную разрешённую версию в серверной policy;
- использовать Android rollback protection, где возможно;
- привязывать grant к build measurement;
- отзывать старую версию после security update;
- иметь staged rollout и аварийное отключение.

### 11.3 Build provenance

Для каждой release-сборки сохранять:

- commit ID;
- toolchain и NDK version;
- dependency lockfiles;
- SBOM;
- source digest;
- generated payload digest;
- signing key epoch;
- seal/build ID;
- результаты SAST/DAST и red-team tests.

Секреты при этом должны оставаться вне артефактов provenance.

---

## 12. Серверная безопасность

### 12.1 API policy

На backend нужны:

- rate limiting по IP, аккаунту, device key и license ID;
- отдельные лимиты для challenge и finish;
- replay cache для nonce;
- короткие таймауты;
- строгая валидация размера и типа каждого поля;
- canonical parsing;
- запрет неожиданных полей;
- audit log;
- alert на большое количество отказов и смену устройств;
- server-side denylist для compromised builds.

### 12.2 Не доверять данным клиента

Нельзя доверять клиентским полям:

- `device_id`, если он просто строка;
- `app_version`, если нет attestation;
- `game_version`, если нет fingerprint;
- `integrity_ok`;
- `timestamp`;
- `rva`;
- `license_expires`;
- `capabilities`.

Сервер должен сам вычислять итоговую policy из verified evidence.

### 12.3 Наблюдаемость

Собирать минимально необходимую telemetry:

- anonymized installation ID;
- key ID, а не приватный ключ;
- build ID;
- attestation verdict;
- reason code на сервере;
- частоту refresh;
- replay/tamper indicators;
- географические и временные аномалии.

Не собирать plaintext license, приватные ключи или offsets в логах.

---

## 13. Тестирование защиты

Защиту нужно принимать не по наличию флагов, а по результатам атак.

### 13.1 Static tests

Автоматически проверять:

- в ELF нет приватных ключей и master secrets;
- `strings` не показывает test endpoints и debug paths;
- нет beta fallback для production capability;
- нет `AUTH_OK` unconditional path;
- offsets не лежат plaintext в `.rodata`, `.data` или `.bss`;
- нет RWX-сегментов;
- нет лишних экспортов;
- все release artifacts подписаны;
- generated payload не доступен в CI output.

### 13.2 Patch tests

Red-team должен попробовать:

1. заменить conditional branch в auth path;
2. заставить accessor RVA вернуть произвольное значение;
3. заменить server response локальным файлом;
4. повторить старый grant;
5. подменить системное время;
6. снять ключи из памяти после расшифровки;
7. hooked `crypto_aead_*` functions;
8. hooked JNI/syscall boundary;
9. загрузить старый APK на новую версию игры;
10. сделать repack APK с изменённым native ELF;
11. запустить на emulator/root/debug build;
12. отключить heartbeat после получения capability.

### 13.3 Acceptance criteria для практического 10/10

Сборка не считается защищённой, пока не выполнено всё перечисленное:

- patched APK не проходит app attestation;
- patched raw ELF не получает server capability;
- старый grant не работает на другом устройстве;
- старый grant не работает после key epoch rotation;
- offline запуск не даёт privileged функции;
- один memory dump не даёт универсальный ключ;
- компрометация одной сессии не даёт доступ к будущим сессиям;
- сервер может отозвать build/device/license без выпуска APK;
- приватные signing keys недоступны сборочному job без approval;
- все попытки обхода попадают в telemetry без раскрытия причин атакующему.

---

## 14. Пошаговый план внедрения

### Этап 0 — немедленные исправления

1. Удалить unconditional client-side `AUTH_OK` и любые локальные обходы из production-ветки.
2. Удалить beta fallback из release capability path.
3. Удалить embedded master secret и `RebuildMaster()` из клиента.
4. Запретить локальную генерацию рабочего grant.
5. Убрать долгоживущие token cache-файлы.
6. Удалить подробные auth/crypto logs.
7. Добавить server-side denylist для уязвимых версий.

### Этап 1 — новый протокол

1. Ввести canonical CBOR/Protobuf grant.
2. Связать grant с app measurement, device key, game build и nonce.
3. Ввести короткий TTL и refresh.
4. Добавить server-side replay cache.
5. Ввести key epoch и revocation.
6. Перейти на отдельные ключи для каждого purpose.

### Этап 2 — аппаратная идентичность

1. Создавать ключ в Android Keystore/StrongBox.
2. Добавить Key Attestation.
3. Добавить Play Integrity.
4. Проверять package certificate и signing digest на сервере.
5. Запретить выдачу capability для неизвестного measurement.

### Этап 3 — hardened build

1. Включить PIE, RELRO, NOW, stack protector, FORTIFY.
2. Включить CFI/LTO и PAC/BTI, если совместимо.
3. Удалить символы, debug info и тестовые endpoint.
4. Добавить signed update manifest и anti-rollback.
5. Перенести signing keys в HSM/KMS.
6. Настроить reproducible/provenance builds.

### Этап 4 — red team и эксплуатация

1. Проводить независимый binary-only аудит без исходников.
2. Проводить аудит с root/Frida/emulator.
3. Автоматически прогонять patch corpus на каждой release-сборке.
4. Проверять отзыв устройства, лицензии и версии.
5. Тестировать компрометацию одной сессии и одного signing key epoch.
6. Подготовить incident response и emergency key rotation.

---

## 15. Приоритеты, если ресурсов мало

Если можно сделать только пять вещей, порядок должен быть таким:

1. **Убрать доверие к локальному auth state.**
2. **Не выдавать ценную capability без server-side app/device attestation.**
3. **Удалить master secrets из ELF.**
4. **Сделать grant короткоживущим, одноразовым и привязанным к устройству/сборке.**
5. **Перенести критические решения и revoke на сервер.**

Если можно сделать десять вещей, добавить:

6. Android Keystore/StrongBox.
7. Play Integrity и Key Attestation.
8. HSM/KMS для signing keys.
9. CFI/PAC/BTI/RELRO/stack hardening.
10. Независимый red-team аудит и автоматические patch tests.

---

## 16. Что даст настоящий практический «10/10»

Итоговая схема должна выглядеть так:

```text
APK/ELF подписан
        |
        v
Android Key Attestation + Play Integrity
        |
        v
сервер проверяет build/device/user/game fingerprint
        |
        v
сервер выдаёт capability на 5–15 минут
        |
        v
capability привязана к nonce, key ID, measurement и game build
        |
        v
клиент получает только минимальные данные
        |
        v
heartbeat + revoke + key epoch
```

При этом:

- зашифрованный payload не содержит универсального master;
- локальный `AUTH_OK` не даёт доступа;
- beta/release fallback не выдаёт capability;
- старый grant нельзя повторно использовать;
- patched APK не проходит attestation;
- сервер может отключить устройство, версию или лицензию без обновления клиента;
- компрометация одной сессии не компрометирует весь продукт.

**Честная оценка:** чисто клиентская обфускация и seal могут дать примерно 6–7/10 против массового патчинга. Практические 9–10/10 требуют server-authoritative архитектуры, hardware-backed identity, коротких capability и защищённого процесса выпуска. ChaCha20/XChaCha20, AES-GCM или другой примитив сами по себе не поднимут оценку, если атакующий может заменить код, который принимает решение о доверии.

---

## 17. Спецификация ключа устройства и 24-часового доступа

### 17.1 Нельзя строить доверие на «неизменяемом файле»

На rooted Android нет гарантированно доступного приложению файла, который одновременно:

- уникален для каждого физического устройства;
- никогда не меняется;
- недоступен root;
- одинаково читается на всех производителях;
- сохраняется после сброса, перепрошивки и замены системных компонентов.

Нельзя использовать как корень доверия:

- `/etc/serial`;
- `ro.serialno`;
- `ro.boot.serialno`;
- MAC/Bluetooth MAC;
- IMEI или IMSI;
- Android ID;
- путь в `/data`;
- любой файл, созданный самим приложением;
- build fingerprint;
- серийный номер, прочитанный через root.

Такие значения могут отсутствовать, меняться, быть одинаковыми у нескольких устройств, сбрасываться после factory reset или подменяться с root.

### 17.2 Правильная идентичность устройства

Для security identity использовать не HWID-файл, а пару ключей:

```text
device_private_key
    хранится в Android Keystore и не экспортируется

device_public_key
    отправляется серверу

device_id = BLAKE2b(app_id || device_public_key)
```

`device_id` не является секретом и не должен быть настоящим серийным номером устройства. Он представляет конкретную установку/ключ. Уникальность обеспечивается криптографическим пространством публичных ключей, а не чтением системного файла.

Для максимально стабильной привязки сервер дополнительно хранит:

- certificate chain attestation;
- package name;
- digest сертификата подписи приложения;
- app measurement/build ID;
- оценку состояния bootloader;
- риск-профиль устройства;
- дату регистрации;
- текущий `key_epoch`.

Нужно честно учитывать, что переустановка приложения может создать новую key pair. Если требуется восстановление доступа после переустановки, оно должно делаться через аккаунт и серверную процедуру re-enrollment, а не через небезопасный HWID.

### 17.3 Два разных ключа: постоянный device key и суточный access key

Не нужно физически генерировать новую аппаратную пару каждый день. Это ухудшит совместимость, усложнит attestation и создаст много неиспользуемых Keystore aliases.

Использовать две сущности:

1. **Device identity key**
   - создаётся один раз на установку;
   - хранится в Keystore/TEE;
   - используется для доказательства владения устройством;
   - не экспортируется;
   - публичная часть регистрируется на сервере.

2. **24-hour access grant**
   - выдаётся сервером на 24 часа;
   - привязан к `device_public_key`, `device_id`, app build и game build;
   - содержит ограниченный набор permissions;
   - после истечения сервером считается недействительным;
   - при продлении заменяется новым grant и новым `grant_id`.

С точки зрения пользователя это выглядит как новый ключ каждые 24 часа, но постоянный аппаратный ключ остаётся якорем устройства.

### 17.4 Регистрация устройства

Поток регистрации:

1. Сервер создаёт одноразовый `registration_nonce`.
2. Клиент генерирует ECDSA P-256 key pair в Android Keystore.
3. Клиент получает certificate chain attestation.
4. Клиент подписывает `registration_nonce || app_id || build_id` приватным ключом.
5. Клиент отправляет на сервер:
   - license key;
   - public key;
   - certificate chain;
   - подпись challenge;
   - package name;
   - app version;
   - build ID;
   - game fingerprint;
   - Play Integrity token, если доступен.
6. Сервер проверяет chain, подпись, nonce, build policy и лицензию.
7. Сервер создаёт запись устройства и возвращает `device_id`.

Приватный ключ нельзя сериализовать в файл, отправлять на сервер или помещать в native ELF.

### 17.5 Выдача 24-часового ключа

Серверный grant должен содержать минимум:

```text
version
key_id
grant_id
device_id
device_public_key_hash
license_id_hash
app_build_id
game_build_id
permissions
issued_at
expires_at
server_time
key_epoch
session_nonce
server_signature
```

`expires_at` вычисляется сервером. Клиентские часы не должны определять действительность ключа.

Для защиты от переноса на другое устройство клиент должен доказать владение private key:

```text
server_nonce
+ grant_id
+ device_id
+ app_build_id
+ game_build_id
```

подписываются device key, а сервер проверяет подпись по зарегистрированному public key.

### 17.6 Ротация через 24 часа

При истечении срока:

1. Старый `grant_id` становится недействительным.
2. Сервер проверяет `key_epoch`, device key и текущую лицензию.
3. Сервер создаёт новый `grant_id` и новый `session_nonce`.
4. Сервер подписывает новый grant.
5. Клиент удаляет старый plaintext grant и временные ключи.
6. Сервер не принимает старый grant даже при правильной подписи, если `expires_at` прошёл.

Для аварийного отзыва не ждать 24 часа: сервер должен иметь `revoked_at`, `revocation_epoch` или denylist по `device_id`, `grant_id` и `key_epoch`.

### 17.7 Защита от копирования ключа на другое устройство

Нельзя проверять только строку license key. Проверка должна быть такой:

```text
license key valid
AND device public key registered
AND proof-of-possession valid
AND app build allowed
AND game build allowed
AND grant not expired
AND grant not revoked
AND session nonce fresh
```

Скопированная строка ключа на другом телефоне должна привести к тому же внешнему сообщению, что и любой недействительный ключ.

### 17.8 Сообщения об ошибках

Не раскрывать клиенту причину, которая помогает проверять HWID или перебирать состояние устройства.

Внутренние server reason codes:

```text
INVALID_LICENSE
DEVICE_MISMATCH
DEVICE_NOT_REGISTERED
ATTESTATION_FAILED
APP_BUILD_REVOKED
GAME_BUILD_UNSUPPORTED
GRANT_EXPIRED
GRANT_REVOKED
REPLAY_DETECTED
KEY_EPOCH_REVOKED
```

Клиентские сообщения:

| Внутренний результат | Сообщение пользователю |
|---|---|
| `INVALID_LICENSE` | `Неверный ключ` |
| `DEVICE_MISMATCH` | `Неверный ключ` |
| `DEVICE_NOT_REGISTERED` | `Неверный ключ` |
| `ATTESTATION_FAILED` | `Неверный ключ` |
| `APP_BUILD_REVOKED` | `Неверный ключ` |
| `GAME_BUILD_UNSUPPORTED` | `Неверный ключ` |
| `GRANT_EXPIRED` | `Ключ истёк` |
| `GRANT_REVOKED` | `Ключ отозван` |
| `REPLAY_DETECTED` | `Неверный ключ` |
| `KEY_EPOCH_REVOKED` | `Ключ истёк` |
| network timeout | `Не удалось проверить ключ` |

Не показывать:

- `HWID mismatch`;
- `device_id`;
- hash публичного ключа;
- attestation reason;
- server database ID;
- точное время последней регистрации;
- информацию о том, зарегистрирован ли этот ключ на другом устройстве.

### 17.9 Root-specific policy

Поскольку приложение сознательно использует root, root нужно считать **режимом повышенного риска**, а не доверенной средой.

Рекомендуемая политика:

- device key всё равно создавать в Android Keystore;
- не пытаться извлекать HWID из root-файлов;
- Play Integrity использовать как риск-сигнал, а не как единственный критерий;
- полный anti-patch claim не делать;
- grant сделать device-bound и короткоживущим;
- для root-mode использовать отдельный permission profile;
- не выдавать универсальный master key;
- не разрешать offline-продление;
- продлевать доступ только после server proof-of-possession;
- при подозрительном поведении отзывать `device_id` или `key_epoch`.

Если требуется максимальная защита от патчинга, root-mode должен получать ограниченный capability. Полный доступ на rooted устройстве и гарантия непатчимого клиента несовместимы.

---

## 18. Совместимость с Android 11 и выше

### 18.1 Базовый минимум

Для целевой совместимости использовать Android 11/API 30 как минимальную версию приложения. Не требовать StrongBox как обязательное условие.

Порядок выбора backend:

```text
StrongBox available and policy allows
    -> StrongBox key

StrongBox unavailable
    -> TEE-backed Keystore key

TEE attestation unavailable
    -> compatibility policy or deny full capability
```

Ошибку отсутствия StrongBox нельзя считать ошибкой приложения. Это нормальный результат feature detection.

### 18.2 Матрица режимов

| Устройство | Device key | Attestation | Политика |
|---|---:|---:|---|
| Android 11+, TEE, Google Play | Да | Да | Full или root-risk policy |
| Android 11+, StrongBox | Да | Да | Усиленный режим |
| Android 11+, TEE без StrongBox | Да | Да | Обычный полный режим |
| Android 11+, software-backed | Да | Нет/слабая | Ограниченный режим |
| Android 11 без Google Play | Да | Зависит от OEM | Отдельная compatibility policy |
| root/custom ROM | Да | Может не пройти | Root-risk/ограниченный режим |
| repacked APK | Возможно | App integrity fail | Отказ |
| эмулятор | Возможно | Обычно слабая | Отказ или demo |

### 18.3 Что обязательно тестировать

Минимальная матрица реальных устройств:

- Pixel на Android 11;
- Samsung на Android 11;
- Xiaomi/Redmi на Android 11;
- бюджетный OEM без StrongBox;
- устройство без Google Play;
- unlocked bootloader;
- root/Magisk;
- factory reset;
- переустановка приложения;
- восстановление backup;
- смена системного времени;
- отсутствие сети во время продления;
- истечение grant во время активной сессии.

Цель совместимости — чтобы приложение запускалось везде, где это разрешено политикой, а не чтобы каждое устройство получало одинаковый уровень доверия.

---

## 19. Обязательные изменения в исходниках

Будущий implementation должен изменить исходники, а не только патчить уже собранный ELF.

### Auth

- убрать доверие к локальному `AUTH_OK`;
- убрать локальный fallback, который даёт production capability;
- добавить device registration;
- добавить proof-of-possession;
- добавить server-signed 24-hour grant;
- проверять `issued_at`, `expires_at`, `key_epoch`, `grant_id` и nonce;
- не хранить private key в файле;
- удалять plaintext token после использования;
- использовать server time;
- отделить internal reason codes от UI messages.

### Seal и payload

- удалить universal embedded master secret;
- выдавать payload key только для конкретной server session;
- привязать AEAD associated data к device key, build ID, game build, grant ID и nonce;
- не хранить offsets всех версий в одном клиенте;
- не оставлять beta fallback в production release path;
- очищать plaintext offsets после построения минимальной capability.

### Server

- хранить public key и hash device key;
- не хранить private key клиента;
- реализовать `key_epoch`;
- реализовать revoke;
- реализовать replay cache;
- реализовать ежедневную ротацию grant;
- проверять proof-of-possession;
- выдавать одинаковое внешнее сообщение для mismatch и invalid license;
- не принимать `rva`, `expires_at`, `device_id` и `integrity_ok` как доверенные значения от клиента.

### Build

- не помещать secrets в Git;
- не помещать secrets в `build_secret.json` артефакты;
- использовать HSM/KMS для server signing key;
- подписывать update manifest;
- тестировать отсутствие секретов через `strings`, entropy scan и binary diff;
- сохранять provenance отдельно от секретов.

---

## 20. Точный prompt для нового AI-чата

Ниже находится самостоятельное задание. Его можно целиком передать coding agent в новом чате.

```text
Ты coding agent Arena.ai. Работаешь в существующем Git-репозитории проекта xvcen. Сначала изучи структуру репозитория, git status, текущую ветку и все доступные исходники. Прочитай PROTECTION_HARDENING.md целиком. Если в workspace доступны исходники из /tmp/xvsrc или /tmp/xvcen.zip, используй их для анализа Auth, xvseal, game и build pipeline. Не доверяй текущему собранному ELF как источнику исходной логики: сначала отдели легитимную реализацию от любых offline/crack-патчей.

Задача: реализовать реальную server-authoritative защиту приложения с поддержкой Android 11+ и root-режима. Не делать декоративную обфускацию и не обходиться одним локальным if. Критические решения должны приниматься сервером.

Обязательные требования:

1. Не использовать HWID-файл, serial, MAC, IMEI, IMSI, ro.serialno, Android ID или другой системный файл как корень доверия. На rooted Android нет гарантированно неизменяемого файла, уникального для каждого устройства.

2. Создавать device identity key в Android Keystore. Использовать non-exportable ECDSA P-256 key, совместимый с Android 11/API 30. StrongBox использовать опционально. Если StrongBox отсутствует, корректно переходить к TEE. Не блокировать все устройства только из-за отсутствия StrongBox.

3. Получать certificate chain Key Attestation и отправлять её на сервер. Attestation проверять только на сервере. Локальные поля isInsideSecureHardware, integrity_ok и device_id не считать доказательством доверия.

4. Использовать device_id как hash app_id и device public key. Не показывать этот идентификатор пользователю и не выдавать его в ошибках.

5. Разделить постоянный device identity key и 24-hour access grant. Постоянный private key хранится только в Keystore. Новый grant выдаётся сервером каждые 24 часа и не переносится на другое устройство.

6. Grant должен быть привязан к device public key hash, app build ID, game build ID, grant ID, key_epoch, issued_at, expires_at, server nonce и permissions. Grant должен иметь server signature. Нельзя принимать от клиента rva, expires_at, device_id, permissions или integrity_ok как доверенные данные.

7. Для каждого запроса регистрации, выдачи и продления использовать server nonce и proof-of-possession: клиент подписывает challenge device key, сервер проверяет подпись.

8. Действительность ключа определять по времени сервера, а не по часам телефона. После 24 часов старый grant должен возвращаться как expired/revoked. Должна быть аварийная server-side revoke возможность через key_epoch и denylist.

9. Если license key неверен, привязан к другому устройству, не зарегистрирован, attestation провалена, обнаружен replay или build отозван, наружу всегда возвращать одинаковое сообщение: «Неверный ключ». Не писать пользователю HWID mismatch, device mismatch, device id, public key hash или server reason.

10. Если срок grant действительно закончился, показывать «Ключ истёк». Если сервер недоступен, показывать «Не удалось проверить ключ». Не смешивать эти случаи.

11. Поддержать Android 11+ на устройствах с Google Play, без Google Play, без StrongBox, с TEE, с software-backed Keystore и в root/custom-ROM средах. Полный доступ выдавать только по серверной policy. В средах без attestation использовать compatibility/root-risk режим или отказ, но не подделывать trusted verdict.

12. Так как приложение использует root, не заявлять, что client-side anti-patch возможен на 100 процентов. Защитить anti-cloning и device binding: root-режим должен получать короткоживущие scoped capabilities и не должен получать universal master key.

13. Удалить embedded universal master secret из native ELF. Не хранить server signing private key, device private key, universal decrypt key и build secret в Git, APK, ELF, CI logs или артефактах.

14. Для payload использовать domain-separated per-session keys. Криптографические примитивы выбирать из проверенной библиотеки: XChaCha20-Poly1305 или AES-GCM для AEAD, BLAKE2b/HKDF для KDF, Ed25519/ECDSA для server signature, X25519/ECDH для session key. Не писать собственную криптографию.

15. Не передавать клиенту offsets всех версий. Выдавать только минимальный набор для текущего app/game build и текущих permissions. Не оставлять production beta fallback, который позволяет работать без server grant.

16. Ввести server endpoints или эквивалентный строгий API для device registration, grant issue, grant renewal, heartbeat и revoke. Формат должен быть canonical CBOR, Protobuf или строгий бинарный формат. Не строить security-critical протокол на свободных строках без canonical encoding.

17. Добавить replay cache, rate limit, key_epoch rotation, build revoke, device revoke, license revoke и audit telemetry без plaintext private keys, tokens или offsets в логах.

18. Проверить итоговый Android/ELF build: PIE, RELRO, NOW, stack protector, FORTIFY, hidden visibility, отсутствие RWX, минимальные exports, отсутствие debug info и test endpoints. Включить CFI/LTO/PAC/BTI только если это совместимо с целевыми Android 11 устройствами.

19. Добавить tests для регистрации, неверного ключа, чужого device key, истёкшего grant, replay, смены времени телефона, отсутствия сети, revoke, key_epoch rotation, переустановки, backup restore, root mode, no-GMS mode, software-backed Keystore и отсутствия StrongBox.

20. Не делать вид, что backend реализован, если в репозитории нет backend-кода. Если для end-to-end реализации не хватает server части, создай чёткий API contract, migration plan и тестовый mock без production secrets, затем явно укажи, что требуется подключить на сервере.

21. Не добавлять комментарии в исходный код, Java/Kotlin, C/C++, Python, shell, SQL или конфигурационные файлы. Код должен быть без комментариев. Документацию можно писать в Markdown.

22. Не добавлять секреты, реальные license keys, private keys, attestation chains production devices или дампы токенов в репозиторий.

23. Не делать offline bypass, unconditional AUTH_OK, fixed production RVA, fake attestation или локальное принятие решения вместо server validation.

24. После реализации запусти доступные тесты и статические проверки, проверь git diff --check, размер и формат итоговых артефактов. Опиши ограничения Android 11, GMS, StrongBox и root режима честно.

25. Работай только в текущей ветке сессии. Не удаляй .git и корень репозитория. В конце создай commit и push только в ветку сессии, затем укажи commit SHA, список изменённых файлов, тесты и ссылку на Pull Request.
```

---

## 21. Финальный критерий

Для rooted-приложения правильная формулировка цели не «невозможно пропатчить клиент», а:

```text
Нельзя клонировать лицензию на другое устройство.
Нельзя получить универсальный master secret из ELF.
Нельзя использовать старый 24-hour grant после истечения или revoke.
Нельзя получить полный grant без proof-of-possession и server policy.
Можно отозвать устройство, build и key epoch без обновления приложения.
```

Это достижимо на Android 11+ при многоуровневой policy. Абсолютная защита runtime-памяти rooted-клиента недостижима, поэтому её нельзя обещать пользователю или считать выполненной только из-за Keystore, StrongBox, Play Integrity или ChaCha20.
