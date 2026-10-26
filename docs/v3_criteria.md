# Критерії оцінки infer2 v3 (зафіксовано до першого запуску)

Дата: 2026-10-26.
Контрольний набір: results/heldout_manifest.json (коміт 8939e22), 12 захоплень DNS і ті самі файли pcapng як контейнер.
Розробницькі набори: EVTX, DNS (results/dns_structure_eval.json, коміт eebd4a9).

## Зміни відносно v2

1. Значення-винятки: значення поля, що не влучає ніколи (не більше двох таких), виключаються з підрахунку підтримки; решта значень мають влучати щонайменше у 90% своїх читань, різних значень не менше трьох.
2. Довжина з заголовком: для правила перевіряються дві форми, значення = сума наступних читань або значення = довжина читання-заголовка + сума.
Пороги RULE_MIN_OCC=5, RULE_MIN_SUPPORT=0.6, RULE_MIN_DISTINCT=3, MIN_VAL=1 і всі ролі лишаються без змін.

## Спостереження над v2 до розробки

- DNS, байт довжини мітки: одне місце читання, 345 читань, з них 120 довжин міток; максимальна підтримка 120/345 = 0.348 < 0.6 (experiments/e20_infer2.py, рядки 7 і 121).
- DNS, RDLENGTH: 165 читань, 105 ненульових; підтримка 105/165 = 0.636, лише трохи вище порога 0.6. Нульові значення (OPT) відхиляються через MIN_VAL=1.

## Прогноз до запуску на контрольних даних

- v2: довжина мітки імені не розпізнається.
- v2: RDLENGTH може не розпізнатися, якщо частка ненульових значень менша за 0.6.
- v3: обидва поля розпізнаються; контейнер pcapng (довжина блоку з заголовком) розпізнається.

## Показники

- П1: частка справжніх полів довжини (довжина мітки, RDLENGTH, довжина блоку pcapng), що отримали роль довжина.
- П2: кількість полів іншого типу з роллю довжина (очікується 0).
- П3: частка істинних полів із точним збігом інтервалу (не повинна зменшитись відносно v2).
Розмітка істини для DNS береться з experiments/e28_dns_structure_eval.py; читач pcapng і розмітка додаються окремим комітом до першого запуску.

## Регресія

На всіх старих наборах (XDT, CFG1, PNG, DOCX, WAV, EVTX, DNS) жодна роль, правильна у v2, не повинна змінитись. Кожна зміна ролі пояснюється у звіті.

## Рішення

Запуск на контрольних даних один, після заморожування v3. Пороги під контрольні дані не підбираються.
- П1 росте, П2 = 0, регресії немає: v3 стає основним, v2 лишається базою в таблиці.
- Інакше: основним лишається v2, а v3 описується як частковий або негативний результат.

## Pre-implementation clarification: EVTX offset

Added after inspecting demo/evtx_reader.py, before creating or running v3.
No held-out inference results have been inspected.

The EVTX reader reads the record signature (4 bytes) and size (4 bytes)
separately. After the size field, the reads through the record trailer
sum to size - 8. Therefore the previously proposed relation
value = current_read_length + following_read_sum does not describe
the intended EVTX record boundary.

An offset of 4 can also produce an accidental match by including the
next record signature. A numeric match alone is not evidence of a
correct related interval.

The offset-learning design remains unresolved. No EVTX-specific
constant is to be introduced as a general solution without an explicit
design amendment. Acceptance criteria remain unchanged.
