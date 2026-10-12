MIST hardening-32 — Windows portable

1. Это консольная тестовая сборка, а не графическое приложение.
2. Файлы mist-*-windows-amd64.exe не надо запускать двойным кликом напрямую.
3. Запускай START-MIST.cmd. Он сам запросит права администратора и не закроет окно при ошибке.
4. Для работы рядом должен лежать client.json с реальными параметрами твоего MIST-сервера.
   Если client.json отсутствует, START-MIST.cmd создаст его из client.example.json и откроет в Блокноте.
   Проще всего скопировать client.json из предыдущей рабочей сборки MIST и проверить новые поля.
5. Для аварийного восстановления маршрутов/DNS запусти RECOVER-MIST.cmd.

Основной запуск вручную из PowerShell (Администратор):
  .\mist-client-windows-amd64.exe -config .\client.json -transport auto

Важно:
- Linux-архив MIST-Linux-Edge-amd64 предназначен для VPS Linux и на Windows не запускается.
- Windows Explorer может скрывать расширение .exe. Поэтому в проводнике имя выглядит как mist-client-windows-amd64 без '.exe'.
