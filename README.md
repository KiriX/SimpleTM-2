ТРЕКЕР ЗАДАЧ (Python 3 + SQLite, без внешних пакетов)

Запуск:           python3 app.py            (порт 8080)
                  python3 app.py --port 8000 --host 127.0.0.1
Первый запуск:    создаётся пользователь admin, пароль выводится в консоль.
Пользователи:     через веб-интерфейс (меню «Пользователи») или
                  python3 app.py adduser LOGIN "Имя Фамилия" [--admin]
                  python3 app.py passwd LOGIN      (сброс пароля)
Данные:           папка data/ (tasks.db + files/). Резервная копия = копия папки.
Автозапуск:       см. tasktracker.service
Если порт закрыт firewall'ом:  sudo ufw allow 8080/tcp

Версия и история изменений: CHANGELOG.md (версия также внизу каждой страницы и в "python3 app.py --version").
