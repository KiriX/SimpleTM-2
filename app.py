#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Простой трекер задач. Только стандартная библиотека Python 3.9+ и SQLite.

Запуск:            python3 app.py                (порт 8080, все интерфейсы)
                   python3 app.py --port 8000 --host 127.0.0.1
Пользователи:      python3 app.py adduser LOGIN "Имя Фамилия" [--admin]
                   python3 app.py passwd LOGIN
Данные:            папка data/ рядом с app.py (tasks.db и files/)
"""
import argparse
import getpass
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import sys
import time
import traceback
from email import policy
from email.parser import BytesParser
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, parse_qsl, quote, urlencode, urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("TT_DATA", os.path.join(BASE, "data"))
FILES = os.path.join(DATA, "files")
DB = os.path.join(DATA, "tasks.db")
MAX_UPLOAD = 100 * 1024 * 1024      # максимум на одну отправку формы, байт
SESSION_SECONDS = 14 * 86400

PRIO = {0: "Низкий", 1: "Обычный", 2: "Высокий", 3: "Срочный"}
STATUS = {"new": "Новая", "work": "В работе", "info": "Запрос информации",
          "infook": "Информация предоставлена",
          "done": "Выполнена", "checked": "Проверено", "returned": "Возвращено",
          "cancel": "Отменена"}
FINAL = ("checked", "cancel")                                   # закрытые задачи
ACTIVE = tuple(x for x in STATUS if x not in FINAL)             # фильтр «Активные»
WORKING = ("new", "work", "info", "infook", "returned")  # здесь важен срок
# при переходе в эти статусы комментарий обязателен
COMMENT_REQUIRED = ("info", "infook", "done", "cancel", "returned")
LEGACY = {"review": "На проверке"}   # упразднённый статус: только для подписей в старых комментариях
# из какого статуса в какие можно перейти
TRANSITIONS = {
    "new": ("work", "info", "done", "cancel"),
    "work": ("info", "done", "cancel"),
    "info": ("infook", "work", "cancel"),
    "infook": ("work", "info", "done", "cancel"),
    "done": ("checked", "returned"),
    "returned": ("work", "info", "done", "cancel"),
    "checked": (),
    "cancel": ("new",),
}
DEFAULT_CATEGORIES = ["Отчёты", "SIEM", "АСЗИ", "Astra Linux", "Windows", "ГосСопка"]


def allowed_next(cur):
    return [x for x in STATUS if x in TRANSITIONS.get(cur, ())]

SCHEMA = """
create table if not exists users(
  id integer primary key, login text unique not null, name text not null,
  pw text not null, is_admin integer not null default 0, active integer not null default 1);
create table if not exists sessions(
  token text primary key, user_id integer not null references users(id),
  csrf text not null, expires real not null);
create table if not exists categories(
  id integer primary key, name text unique not null, active integer not null default 1);
create table if not exists tasks(
  id integer primary key, title text not null, description text not null default '',
  priority integer not null default 1, due text, status text not null default 'new',
  assignee_id integer references users(id), author_id integer not null references users(id),
  created text not null, updated text not null, category_id integer references categories(id));
create table if not exists comments(
  id integer primary key, task_id integer not null references tasks(id) on delete cascade,
  user_id integer not null references users(id), body text not null, created text not null, status_change text);
create table if not exists attachments(
  id integer primary key, task_id integer not null references tasks(id) on delete cascade,
  comment_id integer references comments(id) on delete cascade,
  user_id integer not null references users(id), name text not null,
  stored text not null, size integer not null, created text not null);
create table if not exists history(
  id integer primary key, task_id integer not null references tasks(id) on delete cascade,
  user_id integer not null references users(id), text text not null, created text not null);
create table if not exists notifications(
  id integer primary key, user_id integer not null references users(id),
  task_id integer not null references tasks(id) on delete cascade,
  text text not null, created text not null, is_read integer not null default 0);
create index if not exists i_notif_user on notifications(user_id, is_read);
create index if not exists i_tasks_status on tasks(status);
create index if not exists i_comments_task on comments(task_id);
create index if not exists i_att_task on attachments(task_id);
create index if not exists i_hist_task on history(task_id);
"""


# ---------- утилиты ----------
def e(s):
    return html.escape("" if s is None else str(s), quote=True)


def now():
    return time.strftime("%Y-%m-%d %H:%M")


def today():
    return time.strftime("%Y-%m-%d")


def fd(s):
    """ГГГГ-ММ-ДД -> ДД.ММ.ГГГГ"""
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", s or "")
    return "%s.%s.%s" % (m.group(3), m.group(2), m.group(1)) if m else "—"


def fdt(s):
    """ГГГГ-ММ-ДД ЧЧ:ММ -> ДД.ММ.ГГГГ, ЧЧ:ММ"""
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2}) (\d{2}:\d{2})", s or "")
    return "%s.%s.%s, %s" % (m.group(3), m.group(2), m.group(1), m.group(4)) if m else "—"


def parse_date(s):
    s = (s or "").strip()
    if not s:
        return None
    try:
        return time.strftime("%Y-%m-%d", time.strptime(s, "%d.%m.%Y"))
    except ValueError:
        raise Http(400, "Срок указывается в формате ДД.ММ.ГГГГ, например 31.12.2026")


def fmt_size(n):
    for u in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024 or u == "ГБ":
            return ("%d %s" % (n, u)) if u == "Б" else ("%.1f %s" % (n, u))
        n /= 1024.0


def hash_pw(pw, salt=None, it=200000):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), it).hex()
    return "%d$%s$%s" % (it, salt, h)


def check_pw(pw, stored):
    try:
        it, salt, h = stored.split("$")
        return hmac.compare_digest(hash_pw(pw, salt, int(it)).split("$")[2], h)
    except Exception:
        return False


def db():
    c = sqlite3.connect(DB, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    # LIKE в SQLite не понимает регистр кириллицы, поэтому свой lower
    c.create_function("pylower", 1, lambda s: (s or "").lower())
    return c


def add_user(c, login, name, pw, is_admin=0):
    c.execute("insert into users(login,name,pw,is_admin) values(?,?,?,?)",
              (login, name, hash_pw(pw), is_admin))
    c.commit()


def init_db():
    os.makedirs(FILES, exist_ok=True)
    c = db()
    c.execute("PRAGMA journal_mode=WAL")
    had_cat = c.execute("select 1 from sqlite_master where name='categories'").fetchone()
    c.executescript(SCHEMA)
    if "status_change" not in [r["name"] for r in c.execute("pragma table_info(comments)")]:
        c.execute("alter table comments add column status_change text")   # миграция старой базы
        c.commit()
    if "category_id" not in [r["name"] for r in c.execute("pragma table_info(tasks)")]:
        c.execute("alter table tasks add column category_id integer references categories(id)")
        c.commit()
    ucols = [r["name"] for r in c.execute("pragma table_info(users)")]
    if "ui_theme" not in ucols:
        c.execute("alter table users add column ui_theme text not null default 'auto'")
    if "ui_view" not in ucols:
        c.execute("alter table users add column ui_view text not null default 'list'")
    c.commit()
    if not had_cat:
        c.executemany("insert into categories(name) values(?)", [(n,) for n in DEFAULT_CATEGORIES])
        c.commit()
    if c.execute("select 1 from tasks where status='review'").fetchone():   # статус «На проверке» упразднён
        c.execute("insert into history(task_id,user_id,text,created) select id, author_id, "
                  "'Статус «На проверке» упразднён, задача переведена в «Выполнена»', ? from tasks where status='review'",
                  (now(),))
        c.execute("update tasks set status='done' where status='review'")
        c.commit()
    old = time.strftime("%Y-%m-%d %H:%M", time.localtime(time.time() - 60 * 86400))
    c.execute("delete from notifications where is_read=1 and created<?", (old,))
    c.commit()
    if not c.execute("select 1 from users").fetchone():
        pw = secrets.token_urlsafe(9)
        add_user(c, "admin", "Администратор", pw, 1)
        print("=" * 50)
        print("Создан администратор: admin / %s" % pw)
        print("Запомните пароль и смените его после входа.")
        print("=" * 50)
    c.close()


def parse_multipart(ctype, body):
    raw = b"Content-Type: " + ctype.encode("latin-1", "replace") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    fields, files = {}, []
    if not msg.is_multipart():
        return fields, files
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        fname = part.get_filename()
        data = part.get_payload(decode=True) or b""
        if fname is not None:
            if fname and data:
                files.append((fname, data))
        elif name:
            fields[name] = data.decode("utf-8", "replace")
    return fields, files


class Http(Exception):
    def __init__(self, code, msg=""):
        self.code, self.msg = code, msg


FAILS = {}   # ip -> [время неудачных входов]


# ---------- оформление ----------
CSS = """
:root{--bg:#f6f7f8;--card:#fff;--col:#eceff2;--ink:#1f2933;--mute:#66727f;--line:#dde2e7;--acc:#1f6f8b;--acc-ink:#fff;
--bad:#b3261e;--warn:#a15c00;--ok:#2e7d32;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#161a1d;--card:#1f2428;--col:#262c31;--ink:#e6eaee;--mute:#92a0ad;
--line:#323a41;--acc:#5fb0cc;--acc-ink:#0d1a20;--bad:#ff8a80;--warn:#ffb74d;--ok:#81c784;color-scheme:dark}}
:root[data-theme="dark"]{--bg:#161a1d;--card:#1f2428;--col:#262c31;--ink:#e6eaee;--mute:#92a0ad;
--line:#323a41;--acc:#5fb0cc;--acc-ink:#0d1a20;--bad:#ff8a80;--warn:#ffb74d;--ok:#81c784;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.45 system-ui,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
header{display:flex;gap:18px;align-items:center;padding:10px 20px;background:var(--card);border-bottom:1px solid var(--line);flex-wrap:wrap}
header a{color:var(--ink);text-decoration:none;font-weight:600}header a:hover{color:var(--acc)}
.sp{flex:1}
main{max-width:1180px;margin:20px auto;padding:0 16px}
h1{font-size:1.4rem;margin:0 0 14px}h2{font-size:1.1rem;margin:22px 0 8px}
a{color:var(--acc)}
.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px 16px;margin-bottom:14px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line)}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.85rem;color:var(--mute);font-weight:600}
tr:last-child td{border-bottom:0}
.tbl{overflow-x:auto}
input,select,textarea,button{font:inherit;color:inherit}
input[type=text],input[type=password],input[type=date],input[type=search],select,textarea{
width:100%;padding:7px 9px;border:1px solid var(--line);border-radius:4px;background:var(--bg)}
textarea{min-height:110px;resize:vertical}
button,.btn{background:var(--acc);color:var(--acc-ink);border:0;border-radius:4px;padding:7px 14px;cursor:pointer;text-decoration:none;display:inline-block}
button.sec{background:transparent;color:var(--ink);border:1px solid var(--line)}
button.danger{background:var(--bad);color:var(--acc-ink)}
button.link{background:none;color:var(--ink);padding:0;font-weight:600}
:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
form.inline{display:inline}
label{display:block;font-size:.85rem;color:var(--mute);margin:10px 0 3px}
.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.filters{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:14px}
.filters>div{flex:1;min-width:130px}.filters label{margin-top:0}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;border:1px solid var(--line);font-size:.8rem;white-space:nowrap}
.p2{color:var(--warn);border-color:var(--warn)}.p3{color:var(--bad);border-color:var(--bad);font-weight:600}
.s-work{color:var(--acc);border-color:var(--acc)}.s-review{color:var(--warn);border-color:var(--warn)}
.s-done{color:var(--ok);border-color:var(--ok)}.s-cancel{color:var(--mute)}
.late{color:var(--bad);font-weight:600}.mute{color:var(--mute)}.small{font-size:.85rem}
.pre{white-space:pre-wrap;word-wrap:break-word}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:10px 0}
.meta b{display:block;font-size:.8rem;color:var(--mute);font-weight:600}
.cm{border-top:1px solid var(--line);padding:10px 0}.cm:first-child{border-top:0}
.flash{background:var(--card);border-left:4px solid var(--bad);padding:8px 12px;margin-bottom:14px}
.login{max-width:340px;margin:60px auto}
.s-info{color:var(--warn);border-color:var(--warn);font-weight:600}
.s-infook{color:var(--acc);border-color:var(--acc);font-weight:600}
.last{font-size:.85rem;color:var(--mute);margin-top:3px}
.hint{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--warn);padding:8px 12px;margin-bottom:14px}
.chg{margin:4px 0}
.s-checked{background:var(--ok);color:var(--acc-ink);border-color:var(--ok)}
.s-returned{color:var(--bad);border-color:var(--bad);font-weight:600}
.cat{color:var(--mute);font-size:.85rem}
.cnt{background:var(--bad);color:var(--acc-ink);border-radius:9px;padding:0 6px;font-size:.75rem;margin-left:5px}
.nt{padding:9px 12px;border-left:4px solid transparent;border-bottom:1px solid var(--line)}
.nt.new{border-left-color:var(--acc);background:var(--bg)}
.chatbox{padding:6px 16px}
.um{position:relative}.um summary{cursor:pointer;font-weight:600;list-style:none}
.um summary::-webkit-details-marker{display:none}
.menu{position:absolute;right:0;top:140%;z-index:30;background:var(--card);border:1px solid var(--line);
border-radius:6px;padding:10px 14px;min-width:270px;box-shadow:0 6px 20px rgba(0,0,0,.25)}
.menu a,.menu button.link{display:block;padding:6px 0;font-weight:500}
.menu form{margin:0}.mh{font-size:.8rem;color:var(--mute);margin:8px 0 4px}
.opts{display:flex;gap:4px;flex-wrap:wrap}
.opt{background:transparent;color:var(--ink);border:1px solid var(--line);padding:4px 10px}
.opt.on{background:var(--acc);color:var(--acc-ink);border-color:var(--acc)}
body.wide main{max-width:none}
.kb{display:flex;gap:12px;align-items:flex-start;overflow-x:auto;padding-bottom:10px}
.kcol{flex:0 0 270px;background:var(--col);border:1px solid var(--line);border-radius:6px;padding:8px}
.kh{font-weight:600;margin-bottom:8px;display:flex;gap:8px;align-items:center}
.cards{display:flex;flex-direction:column;gap:8px;max-height:calc(100vh - 260px);overflow-y:auto}
.kc{background:var(--card);border:1px solid var(--line);border-radius:5px;padding:8px 10px}
.kc a{font-weight:600;text-decoration:none;display:block;margin:2px 0}
.kp2{border-left:4px solid var(--warn)}.kp3{border-left:4px solid var(--bad)}
.mtop table{font-size:.85rem}.mtop th,.mtop td{padding:3px 8px;white-space:nowrap}
.mtop th{position:sticky;top:0;background:var(--card);z-index:1}
.mtop tr[data-frag]{cursor:pointer}.mtop tr.on td{background:var(--col)}
.mtop td.tt{max-width:460px;overflow:hidden;text-overflow:ellipsis}
.mtop td.tt a{text-decoration:none}.mtop .badge{font-size:.72rem;padding:0 6px}
.mtop .filters{margin:0;padding:8px 8px 6px}
.main2 textarea{min-height:70px}
@media (min-width:900px){
body.fit{height:100vh;height:100dvh;display:flex;flex-direction:column;overflow:hidden}
body.fit main{flex:1;min-height:0;width:100%;max-width:1500px;margin:14px auto;display:grid;
grid-template-columns:minmax(300px,380px) minmax(0,1fr);gap:16px}
.side{overflow-y:auto;min-height:0;padding-right:4px}
.main2{display:flex;flex-direction:column;min-height:0}
.main2 .chatbox{flex:1;min-height:0;display:flex}
body.mini{height:100vh;height:100dvh;display:flex;flex-direction:column;overflow:hidden}
body.mini main{flex:1;min-height:0;width:100%;max-width:none;margin:10px auto;display:flex;flex-direction:column;gap:10px}
.mtop{flex:none;height:38vh;min-height:110px;max-height:75vh;overflow:auto;resize:vertical;
background:var(--card);border:1px solid var(--line)}
.detail{flex:1;min-height:0;display:grid;grid-template-columns:minmax(300px,380px) minmax(0,1fr);gap:16px}
#chat{flex:1;min-height:0;overflow-y:auto}
}
.dt{display:flex;gap:6px;position:relative}.dt input[type=text]{flex:1;min-width:0}.dt button{padding:7px 10px}
.pick{position:absolute;right:0;bottom:0;opacity:0;width:1px;height:1px;border:0;padding:0;pointer-events:none}
"""

JS = """
function pickDate(b){var d=b.nextElementSibling;try{d.showPicker()}catch(x){d.focus()}}
function setDate(d){if(d.value){var p=d.value.split('-');d.previousElementSibling.previousElementSibling.value=p[2]+'.'+p[1]+'.'+p[0]}}
function setNb(n){var b=document.getElementById('nb');if(b){b.textContent=n;b.style.display=n>0?'':'none'}}
function pollNb(){fetch('/unread',{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(d){setNb(d.n)}).catch(function(){})}
if(document.getElementById('nb')){setInterval(pollNb,60000)}
document.addEventListener('click',function(ev){
var m=document.querySelector('details.um[open]');if(m&&!m.contains(ev.target)){m.removeAttribute('open')}
var tr=ev.target.closest?ev.target.closest('tr[data-frag]'):null;if(!tr||ev.ctrlKey||ev.metaKey||ev.shiftKey||ev.button){return}
var a=ev.target.closest('a');if(a&&!a.classList.contains('sel')){return}
var d=document.getElementById('detail');if(!d){return}
ev.preventDefault();
fetch(tr.dataset.frag,{credentials:'same-origin'}).then(function(r){return r.text()}).then(function(h){d.innerHTML=h;
var o=document.querySelector('tr.on');if(o){o.classList.remove('on')}tr.classList.add('on');
var c=document.getElementById('chat');if(c){c.scrollTop=c.scrollHeight}
history.replaceState(null,'',tr.dataset.href);pollNb()}).catch(function(){location.href=tr.dataset.href})});
var ch=document.getElementById('chat');if(ch){ch.scrollTop=ch.scrollHeight}
function chk(f){var s=f.status?f.status.value:'',r=f.dataset.req.split(',');
if(s&&r.indexOf(s)>=0&&!f.body.value.trim()){alert('Для выбранного статуса нужен комментарий.');f.body.focus();return false}return true}
"""


def layout(user, csrf, title, body, unread=0, cls="", cur="/"):
    nav = ""
    theme = ""
    if user:
        if user["ui_theme"] in ("light", "dark"):
            theme = ' data-theme="%s"' % user["ui_theme"]
        nav = ('<a href="/">Задачи</a><a href="/task/new">Новая задача</a>'
               '<a href="/notifications">Уведомления<span class="cnt" id="nb"%s>%d</span></a>'
               % ("" if unread else ' style="display:none"', unread))
        if user["is_admin"]:
            nav += '<a href="/users">Пользователи</a><a href="/categories">Категории</a>'
        nav += '<span class="sp"></span>' + user_menu(user, csrf, cur)
    return ('<!doctype html><html lang="ru"%s><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>%s — Задачи</title><style>%s</style></head><body class="%s"><header>%s</header>'
            '<main>%s</main><script>%s</script></body></html>'
            % (theme, e(title), CSS, cls, nav, body, JS))


def opts(pairs, selected):
    return "".join('<option value="%s"%s>%s</option>' % (e(k), " selected" if str(k) == str(selected) else "", e(v))
                   for k, v in pairs)


def badge_prio(p):
    return '<span class="badge p%d">%s</span>' % (p, PRIO.get(p, "?"))


def badge_status(s):
    return '<span class="badge s-%s">%s</span>' % (e(s), STATUS.get(s) or LEGACY.get(s, s))


def safe_back(b):
    """Разрешаем возврат только на внутренний адрес."""
    b = b or ""
    if b.startswith("/") and not b.startswith("//") and b.isascii() and all(ord(ch) >= 32 for ch in b):
        return b
    return ""


def back_hidden(b):
    b = safe_back(b)
    return '<input type="hidden" name="back" value="%s">' % e(b) if b else ""


def user_menu(user, csrf, cur):
    th, vw = user["ui_theme"], user["ui_view"]

    def grp(name, now_val, items):
        return "".join('<button name="%s" value="%s" class="opt%s">%s</button>'
                       % (name, k, " on" if k == now_val else "", v) for k, v in items)
    return ('<details class="um"><summary>%s ▾</summary><div class="menu">'
            '<form method="post" action="/settings">%s%s<div class="mh">Тема</div><div class="opts">%s</div>'
            '<div class="mh">Вид списка задач</div><div class="opts">%s</div></form>'
            '<hr style="border:0;border-top:1px solid var(--line);margin:8px 0">'
            '<a href="/password">Сменить пароль</a>'
            '<form method="post" action="/logout">%s<button class="link">Выйти</button></form></div></details>'
            % (e(user["name"]), csrf_field(csrf), back_hidden(cur),
               grp("theme", th, [("auto", "Как в системе"), ("light", "Светлая"), ("dark", "Тёмная")]),
               grp("view", vw, [("list", "Список"), ("kanban", "Канбан"), ("mini", "Компактный")]),
               csrf_field(csrf)))


def csrf_field(csrf):
    return '<input type="hidden" name="csrf" value="%s">' % e(csrf)


# ---------- обработчик ----------
class H(BaseHTTPRequestHandler):
    server_version = "TaskTracker/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.log_date_time_string(), fmt % args))

    # --- ответы ---
    def send(self, code, body, ctype="text/html; charset=utf-8", headers=()):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def unread(self):
        if not self.user:
            return 0
        try:
            return self.db.execute("select count(*) from notifications where user_id=? and is_read=0",
                                   (self.user["id"],)).fetchone()[0]
        except Exception:
            return 0

    def cur_url(self):
        return safe_back(self.path) or "/"

    def redirect_back(self, default):
        self.redirect(safe_back(self.fields.get("back", "")) or default)

    def page(self, title, body, code=200, headers=(), cls=""):
        self.send(code, layout(self.user, self.csrf, title, body, self.unread(), cls, self.cur_url()), headers=headers)

    def redirect(self, url, headers=()):
        self.send(303, b"", headers=[("Location", url)] + list(headers))

    # --- разбор запроса ---
    def read_form(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_UPLOAD:
            raise Http(413, "Слишком большой объём данных (максимум %s)" % fmt_size(MAX_UPLOAD))
        body = self.rfile.read(n)
        ct = self.headers.get("Content-Type", "")
        if ct.startswith("multipart/form-data"):
            return parse_multipart(ct, body)
        return dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True)), []

    def session_user(self):
        self.csrf = ""
        c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        if "sid" in c:
            r = self.db.execute(
                "select u.*, s.csrf from sessions s join users u on u.id=s.user_id "
                "where s.token=? and s.expires>? and u.active=1", (c["sid"].value, time.time())).fetchone()
            if r:
                self.csrf = r["csrf"]
                return r
        return None

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def route(self, method):
        self.db = db()
        self.user = None
        self.csrf = ""
        try:
            u = urlparse(self.path)
            path, self.q = u.path, parse_qs(u.query)
            self.user = self.session_user()
            self.fields, self.files = {}, []
            if method == "POST":
                self.fields, self.files = self.read_form()
            if path == "/login":
                return self.login(method)
            if not self.user:
                return self.redirect("/login")
            if method == "POST" and not hmac.compare_digest(self.fields.get("csrf", ""), self.csrf):
                raise Http(403, "Форма устарела. Обновите страницу и повторите.")
            self.dispatch(method, path)
        except Http as ex:
            self.page("Ошибка", '<div class="flash">%s</div><p><a href="/">На главную</a></p>' % e(ex.msg), ex.code)
        except Exception:
            traceback.print_exc()
            try:
                self.page("Ошибка", '<div class="flash">Внутренняя ошибка сервера.</div>', 500)
            except Exception:
                pass
        finally:
            self.db.close()

    def dispatch(self, method, path):
        m = None
        if method == "GET":
            if path == "/":
                return self.p_index()
            if path == "/task/new":
                return self.p_task_new()
            m = re.fullmatch(r"/task/(\d+)", path)
            if m:
                return self.p_task(int(m.group(1)))
            m = re.fullmatch(r"/file/(\d+)", path)
            if m:
                return self.p_file(int(m.group(1)))
            if path == "/users":
                return self.p_users()
            if path == "/password":
                return self.p_password()
            if path == "/notifications":
                return self.p_notifications()
            if path == "/unread":
                return self.send(200, json.dumps({"n": self.unread()}), "application/json")
            if path == "/categories":
                return self.p_categories()
        else:
            if path == "/logout":
                self.db.execute("delete from sessions where csrf=?", (self.csrf,))
                self.db.commit()
                return self.redirect("/login", [("Set-Cookie", "sid=; Path=/; Max-Age=0")])
            if path == "/task/new":
                return self.a_task_new()
            m = re.fullmatch(r"/task/(\d+)/(edit|comment|delete)", path)
            if m:
                return getattr(self, "a_task_" + m.group(2))(int(m.group(1)))
            if path == "/users/add":
                return self.a_user_add()
            m = re.fullmatch(r"/users/(\d+)/(reset|toggle|admin)", path)
            if m:
                return getattr(self, "a_user_" + m.group(2))(int(m.group(1)))
            if path == "/password":
                return self.a_password()
            if path == "/settings":
                return self.a_settings()
            if path == "/notifications/read":
                return self.a_notif_read()
            if path == "/categories/add":
                return self.a_cat_add()
            m = re.fullmatch(r"/categories/(\d+)/(rename|toggle)", path)
            if m:
                return getattr(self, "a_cat_" + m.group(2))(int(m.group(1)))
        raise Http(404, "Страница не найдена")

    # --- вход ---
    def login(self, method):
        err = ""
        ip = self.client_address[0]
        if method == "POST":
            recent = [t for t in FAILS.get(ip, []) if t > time.time() - 300]
            FAILS[ip] = recent
            if len(recent) >= 8:
                err = "Слишком много неудачных попыток. Подождите 5 минут."
            else:
                r = self.db.execute("select * from users where login=? and active=1",
                                    (self.fields.get("login", "").strip(),)).fetchone()
                if r and check_pw(self.fields.get("password", ""), r["pw"]):
                    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(16)
                    self.db.execute("delete from sessions where expires<?", (time.time(),))
                    self.db.execute("insert into sessions values(?,?,?,?)",
                                    (token, r["id"], csrf, time.time() + SESSION_SECONDS))
                    self.db.commit()
                    return self.redirect("/", [("Set-Cookie", "sid=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d"
                                                % (token, SESSION_SECONDS))])
                FAILS.setdefault(ip, []).append(time.time())
                err = "Неверный логин или пароль."
        body = ('<div class="card login"><h1>Вход</h1>%s<form method="post">'
                '<label>Логин</label><input type="text" name="login" autofocus required>'
                '<label>Пароль</label><input type="password" name="password" required>'
                '<p><button>Войти</button></p></form></div>'
                % ('<div class="flash">%s</div>' % e(err) if err else ""))
        self.page("Вход", body)

    # --- список задач ---
    def row_info(self, t, td):
        late = bool(t["due"] and t["due"] < td and t["status"] in WORKING)
        me = self.user["id"]
        mark = ""
        if t["status"] == "info" and t["author_id"] == me:
            mark = ' <span class="badge s-info">ждёт вашего ответа</span>'
        elif t["status"] == "infook" and t["assignee_id"] == me:
            mark = ' <span class="badge s-infook">ответ получен</span>'
        elif t["status"] == "done" and t["author_id"] == me:
            mark = ' <span class="badge s-info">ждёт вашей проверки</span>'
        elif t["status"] == "returned" and t["assignee_id"] == me:
            mark = ' <span class="badge s-returned">возвращена вам</span>'
        tip = ""
        d = "\n".join(l.strip() for l in (t["description"] or "").splitlines() if l.strip())
        if d:
            tip = ' title="%s"' % e(d[:600] + ("…" if len(d) > 600 else ""))
        return late, mark, tip

    def p_index(self):
        g = lambda k, d="": self.q.get(k, [d])[0]
        st, asg, pr, text = g("status", "active"), g("assignee", "all"), g("priority"), g("q").strip()
        cat = g("category")
        where, args = [], []
        if st == "active":
            where.append("t.status in (%s)" % ",".join("'%s'" % x for x in ACTIVE))
        elif st in STATUS:
            where.append("t.status=?")
            args.append(st)
        if asg == "me":
            where.append("t.assignee_id=?")
            args.append(self.user["id"])
        elif asg == "none":
            where.append("t.assignee_id is null")
        elif asg.isdigit():
            where.append("t.assignee_id=?")
            args.append(int(asg))
        if pr.isdigit():
            where.append("t.priority=?")
            args.append(int(pr))
        if cat.isdigit():
            where.append("t.category_id=?")
            args.append(int(cat))
        elif cat == "none":
            where.append("t.category_id is null")
        if text:
            where.append("(instr(pylower(t.title),?)>0 or instr(pylower(t.description),?)>0)")
            args += [text.lower(), text.lower()]
        sql = ("select t.*, a.name as aname, (select count(*) from comments c where c.task_id=t.id) as ncom, "
               "lc.body as lbody, lc.created as lcreated, lu.name as lname, cg.name as cname "
               "from tasks t left join users a on a.id=t.assignee_id "
               "left join comments lc on lc.id=(select max(id) from comments where task_id=t.id) "
               "left join users lu on lu.id=lc.user_id left join categories cg on cg.id=t.category_id %s "
               "order by (t.status in ('checked','cancel')), t.priority desc, t.due is null, t.due, t.id desc limit 500"
               % ("where " + " and ".join(where) if where else ""))
        rows = self.db.execute(sql, args).fetchall()
        users = self.db.execute("select id,name from users where active=1 order by name").fetchall()
        cats = self.db.execute("select id,name from categories order by name").fetchall()
        fl = ('<form class="filters" method="get">'
              '<div><label>Поиск</label><input type="search" name="q" value="%s"></div>'
              '<div><label>Статус</label><select name="status">%s</select></div>'
              '<div><label>Исполнитель</label><select name="assignee">%s</select></div>'
              '<div><label>Приоритет</label><select name="priority">%s</select></div>'
              '<div><label>Категория</label><select name="category">%s</select></div>'
              '<div><button>Показать</button></div></form>'
              % (e(text),
                 opts([("active", "Активные"), ("all", "Все")] + list(STATUS.items()), st),
                 opts([("all", "Все"), ("me", "Мои"), ("none", "Не назначен")] + [(u["id"], u["name"]) for u in users], asg),
                 opts([("", "Любой")] + list(PRIO.items()), pr),
                 opts([("", "Любая"), ("none", "Без категории")] + [(c["id"], c["name"]) for c in cats], cat)))
        view = self.user["ui_view"]
        if view == "kanban":
            return self.v_kanban(rows, fl, st)
        if view == "mini":
            return self.v_mini(rows, fl)
        return self.v_list(rows, fl)

    def v_list(self, rows, fl):
        td = today()
        trs = ""
        for t in rows:
            late, mark, tip = self.row_info(t, td)
            last = ""
            if t["lcreated"]:
                txt = " ".join((t["lbody"] or "").split())
                if len(txt) > 140:
                    txt = txt[:140].rstrip() + "…"
                last = ('<div class="last"><b>%s</b>, %s: %s</div>'
                        % (e(t["lname"]), fdt(t["lcreated"]), e(txt or "(без текста)")))
            trs += ('<tr><td class="mute">%d</td><td><a href="/task/%d"%s>%s</a>%s%s%s</td><td class="cat">%s</td>'
                    '<td>%s</td><td>%s</td><td>%s</td><td class="%s">%s</td></tr>'
                    % (t["id"], t["id"], tip, e(t["title"]),
                       (' <span class="mute small">(%d)</span>' % t["ncom"]) if t["ncom"] else "", mark, last,
                       e(t["cname"] or ""),
                       badge_prio(t["priority"]), badge_status(t["status"]), e(t["aname"] or "—"),
                       "late" if late else "", fd(t["due"])))
        if not trs:
            trs = '<tr><td colspan="7" class="mute">Задач не найдено.</td></tr>'
        self.page("Задачи", '<h1>Задачи</h1>%s<div class="tbl"><table><tr><th>№</th><th>Задача</th><th>Категория</th>'
                  '<th>Приоритет</th><th>Статус</th><th>Исполнитель</th><th>Срок</th></tr>%s</table></div>' % (fl, trs))

    def v_kanban(self, rows, fl, st):
        td = today()
        cols = list(STATUS) if st == "all" else ([st] if st in STATUS else list(ACTIVE))
        out = ""
        for col in cols:
            cards, n = "", 0
            for t in rows:
                if t["status"] != col:
                    continue
                n += 1
                late, mark, tip = self.row_info(t, td)
                cards += ('<div class="kc kp%d"><div class="small mute">#%d%s</div><a href="/task/%d"%s>%s</a>%s'
                          '<div class="small">%s %s</div><div class="small %s">%s%s</div></div>'
                          % (t["priority"], t["id"], (" · " + e(t["cname"])) if t["cname"] else "",
                             t["id"], tip, e(t["title"]), mark,
                             badge_prio(t["priority"]), e(t["aname"] or "не назначен"),
                             "late" if late else "mute", ("срок " + fd(t["due"])) if t["due"] else "без срока",
                             (" · 💬 %d" % t["ncom"]) if t["ncom"] else ""))
            out += ('<div class="kcol"><div class="kh">%s <span class="mute">%d</span></div><div class="cards">%s</div></div>'
                    % (badge_status(col), n, cards or '<div class="mute small">—</div>'))
        self.page("Задачи", '<h1>Задачи</h1>%s<div class="kb">%s</div>' % (fl, out), cls="wide")

    def v_mini(self, rows, fl):
        td = today()
        sel = self.q.get("sel", [""])[0]
        sel = int(sel) if sel.isdigit() else 0
        keep = [(k, self.q[k][0]) for k in ("status", "assignee", "priority", "category", "q")
                if self.q.get(k) and self.q[k][0]]
        trs = ""
        for t in rows:
            late, mark, tip = self.row_info(t, td)
            href = "/?" + urlencode(keep + [("sel", t["id"])])
            frag = "/task/%d?frag=1&back=%s" % (t["id"], quote(href, safe=""))
            trs += ('<tr data-frag="%s" data-href="%s"%s><td class="mute">%d</td><td class="tt"><a class="sel" href="%s"%s>%s</a>%s</td>'
                    '<td class="cat">%s</td><td>%s</td><td>%s</td><td>%s</td><td class="%s">%s</td><td class="mute">%s</td>'
                    '<td class="mute">%s</td></tr>'
                    % (e(frag), e(href), ' class="on"' if t["id"] == sel else "", t["id"], e(href), tip, e(t["title"]), mark,
                       e(t["cname"] or ""), badge_prio(t["priority"]), badge_status(t["status"]), e(t["aname"] or "—"),
                       "late" if late else "", fd(t["due"]), fdt(t["updated"]), t["ncom"] or ""))
        if not trs:
            trs = '<tr><td colspan="9" class="mute">Задач не найдено.</td></tr>'
        detail = '<div class="card mute" style="margin:0">Выберите задачу в таблице.</div>'
        if sel:
            try:
                _, side, main = self.task_panes(sel, self.cur_url())
                detail = side + main
            except Http:
                pass
        top = ('<div class="mtop">%s<table><tr><th>№</th><th>Задача</th><th>Категория</th><th>Приоритет</th><th>Статус</th>'
               '<th>Исполнитель</th><th>Срок</th><th>Изменена</th><th>💬</th></tr>%s</table></div>' % (fl, trs))
        self.page("Задачи", top + '<div class="detail" id="detail">%s</div>' % detail, cls="mini")

    # --- форма задачи ---
    def task_form(self, action, t, with_files, back=""):
        users = self.db.execute("select id,name from users where active=1 order by name").fetchall()
        cur = t["assignee_id"] if t else ""
        cats = self.db.execute("select id,name,active from categories order by name").fetchall()
        curc = (t["category_id"] if t else None) or ""
        copts = opts([("", "— без категории —")] + [(c["id"], c["name"]) for c in cats
                                                   if c["active"] or c["id"] == curc], curc)
        enc = ' enctype="multipart/form-data"' if with_files else ""
        files = ('<label>Файлы</label><input type="file" name="file" multiple>' if with_files else "")
        return ('<form method="post" action="%s"%s>%s<label>Название</label>'
                '<input type="text" name="title" value="%s" required maxlength="200">'
                '<label>Описание</label><textarea name="description">%s</textarea>'
                '<div class="row"><div><label>Приоритет</label><select name="priority">%s</select></div>'
                '<div><label>Срок</label><div class="dt"><input type="text" name="due" value="%s" placeholder="ДД.ММ.ГГГГ" '
                'pattern="\\d{2}\\.\\d{2}\\.\\d{4}" title="ДД.ММ.ГГГГ" inputmode="numeric" maxlength="10">'
                '<button type="button" class="sec" title="Выбрать дату" onclick="pickDate(this)">📅</button>'
                '<input type="date" class="pick" tabindex="-1" onchange="setDate(this)"></div></div>'
                '<div><label>Исполнитель</label><select name="assignee">%s</select></div>'
                '<div><label>Категория</label><select name="category">%s</select></div></div>%s'
                '<p><button>Сохранить</button></p></form>'
                % (action, enc, csrf_field(self.csrf) + back_hidden(back), e(t["title"] if t else ""),
                   e(t["description"] if t else ""),
                   opts(PRIO.items(), t["priority"] if t else 1), e(fd(t["due"]) if t and t["due"] else ""),
                   opts([("", "— не назначен —")] + [(u["id"], u["name"]) for u in users], cur), copts, files))

    def read_task_fields(self):
        f = self.fields
        title = f.get("title", "").strip()
        if not title:
            raise Http(400, "Укажите название задачи")
        pr = int(f["priority"]) if f.get("priority", "").isdigit() and int(f["priority"]) in PRIO else 1
        due = parse_date(f.get("due", ""))
        asg = int(f["assignee"]) if f.get("assignee", "").isdigit() else None
        if asg and not self.db.execute("select 1 from users where id=? and active=1", (asg,)).fetchone():
            asg = None
        cat = int(f["category"]) if f.get("category", "").isdigit() else None
        if cat and not self.db.execute("select 1 from categories where id=?", (cat,)).fetchone():
            cat = None
        return title[:200], f.get("description", "").strip(), pr, due or None, asg, cat

    def hist(self, tid, text):
        self.db.execute("insert into history(task_id,user_id,text,created) values(?,?,?,?)",
                        (tid, self.user["id"], text, now()))

    def notify(self, tid, text, user_ids):
        for uid in set(u for u in user_ids if u and u != self.user["id"]):
            self.db.execute("insert into notifications(user_id,task_id,text,created) values(?,?,?,?)",
                            (uid, tid, text, now()))

    def participants(self, t):
        ids = {t["author_id"], t["assignee_id"]}
        ids |= {r[0] for r in self.db.execute("select distinct user_id from comments where task_id=?", (t["id"],))}
        return list(ids)

    def touch(self, tid):
        self.db.execute("update tasks set updated=? where id=?", (now(), tid))

    def save_files(self, tid, cid):
        names = []
        for name, data in self.files:
            name = os.path.basename(name.replace("\\", "/"))[:200] or "file"
            stored = secrets.token_hex(16)
            with open(os.path.join(FILES, stored), "wb") as fh:
                fh.write(data)
            self.db.execute("insert into attachments(task_id,comment_id,user_id,name,stored,size,created) "
                            "values(?,?,?,?,?,?,?)", (tid, cid, self.user["id"], name, stored, len(data), now()))
            names.append(name)
        if names:
            self.hist(tid, "Добавлены файлы: " + ", ".join(names))

    def p_task_new(self):
        self.page("Новая задача", "<h1>Новая задача</h1><div class='card'>%s</div>"
                  % self.task_form("/task/new", None, True))

    def a_task_new(self):
        title, desc, pr, due, asg, cat = self.read_task_fields()
        cur = self.db.execute("insert into tasks(title,description,priority,due,assignee_id,author_id,created,updated,category_id) "
                              "values(?,?,?,?,?,?,?,?,?)",
                              (title, desc, pr, due, asg, self.user["id"], now(), now(), cat))
        tid = cur.lastrowid
        self.hist(tid, "Задача создана")
        self.save_files(tid, None)
        self.notify(tid, "Вам назначена задача. Назначил: %s." % self.user["name"], [asg])
        self.db.commit()
        self.redirect("/task/%d" % tid)

    # --- карточка задачи ---
    def get_task(self, tid):
        t = self.db.execute("select t.*, a.name as aname, u.name as uname, cg.name as cname from tasks t "
                            "left join users a on a.id=t.assignee_id join users u on u.id=t.author_id "
                            "left join categories cg on cg.id=t.category_id "
                            "where t.id=?", (tid,)).fetchone()
        if not t:
            raise Http(404, "Задача не найдена")
        return t

    def att_links(self, rows):
        return "".join('<div class="small">📎 <a href="/file/%d">%s</a> <span class="mute">(%s, %s)</span></div>'
                       % (a["id"], e(a["name"]), fmt_size(a["size"]), e(a["uname"])) for a in rows)

    def p_task(self, tid):
        back = safe_back(self.q.get("back", [""])[0]) or "/task/%d" % tid
        title, side, main = self.task_panes(tid, back)
        if self.q.get("frag"):
            return self.send(200, side + main)
        self.page(title, side + main, cls="fit")

    def task_panes(self, tid, back):
        t = self.get_task(tid)
        me = self.user["id"]
        self.db.execute("update notifications set is_read=1 where user_id=? and task_id=? and is_read=0", (me, tid))
        self.db.commit()
        atts = self.db.execute("select a.*, u.name as uname from attachments a join users u on u.id=a.user_id "
                               "where a.task_id=? order by a.id", (tid,)).fetchall()
        comments = self.db.execute("select c.*, u.name as uname from comments c join users u on u.id=c.user_id "
                                   "where c.task_id=? order by c.id", (tid,)).fetchall()
        hist = self.db.execute("select h.*, u.name as uname from history h join users u on u.id=h.user_id "
                               "where h.task_id=? order by h.id desc", (tid,)).fetchall()
        late = t["due"] and t["due"] < today() and t["status"] in WORKING
        task_atts = self.att_links([a for a in atts if a["comment_id"] is None])
        cm = ""
        for c in comments:
            chg = ""
            if c["status_change"]:
                old, new = c["status_change"].split(">")
                chg = '<div class="chg">Статус: %s → %s</div>' % (badge_status(old), badge_status(new))
            text = ('<div class="pre">%s</div>' % e(c["body"])) if c["body"] else ""
            cm += ('<div class="cm"><div class="small"><b>%s</b> <span class="mute">%s</span></div>%s%s%s</div>'
                   % (e(c["uname"]), fdt(c["created"]), chg, text,
                      self.att_links([a for a in atts if a["comment_id"] == c["id"]])))
        if not cm:
            cm = '<p class="mute">Обсуждения пока нет.</p>'
        hs = "".join('<div class="small"><span class="mute">%s</span> %s: %s</div>'
                     % (fdt(h["created"]), e(h["uname"]), e(h["text"])) for h in hist)
        hint = ""
        if t["status"] == "info" and t["author_id"] == me:
            hint = ('Исполнитель запросил информацию. Ответьте комментарием; чтобы вернуть '
                    'задачу в работу, выберите статус «Информация предоставлена».')
        elif t["status"] == "infook" and t["assignee_id"] == me:
            hint = 'Автор предоставил информацию. Можно продолжать: выберите статус «В работе».'
        elif t["status"] == "done" and t["author_id"] == me:
            hint = 'Задача выполнена. Проверьте результат: выберите «Проверено» или «Возвращено» (с комментарием).'
        elif t["status"] == "returned" and t["assignee_id"] == me:
            hint = 'Задача возвращена на доработку. Причина указана в последнем комментарии.'
        hint = ('<div class="hint">%s</div>' % hint) if hint else ""
        delete = ""
        if self.user["is_admin"]:
            delete = ('<form class="inline" method="post" action="/task/%d/delete" '
                      'onsubmit="return confirm(\'Удалить задачу вместе с обсуждением и файлами?\')">%s'
                      '<button class="danger">Удалить задачу</button></form>' % (tid, csrf_field(self.csrf)))
        card = ('<div class="card"><div>%s %s</div><div class="meta">'
                '<div><b>Исполнитель</b>%s</div><div><b>Срок</b><span class="%s">%s</span></div>'
                '<div><b>Автор</b>%s</div><div><b>Категория</b>%s</div>'
                '<div><b>Создана</b>%s</div><div><b>Изменена</b>%s</div></div>'
                '<div class="pre">%s</div>%s</div>'
                % (badge_prio(t["priority"]), badge_status(t["status"]),
                   e(t["aname"] or "не назначен"), "late" if late else "", fd(t["due"]),
                   e(t["uname"]), e(t["cname"] or "—"), fdt(t["created"]), fdt(t["updated"]),
                   e(t["description"]) or '<span class="mute">Без описания</span>',
                   ('<h2>Файлы</h2>' + task_atts) if task_atts else ""))
        side = ('<div class="side"><h1>#%d %s</h1>%s'
                '<details class="card"><summary>Редактировать задачу</summary>%s</details>'
                '<details class="card"><summary>История изменений</summary>%s</details><p>%s</p></div>'
                % (tid, e(t["title"]), card, self.task_form("/task/%d/edit" % tid, t, False, back), hs, delete))
        nxt = allowed_next(t["status"])
        status_row = ""
        if nxt:
            status_row = ('<div><label>Статус</label><select name="status"><option value="">Без смены (%s)</option>%s'
                          '</select></div>' % (e(STATUS[t["status"]]), opts([(k, STATUS[k]) for k in nxt], "")))
        form = ('<div class="card"><form method="post" action="/task/%d/comment" enctype="multipart/form-data" '
                'data-req="%s" onsubmit="return chk(this)">%s'
                '<textarea name="body" placeholder="Комментарий"></textarea>'
                '<div class="row">%s<div><label>Файлы</label><input type="file" name="file" multiple></div></div>'
                '<p style="margin:10px 0 0"><button>Отправить</button></p></form></div>'
                % (tid, ",".join(COMMENT_REQUIRED), csrf_field(self.csrf) + back_hidden(back), status_row))
        main = ('<div class="main2">%s<div class="card chatbox"><div id="chat">%s</div></div>%s</div>'
                % (hint, cm, form))
        return "#%d %s" % (tid, t["title"]), side, main

    def a_task_edit(self, tid):
        t = self.get_task(tid)
        title, desc, pr, due, asg, cat = self.read_task_fields()
        ch = []
        if title != t["title"]:
            ch.append("название")
        if desc != t["description"]:
            ch.append("описание")
        if pr != t["priority"]:
            ch.append("приоритет: %s → %s" % (PRIO[t["priority"]], PRIO[pr]))
        if due != t["due"]:
            ch.append("срок: %s → %s" % (fd(t["due"]), fd(due)))
        if cat != t["category_id"]:
            names = dict((r["id"], r["name"]) for r in self.db.execute("select id,name from categories"))
            ch.append("категория: %s → %s" % (names.get(t["category_id"], "—"), names.get(cat, "—")))
        if asg != t["assignee_id"]:
            nm = self.db.execute("select name from users where id=?", (asg,)).fetchone()
            ch.append("исполнитель: %s → %s" % (t["aname"] or "—", nm["name"] if nm else "—"))
        if ch:
            self.db.execute("update tasks set title=?,description=?,priority=?,due=?,assignee_id=?,category_id=? where id=?",
                            (title, desc, pr, due, asg, cat, tid))
            self.hist(tid, "Изменено: " + "; ".join(ch))
            self.touch(tid)
            who = self.user["name"]
            changed_asg = asg != t["assignee_id"]
            if changed_asg:
                self.notify(tid, "Вам назначена задача. Назначил: %s." % who, [asg])
                self.notify(tid, "Задача снята с вас. Изменил: %s." % who, [t["assignee_id"]])
            rest = [c for c in ch if not c.startswith("исполнитель")]
            if rest:
                self.notify(tid, "Изменено (%s): %s" % (who, "; ".join(rest)),
                            [t["author_id"]] + ([] if changed_asg else [asg]))
            self.db.commit()
        self.redirect_back("/task/%d" % tid)

    def a_task_comment(self, tid):
        t = self.get_task(tid)
        body = self.fields.get("body", "").strip()
        new = self.fields.get("status", "")
        if new and new not in STATUS:
            raise Http(400, "Неизвестный статус")
        if new == t["status"]:
            new = ""
        if new and new not in allowed_next(t["status"]):
            raise Http(400, "Из статуса «%s» нельзя перейти в «%s»." % (STATUS[t["status"]], STATUS[new]))
        if new in COMMENT_REQUIRED and not body:
            raise Http(400, "Для статуса «%s» нужен комментарий: напишите, что сделано или почему." % STATUS[new])
        if not body and not self.files and not new:
            raise Http(400, "Напишите комментарий, приложите файл или смените статус")
        cid = self.db.execute("insert into comments(task_id,user_id,body,created,status_change) values(?,?,?,?,?)",
                              (tid, self.user["id"], body, now(), ("%s>%s" % (t["status"], new)) if new else None)).lastrowid
        if new:
            self.db.execute("update tasks set status=? where id=?", (new, tid))
            self.hist(tid, "Статус: %s → %s" % (STATUS[t["status"]], STATUS[new]))
        self.save_files(tid, cid)
        self.touch(tid)
        head = ("%s: статус «%s»" % (self.user["name"], STATUS[new])) if new else ("%s: комментарий" % self.user["name"])
        prev = " ".join(body.split())
        if prev:
            head += " — " + (prev[:100] + "…" if len(prev) > 100 else prev)
        self.notify(tid, head, self.participants(t))
        self.db.commit()
        self.redirect_back("/task/%d" % tid)

    def a_task_delete(self, tid):
        if not self.user["is_admin"]:
            raise Http(403, "Удалять задачи может только администратор")
        stored = [r["stored"] for r in self.db.execute("select stored from attachments where task_id=?", (tid,))]
        self.db.execute("delete from tasks where id=?", (tid,))
        self.db.commit()
        for s in stored:
            try:
                os.remove(os.path.join(FILES, s))
            except OSError:
                pass
        self.redirect("/")

    def p_file(self, aid):
        a = self.db.execute("select * from attachments where id=?", (aid,)).fetchone()
        path = os.path.join(FILES, a["stored"]) if a else ""
        if not a or not os.path.isfile(path):
            raise Http(404, "Файл не найден")
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(os.path.getsize(path)))
        self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + quote(a["name"]))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)

    # --- пользователи (админ) ---
    def need_admin(self):
        if not self.user["is_admin"]:
            raise Http(403, "Доступно только администратору")

    def p_users(self):
        self.need_admin()
        rows = ""
        for u in self.db.execute("select * from users order by active desc, name"):
            me = u["id"] == self.user["id"]
            acts = ""
            if not me:
                acts += ('<form class="inline" method="post" action="/users/%d/toggle">%s<button class="sec">%s</button></form> '
                         '<form class="inline" method="post" action="/users/%d/admin">%s<button class="sec">%s</button></form> '
                         % (u["id"], csrf_field(self.csrf), "Отключить" if u["active"] else "Включить",
                            u["id"], csrf_field(self.csrf), "Снять права админа" if u["is_admin"] else "Сделать админом"))
            acts += ('<form class="inline" method="post" action="/users/%d/reset">%s'
                     '<input type="text" name="password" placeholder="новый пароль" required minlength="6" style="width:140px"> '
                     '<button class="sec">Сменить пароль</button></form>' % (u["id"], csrf_field(self.csrf)))
            rows += ('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'
                     % (e(u["login"]), e(u["name"]), "админ" if u["is_admin"] else "", "" if u["active"] else "отключён", acts))
        body = ('<h1>Пользователи</h1><div class="tbl"><table><tr><th>Логин</th><th>Имя</th><th>Роль</th><th></th><th>Действия</th></tr>%s</table></div>'
                '<h2>Добавить пользователя</h2><div class="card"><form method="post" action="/users/add"><div class="row">%s'
                '<div><label>Логин</label><input type="text" name="login" required></div>'
                '<div><label>Имя</label><input type="text" name="name" required></div>'
                '<div><label>Пароль (от 6 символов)</label><input type="text" name="password" required minlength="6"></div></div>'
                '<label><input type="checkbox" name="is_admin" value="1"> Администратор</label>'
                '<p><button>Добавить</button></p></form></div>' % (rows, csrf_field(self.csrf)))
        self.page("Пользователи", body)

    def a_user_add(self):
        self.need_admin()
        login, name, pw = (self.fields.get(k, "").strip() for k in ("login", "name", "password"))
        if not login or not name or len(pw) < 6:
            raise Http(400, "Заполните логин, имя и пароль (не короче 6 символов)")
        try:
            add_user(self.db, login, name, pw, 1 if self.fields.get("is_admin") else 0)
        except sqlite3.IntegrityError:
            raise Http(400, "Такой логин уже существует")
        self.redirect("/users")

    def a_user_reset(self, uid):
        self.need_admin()
        pw = self.fields.get("password", "")
        if len(pw) < 6:
            raise Http(400, "Пароль не короче 6 символов")
        self.db.execute("update users set pw=? where id=?", (hash_pw(pw), uid))
        self.db.execute("delete from sessions where user_id=?", (uid,))
        self.db.commit()
        self.redirect("/users")

    def a_user_toggle(self, uid):
        self.need_admin()
        if uid != self.user["id"]:
            self.db.execute("update users set active=1-active where id=?", (uid,))
            self.db.execute("delete from sessions where user_id=?", (uid,))
            self.db.commit()
        self.redirect("/users")

    def a_user_admin(self, uid):
        self.need_admin()
        if uid != self.user["id"]:
            self.db.execute("update users set is_admin=1-is_admin where id=?", (uid,))
            self.db.commit()
        self.redirect("/users")

    def a_settings(self):
        th, vw = self.fields.get("theme"), self.fields.get("view")
        if th in ("auto", "light", "dark"):
            self.db.execute("update users set ui_theme=? where id=?", (th, self.user["id"]))
        if vw in ("list", "kanban", "mini"):
            self.db.execute("update users set ui_view=? where id=?", (vw, self.user["id"]))
        self.db.commit()
        self.redirect_back("/")

    # --- уведомления ---
    def p_notifications(self):
        rows = self.db.execute("select n.*, t.title from notifications n join tasks t on t.id=n.task_id "
                               "where n.user_id=? order by n.id desc limit 100", (self.user["id"],)).fetchall()
        items = "".join('<div class="nt%s"><div class="small mute">%s</div><a href="/task/%d">#%d %s</a><div>%s</div></div>'
                        % (" new" if not r["is_read"] else "", fdt(r["created"]), r["task_id"], r["task_id"],
                           e(r["title"]), e(r["text"])) for r in rows)
        btn = ""
        if any(not r["is_read"] for r in rows):
            btn = ('<form method="post" action="/notifications/read">%s<p><button class="sec">Отметить все прочитанными</button></p></form>'
                   % csrf_field(self.csrf))
        self.page("Уведомления", '<h1>Уведомления</h1>%s<div class="card" style="padding:0">%s</div>'
                  % (btn, items or '<p class="mute" style="padding:12px">Уведомлений пока нет.</p>'))

    def a_notif_read(self):
        self.db.execute("update notifications set is_read=1 where user_id=?", (self.user["id"],))
        self.db.commit()
        self.redirect("/notifications")

    # --- категории (админ) ---
    def p_categories(self):
        self.need_admin()
        rows = ""
        for c in self.db.execute("select c.*, (select count(*) from tasks t where t.category_id=c.id) as n "
                                 "from categories c order by active desc, name"):
            rows += ('<tr><td><form class="inline" method="post" action="/categories/%d/rename">%s'
                     '<input type="text" name="name" value="%s" required maxlength="60" style="width:230px"> '
                     '<button class="sec">Переименовать</button></form></td><td>%d</td><td>%s</td>'
                     '<td><form class="inline" method="post" action="/categories/%d/toggle">%s<button class="sec">%s</button></form></td></tr>'
                     % (c["id"], csrf_field(self.csrf), e(c["name"]), c["n"], "" if c["active"] else "отключена",
                        c["id"], csrf_field(self.csrf), "Отключить" if c["active"] else "Включить"))
        body = ('<h1>Категории</h1><div class="tbl"><table><tr><th>Название</th><th>Задач</th><th></th><th></th></tr>%s</table></div>'
                '<h2>Добавить категорию</h2><div class="card"><form method="post" action="/categories/add">%s'
                '<label>Название</label><input type="text" name="name" required maxlength="60">'
                '<p><button>Добавить</button></p></form></div>'
                '<p class="mute small">Категории не удаляются, чтобы не потерять связь со старыми задачами. '
                'Отключённая категория пропадает из выбора в новых задачах, но остаётся у старых.</p>'
                % (rows, csrf_field(self.csrf)))
        self.page("Категории", body)

    def a_cat_add(self):
        self.need_admin()
        name = self.fields.get("name", "").strip()[:60]
        if not name:
            raise Http(400, "Укажите название категории")
        try:
            self.db.execute("insert into categories(name) values(?)", (name,))
            self.db.commit()
        except sqlite3.IntegrityError:
            raise Http(400, "Такая категория уже есть")
        self.redirect("/categories")

    def a_cat_rename(self, cid):
        self.need_admin()
        name = self.fields.get("name", "").strip()[:60]
        if not name:
            raise Http(400, "Укажите название категории")
        try:
            self.db.execute("update categories set name=? where id=?", (name, cid))
            self.db.commit()
        except sqlite3.IntegrityError:
            raise Http(400, "Такая категория уже есть")
        self.redirect("/categories")

    def a_cat_toggle(self, cid):
        self.need_admin()
        self.db.execute("update categories set active=1-active where id=?", (cid,))
        self.db.commit()
        self.redirect("/categories")

    # --- смена своего пароля ---
    def p_password(self, msg=""):
        body = ('<h1>Смена пароля</h1>%s<div class="card"><form method="post" action="/password">%s'
                '<label>Текущий пароль</label><input type="password" name="old" required>'
                '<label>Новый пароль (от 6 символов)</label><input type="password" name="new" required minlength="6">'
                '<p><button>Сменить пароль</button></p></form></div>'
                % (('<div class="flash">%s</div>' % e(msg)) if msg else "", csrf_field(self.csrf)))
        self.page("Смена пароля", body)

    def a_password(self):
        if not check_pw(self.fields.get("old", ""), self.user["pw"]):
            return self.p_password("Текущий пароль указан неверно.")
        new = self.fields.get("new", "")
        if len(new) < 6:
            return self.p_password("Новый пароль слишком короткий.")
        self.db.execute("update users set pw=? where id=?", (hash_pw(new), self.user["id"]))
        self.db.commit()
        self.redirect("/")


# ---------- запуск ----------
def main():
    ap = argparse.ArgumentParser(description="Простой трекер задач")
    ap.add_argument("cmd", nargs="?", choices=["run", "adduser", "passwd"], default="run")
    ap.add_argument("login", nargs="?")
    ap.add_argument("name", nargs="?")
    ap.add_argument("--admin", action="store_true")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args()
    init_db()
    if a.cmd == "adduser":
        if not a.login or not a.name:
            sys.exit('Использование: app.py adduser LOGIN "Имя Фамилия" [--admin]')
        pw = getpass.getpass("Пароль: ")
        add_user(db(), a.login, a.name, pw, 1 if a.admin else 0)
        print("Пользователь создан.")
    elif a.cmd == "passwd":
        if not a.login:
            sys.exit("Использование: app.py passwd LOGIN")
        c = db()
        c.execute("update users set pw=? where login=?", (hash_pw(getpass.getpass("Новый пароль: ")), a.login))
        c.commit()
        print("Готово.")
    else:
        ThreadingHTTPServer.request_queue_size = 128
        srv = ThreadingHTTPServer((a.host, a.port), H)
        srv.daemon_threads = True
        print("Трекер задач: http://%s:%d  (Ctrl+C — остановить)" % (a.host, a.port))
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
