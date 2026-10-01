# -*- coding: utf-8 -*-
"""
════════════════════════════════════════════════════════════════
  🌐 HAMO Dashboard Server v3.0 ULTRA
  - Login + Admin + Dashboard
  - Create Accounts (بدل المفاتيح)
  - Broadcast System
  - User Management
  - Real-time Bot Stats
════════════════════════════════════════════════════════════════
"""

import asyncio
import json
import os
import time
import random
import string
from typing import Dict, List, Any, Optional
from aiohttp import web

# ═══════════════════════════════════════════════════════
#   Config
# ═══════════════════════════════════════════════════════
USERS_FILE = "users.json"
ACCOUNTS_FILE = "accounts.json"
BROADCASTS_FILE = "broadcasts.json"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "hamo2025"  # ← غيرها لإنت

# Sessions in memory
_sessions: Dict[str, Dict[str, Any]] = {}


# ═══════════════════════════════════════════════════════
#   File Helpers
# ═══════════════════════════════════════════════════════
def load_json(path, default=None):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return default if default is not None else []


def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def random_string(length=16):
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=length))


# ═══════════════════════════════════════════════════════
#   Bot State
# ═══════════════════════════════════════════════════════
class BotState:
    def __init__(self):
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.logs: List[Dict[str, Any]] = []
        self.max_logs = 200
        self.total_matches = 0
        self.total_gained_exp = 0
        self.start_time = time.time()
        self.account_workers: Dict[str, asyncio.Task] = {}
        self.refresh_callbacks: Dict[str, Any] = {}
        self.account_credentials: Dict[str, Dict[str, Any]] = {}

    def log(self, message: str, level: str = "info", uid: Optional[str] = None):
        entry = {
            "time": time.strftime("%H:%M:%S"),
            "level": level,
            "message": message,
            "uid": str(uid) if uid else None
        }
        self.logs.append(entry)
        if len(self.logs) > self.max_logs:
            self.logs.pop(0)

    def register_account(self, uid: str, nickname: str, region: str, level: int, exp: int, likes: int = 0):
        uid_str = str(uid)
        if uid_str not in self.accounts:
            self.accounts[uid_str] = {
                "uid": uid_str,
                "nickname": nickname or f"Player_{uid_str[:6]}",
                "region": region or "BD",
                "level": level or 1,
                "initial_exp": exp,
                "current_exp": exp,
                "gained_exp": 0,
                "likes": likes or 0,
                "status": "ONLINE",
                "matches_played": 0,
                "active_matches": 0,
                "last_match_time": None,
                "last_updated": time.strftime("%H:%M:%S")
            }
        else:
            acc = self.accounts[uid_str]
            if nickname:
                acc["nickname"] = nickname
            if region:
                acc["region"] = region
            if level:
                acc["level"] = level
            acc["current_exp"] = exp
            acc["gained_exp"] = max(0, exp - acc["initial_exp"])
            acc["likes"] = likes
            acc["status"] = "ONLINE"
            acc["last_updated"] = time.strftime("%H:%M:%S")
        self.recalc_totals()

    def update_exp(self, uid: str, current_exp: int, level: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            acc = self.accounts[uid_str]
            old_exp = acc["current_exp"]
            acc["current_exp"] = current_exp
            if level is not None and level > 0:
                acc["level"] = level
            acc["gained_exp"] = max(0, current_exp - acc["initial_exp"])
            acc["last_updated"] = time.strftime("%H:%M:%S")
            diff = current_exp - old_exp
            if diff > 0:
                self.log(f"Account {acc['nickname']} ({uid_str}) gained +{diff} EXP!", "success", uid_str)
            self.recalc_totals()

    def update_status(self, uid: str, status: str, active_matches: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            self.accounts[uid_str]["status"] = status
            if active_matches is not None:
                self.accounts[uid_str]["active_matches"] = active_matches
            self.accounts[uid_str]["last_updated"] = time.strftime("%H:%M:%S")

    def increment_match(self, uid: str):
        uid_str = str(uid)
        self.total_matches += 1
        if uid_str in self.accounts:
            self.accounts[uid_str]["matches_played"] += 1
            self.accounts[uid_str]["last_match_time"] = time.strftime("%H:%M:%S")
            self.accounts[uid_str]["last_updated"] = time.strftime("%H:%M:%S")
            self.log(
                f"Account {self.accounts[uid_str]['nickname']} finished Match #{self.accounts[uid_str]['matches_played']}",
                "info",
                uid_str
            )

    def recalc_totals(self):
        self.total_gained_exp = sum(acc.get("gained_exp", 0) for acc in self.accounts.values())


bot_state = BotState()


# ═══════════════════════════════════════════════════════
#   Session Helpers
# ═══════════════════════════════════════════════════════
def create_session(username: str, is_admin: bool = False):
    token = random_string(32)
    _sessions[token] = {
        "username": username,
        "is_admin": is_admin,
        "created": time.time()
    }
    return token


def get_session(token: str) -> Optional[Dict[str, Any]]:
    return _sessions.get(token)


def get_token_from_request(request: web.Request) -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    cookie = request.cookies.get("hamo_token", "")
    if cookie:
        return cookie
    return request.query.get("token", "")


def require_admin(request: web.Request) -> Optional[Dict[str, Any]]:
    token = get_token_from_request(request)
    session = get_session(token)
    if not session or not session.get("is_admin"):
        return None
    return session


def require_auth(request: web.Request) -> Optional[Dict[str, Any]]:
    token = get_token_from_request(request)
    return get_session(token)


# ═══════════════════════════════════════════════════════
#   Template Paths
# ═══════════════════════════════════════════════════════
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

LOGIN_PATH = os.path.join(TEMPLATES_DIR, "login.html")
ADMIN_PATH = os.path.join(TEMPLATES_DIR, "admin.html")
DASHBOARD_PATH = os.path.join(TEMPLATES_DIR, "index.html")


def serve_html(path: str, fallback: str = "<h1>Not found</h1>") -> web.Response:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return web.Response(text=f.read(), content_type="text/html", charset="utf-8")
    alt = os.path.join(BASE_DIR, os.path.basename(path))
    if os.path.exists(alt):
        with open(alt, "r", encoding="utf-8") as f:
            return web.Response(text=f.read(), content_type="text/html", charset="utf-8")
    return web.Response(text=fallback, content_type="text/html", charset="utf-8")


# ═══════════════════════════════════════════════════════
#   Page Handlers
# ═══════════════════════════════════════════════════════
async def handle_login_page(request: web.Request) -> web.Response:
    return serve_html(LOGIN_PATH, "<h1>login.html not found</h1>")


async def handle_admin_page(request: web.Request) -> web.Response:
    session = require_admin(request)
    if not session:
        raise web.HTTPFound("/")
    return serve_html(ADMIN_PATH, "<h1>admin.html not found</h1>")


async def handle_dashboard_page(request: web.Request) -> web.Response:
    return serve_html(DASHBOARD_PATH, "<h1>index.html not found</h1>")


# ═══════════════════════════════════════════════════════
#   Auth APIs
# ═══════════════════════════════════════════════════════
async def handle_api_login(request: web.Request) -> web.Response:
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"success": False, "message": "Invalid JSON"})

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    if not username or not password:
        return web.json_response({"success": False, "message": "البيانات ناقصة"})

    # ═══ Admin ═══
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = create_session(username, is_admin=True)
        response = web.json_response({
            "success": True,
            "message": "مرحباً ADMIN 👑",
            "token": token,
            "is_admin": True,
            "redirect": "/admin"
        })
        response.set_cookie("hamo_token", token, max_age=86400, samesite="Lax")
        return response

    # ═══ User ═══
    users = load_json(USERS_FILE, [])
    for u in users:
        if u.get("username") == username:
            if u.get("password") == password:
                if u.get("banned"):
                    return web.json_response({
                        "success": False,
                        "message": "🚫 هذا الحساب محظور"
                    })
                token = create_session(username, is_admin=False)
                response = web.json_response({
                    "success": True,
                    "message": f"مرحباً {username}",
                    "token": token,
                    "is_admin": False,
                    "is_vip": u.get("vip", False),
                    "redirect": "/dashboard"
                })
                response.set_cookie("hamo_token", token, max_age=86400, samesite="Lax")
                return response
            return web.json_response({
                "success": False,
                "message": "كلمة المرور غير صحيحة"
            })

    return web.json_response({
        "success": False,
        "message": "المستخدم غير موجود"
    })


async def handle_api_logout(request: web.Request) -> web.Response:
    token = get_token_from_request(request)
    if token in _sessions:
        del _sessions[token]
    response = web.json_response({"success": True})
    response.del_cookie("hamo_token")
    return response


async def handle_api_check_auth(request: web.Request) -> web.Response:
    token = get_token_from_request(request)
    session = get_session(token)
    if not session:
        return web.json_response({"success": False, "authenticated": False})
    return web.json_response({
        "success": True,
        "authenticated": True,
        "username": session["username"],
        "is_admin": session.get("is_admin", False)
    })


# ═══════════════════════════════════════════════════════
#   Bot Stats APIs
# ═══════════════════════════════════════════════════════
async def handle_get_stats(request: web.Request) -> web.Response:
    accounts_data = list(bot_state.accounts.values())
    accounts_data.sort(key=lambda x: x.get("gained_exp", 0), reverse=True)
    return web.json_response({
        "total_accounts": len(bot_state.accounts),
        "total_matches": bot_state.total_matches,
        "total_gained_exp": bot_state.total_gained_exp,
        "accounts": accounts_data,
        "logs": bot_state.logs[-60:],
        "uptime": int(time.time() - bot_state.start_time)
    })


async def handle_add_account(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        existing = load_json(ACCOUNTS_FILE, [])

        if "uid" in data and "password" in data:
            uid = str(data["uid"]).strip()
            pwd = str(data["password"]).strip()
            if not uid or not pwd:
                return web.json_response({"status": "error", "error": "UID and Password required"})
            existing = [acc for acc in existing if str(acc.get("uid")) != uid]
            existing.append({"uid": uid, "password": pwd})
        elif "token" in data:
            token = str(data["token"]).strip()
            if not token:
                return web.json_response({"status": "error", "error": "Token required"})
            existing = [acc for acc in existing if acc.get("token") != token]
            existing.append({"token": token})
        else:
            return web.json_response({"status": "error", "error": "Invalid payload"})

        save_json(ACCOUNTS_FILE, existing)
        bot_state.log(f"New account added: {data.get('uid') or 'Token'}", "success")

        if "on_account_added" in bot_state.refresh_callbacks:
            asyncio.create_task(bot_state.refresh_callbacks["on_account_added"](data))

        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def handle_delete_account(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        uid = str(data.get("uid")).strip()
        existing = load_json(ACCOUNTS_FILE, [])
        existing = [acc for acc in existing if str(acc.get("uid")) != uid]
        save_json(ACCOUNTS_FILE, existing)

        if uid in bot_state.accounts:
            del bot_state.accounts[uid]

        if uid in bot_state.account_workers:
            bot_state.account_workers[uid].cancel()
            del bot_state.account_workers[uid]

        bot_state.log(f"Account {uid} removed.", "warning", uid)
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def handle_refresh_account(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        uid = str(data.get("uid")).strip()
        if "on_refresh_account" in bot_state.refresh_callbacks:
            asyncio.create_task(bot_state.refresh_callbacks["on_refresh_account"](uid))
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


# ═══════════════════════════════════════════════════════
#   Admin APIs
# ═══════════════════════════════════════════════════════
async def handle_admin_users(request: web.Request) -> web.Response:
    session = require_admin(request)
    if not session:
        return web.json_response({"success": False, "error": "admin only"}, status=403)

    users = load_json(USERS_FILE, [])
    return web.json_response({"success": True, "users": users})


async def handle_admin_create_accounts(request: web.Request) -> web.Response:
    """إنشاء حسابات جديدة مباشرة (بدل المفاتيح)"""
    session = require_admin(request)
    if not session:
        return web.json_response({"success": False, "error": "admin only"}, status=403)

    try:
        data = await request.json()
    except Exception:
        return web.json_response({"success": False, "message": "Invalid JSON"})

    vip_type = str(data.get("vip_type", "vip_month"))
    count = int(data.get("count", 5))
    default_password = str(data.get("password", "")).strip()

    if count < 1 or count > 100:
        return web.json_response({"success": False, "message": "العدد بين 1 و 100"})

    users = load_json(USERS_FILE, [])
    existing_usernames = {u.get("username") for u in users}

    created = []
    for i in range(count):
        # اسم مستخدم فريد
        while True:
            username = f"user_{random_string(8).lower()}"
            if username not in existing_usernames:
                existing_usernames.add(username)
                break

        password = default_password if default_password else random_string(12)

        new_user = {
            "username": username,
            "password": password,
            "vip": True,
            "vip_type": vip_type,
            "banned": False,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "created_by": session["username"]
        }
        users.append(new_user)
        created.append(new_user)

    save_json(USERS_FILE, users)
    bot_state.log(f"Admin {session['username']} created {count} accounts ({vip_type})", "success")

    return web.json_response({
        "success": True,
        "accounts": created
    })


async def handle_admin_broadcast(request: web.Request) -> web.Response:
    session = require_admin(request)
    if not session:
        return web.json_response({"success": False, "error": "admin only"}, status=403)

    try:
        data = await request.json()
    except Exception:
        return web.json_response({"success": False, "message": "Invalid JSON"})

    title = str(data.get("title", "")).strip()
    message = str(data.get("message", "")).strip()

    if not message:
        return web.json_response({"success": False, "message": "الرسالة فارغة"})

    broadcasts = load_json(BROADCASTS_FILE, [])
    broadcasts.insert(0, {
        "title": title,
        "message": message,
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "sent_by": session["username"]
    })
    save_json(BROADCASTS_FILE, broadcasts)

    bot_state.log(f"📢 Broadcast from {session['username']}: {message[:50]}", "info")
    return web.json_response({"success": True, "message": "تم الإرسال"})


async def handle_admin_broadcasts(request: web.Request) -> web.Response:
    session = require_admin(request)
    if not session:
        return web.json_response({"success": False, "error": "admin only"}, status=403)

    broadcasts = load_json(BROADCASTS_FILE, [])
    return web.json_response({"success": True, "broadcasts": broadcasts[:50]})


async def handle_admin_ban_user(request: web.Request) -> web.Response:
    session = require_admin(request)
    if not session:
        return web.json_response({"success": False, "error": "admin only"}, status=403)

    try:
        data = await request.json()
    except Exception:
        return web.json_response({"success": False})

    username = str(data.get("username", "")).strip()
    banned = bool(data.get("banned", True))

    users = load_json(USERS_FILE, [])
    for u in users:
        if u.get("username") == username:
            u["banned"] = banned
            break
    save_json(USERS_FILE, users)
    bot_state.log(f"User {username} {'banned' if banned else 'unbanned'} by {session['username']}", "warning")
    return web.json_response({"success": True})


async def handle_admin_delete_user(request: web.Request) -> web.Response:
    session = require_admin(request)
    if not session:
        return web.json_response({"success": False, "error": "admin only"}, status=403)

    try:
        data = await request.json()
    except Exception:
        return web.json_response({"success": False})

    username = str(data.get("username", "")).strip()
    users = load_json(USERS_FILE, [])
    users = [u for u in users if u.get("username") != username]
    save_json(USERS_FILE, users)
    bot_state.log(f"User {username} deleted by {session['username']}", "warning")
    return web.json_response({"success": True})


async def handle_admin_stats(request: web.Request) -> web.Response:
    session = require_admin(request)
    if not session:
        return web.json_response({"success": False, "error": "admin only"}, status=403)

    users = load_json(USERS_FILE, [])
    broadcasts = load_json(BROADCASTS_FILE, [])

    return web.json_response({
        "success": True,
        "total_users": len(users),
        "banned_users": sum(1 for u in users if u.get("banned")),
        "vip_users": sum(1 for u in users if u.get("vip")),
        "active_users": sum(1 for u in users if not u.get("banned")),
        "total_broadcasts": len(broadcasts),
        "uptime": int(time.time() - bot_state.start_time)
    })


# ═══════════════════════════════════════════════════════
#   Start Web Dashboard
# ═══════════════════════════════════════════════════════
async def start_web_dashboard(host: str = "0.0.0.0", port: int = 20335):
    app = web.Application()

    # ═══ Pages ═══
    app.router.add_get("/", handle_login_page)
    app.router.add_get("/login", handle_login_page)
    app.router.add_get("/admin", handle_admin_page)
    app.router.add_get("/dashboard", handle_dashboard_page)

    # ═══ Auth ═══
    app.router.add_post("/api/login", handle_api_login)
    app.router.add_post("/api/logout", handle_api_logout)
    app.router.add_get("/api/check-auth", handle_api_check_auth)

    # ═══ Bot Stats ═══
    app.router.add_get("/api/stats", handle_get_stats)
    app.router.add_post("/api/account/add", handle_add_account)
    app.router.add_post("/api/account/delete", handle_delete_account)
    app.router.add_post("/api/account/refresh", handle_refresh_account)

    # ═══ Admin ═══
    app.router.add_get("/api/admin/stats", handle_admin_stats)
    app.router.add_get("/api/admin/users", handle_admin_users)
    app.router.add_post("/api/admin/create-accounts", handle_admin_create_accounts)
    app.router.add_post("/api/admin/broadcast", handle_admin_broadcast)
    app.router.add_get("/api/admin/broadcasts", handle_admin_broadcasts)
    app.router.add_post("/api/admin/user/ban", handle_admin_ban_user)
    app.router.add_post("/api/admin/user/delete", handle_admin_delete_user)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()

    print(f"\033[92m[+] ═══════════════════════════════════════════════════════\033[0m")
    print(f"\033[92m[+] 🌐 HAMO Dashboard Server Started!\033[0m")
    print(f"\033[92m[+] ═══════════════════════════════════════════════════════\033[0m")
    print(f"\033[96m[+] 🔐 Login:      http://localhost:{port}/\033[0m")
    print(f"\033[96m[+] 👑 Admin:      http://localhost:{port}/admin\033[0m")
    print(f"\033[96m[+] 📊 Dashboard:  http://localhost:{port}/dashboard\033[0m")
    print(f"\033[93m[+] 🔑 Admin Credentials: {ADMIN_USERNAME} / {ADMIN_PASSWORD}\033[0m")
    print(f"\033[92m[+] ═══════════════════════════════════════════════════════\033[0m")


# ═══════════════════════════════════════════════════════
#   Run Standalone
# ═══════════════════════════════════════════════════════
if __name__ == "__main__":
    async def _main():
        await start_web_dashboard()
        while True:
            await asyncio.sleep(3600)

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        print("\n[!] Server stopped")