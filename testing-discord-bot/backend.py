#!/usr/bin/env python3
import argparse
import json
import os
import socket
import sys
from typing import Dict, Any

from core import handle_action

SOCK_PATH = "/run/xray-backend.sock"
SOCK_GROUP = "discordbot"
SOCK_MODE = 0o660

def die(msg: str, code: int = 1):
    print(msg, file=sys.stderr)
    sys.exit(code)

def ensure_root():
    if os.geteuid() != 0:
        die("Must run as root (backend service).", 2)

def setup_socket():
    if os.path.exists(SOCK_PATH):
        os.remove(SOCK_PATH)

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(SOCK_PATH)

    import grp
    gid = grp.getgrnam(SOCK_GROUP).gr_gid
    os.chown(SOCK_PATH, 0, gid)
    os.chmod(SOCK_PATH, SOCK_MODE)

    s.listen(50)
    return s

def recv_json_line(conn) -> Dict[str, Any]:
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 1024 * 1024:
            raise ValueError("Request too large")
    line = buf.split(b"\n", 1)[0].decode("utf-8", errors="strict")
    return json.loads(line)

def send_json(conn, obj: Dict[str, Any]):
    data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
    conn.sendall(data)

def serve():
    ensure_root()
    s = setup_socket()
    try:
        while True:
            conn, _ = s.accept()
            try:
                req = recv_json_line(conn)
                resp = handle_action(req)
            except Exception as ex:
                resp = {"status": "error", "error": str(ex)}
            try:
                send_json(conn, resp)
            finally:
                conn.close()
    finally:
        s.close()
        if os.path.exists(SOCK_PATH):
            os.remove(SOCK_PATH)

def cli():
    ensure_root()
    p = argparse.ArgumentParser(prog="xray-userctl", add_help=True)
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("add")
    pa.add_argument("protocol", choices=["vless","vmess","trojan","allproto"])
    pa.add_argument("username")
    pa.add_argument("days", type=int)
    pa.add_argument("quota_gb", type=float)

    pd = sub.add_parser("del")
    pd.add_argument("protocol", choices=["vless","vmess","trojan","allproto"])
    pd.add_argument("username")

    args = p.parse_args()
    req = {"action": args.cmd, "protocol": args.protocol, "username": args.username}
    if args.cmd == "add":
        req["days"] = args.days
        req["quota_gb"] = args.quota_gb

    resp = handle_action(req)
    print(json.dumps(resp, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--serve":
        serve()
    else:
        sys.exit(cli())