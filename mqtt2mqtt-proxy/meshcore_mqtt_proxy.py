#!/usr/bin/env python3
"""
meshcore-mqtt2mqtt-proxy  -  copy one MQTT feed out to many brokers.

HOW IT WORKS (no hidden behavior):
  1. Runs a small MQTT broker your device connects to (LISTEN_PORT).
  2. Every message the device publishes is copied, unchanged, to each
     destination you list in the config.
  3. A destination can be: plain MQTT, username/password, or a MeshCore
     JWT broker (LetsMesh / MeshMapper).

NOTHING is auto-filled. Every host, port, and audience comes from your
config file. If you don't type it, the proxy does not use it.

CONFIG FILE (proxy.env)  ->  run:  python3 meshcore_mqtt_proxy.py --env proxy.env

  # --- enable/disable destinations (without removing their config) ---
  DEST1_ENABLED=yes
  DEST2_ENABLED=no
  DEST3_ENABLED=yes

  # --- your device connects in here ---
  LISTEN_PORT=1888
  LISTEN_USER=matt        # blank = anyone can connect (no login)
  LISTEN_PASS=matt

  # --- key, ONLY used by destinations with AUTH=token ---
  PUBLIC_KEY=<64 hex chars>      # your repeater public key
  PRIVATE_KEY=<128 hex chars>    # your repeater private key
  # PRIVATE_KEY_FILE=/path       # ...or read the key from a file instead
  TOKEN_TTL=3600                 # seconds a JWT lasts before auto-refresh

  QOS=0                          # global default: 0 = fire-and-forget, 1 = wait for ack
                                 # override per destination with DEST#_QOS=1

  MAX_PAYLOAD=65536              # bytes; messages larger than this are dropped

  # --- destinations: DEST1_, DEST2_, ...  proxy reads up to MAX_DEST ---
  DEST1_NAME=local
  DEST1_HOST=127.0.0.1
  DEST1_PORT=1883
  DEST1_TLS=no
  DEST1_WEBSOCKET=no
  DEST1_AUTH=none                # none | userpass | token
  # DEST1_USER=     DEST1_PASS=        (only when AUTH=userpass)
  # DEST1_AUD=                          (REQUIRED when AUTH=token)
  # DEST1_REWRITE_IATA=MCO:ORL          (optional: change the IATA in the topic)
  # DEST1_REWRITE_KEEP=yes              (optional: send BOTH original and rewritten)
  # DEST1_RETAIN_STATUS=no              (optional: mark .../status messages retained)
  # DEST1_RETAIN=no                     (optional: mark ALL messages retained)

Requires: paho-mqtt, amqtt, pynacl, passlib
"""

import argparse, asyncio, base64, hashlib, json, logging, os, socket, ssl, sys, tempfile, time

try:
    import paho.mqtt.client as mqtt
except ImportError:
    sys.exit("Need paho-mqtt:  pip install paho-mqtt")

log = logging.getLogger("proxy")
L = 2 ** 252 + 27742317777372353535851937790883648493

# maximum number of DEST# slots to scan (gaps are skipped, not fatal)
MAX_DEST = 50


# ---------------------------------------------------------------- config helpers
def cfg(key, default=""):
    return os.getenv(key, default)

def cfg_yes(key, default=False):
    v = os.getenv(key)
    return default if v is None else v.strip().lower() in ("1", "yes", "true", "on")

def cfg_int(key, default):
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default

def load_env_file(path):
    import re
    if not path or not os.path.exists(path):
        return
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            v = v.strip()
            # drop an inline comment: a '#' that follows whitespace (so values
            # like a password "pa#ss" with no space before '#' are kept intact)
            v = re.split(r"\s+#", v, 1)[0].strip()
            v = v.strip('"').strip("'")
            os.environ.setdefault(k.strip(), v)


# ---------------------------------------------------------------- MeshCore JWT
# Exactly the format MeshCore uses: header alg "Ed25519", signature is HEX (not base64url).
def _b64url(b):
    return base64.b64encode(b).decode().replace("+", "-").replace("/", "_").replace("=", "")

def _sign(message, scalar, prefix, public_key):
    import nacl.bindings
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    R = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(r.to_bytes(32, "little"))
    k = int.from_bytes(hashlib.sha512(R + public_key + message).digest(), "little") % L
    s = (r + k * int.from_bytes(scalar, "little")) % L
    return R + s.to_bytes(32, "little")

def make_token(public_hex, private_hex, aud, ttl):
    """Returns (token_string, expiry_unixtime)."""
    import nacl.signing
    pub = bytes.fromhex(public_hex)
    priv = bytes.fromhex(private_hex)
    if len(pub) != 32:
        raise ValueError(f"PUBLIC_KEY must be 64 hex chars (32 bytes); got {len(pub)} bytes")
    if len(priv) != 64:
        raise ValueError(f"PRIVATE_KEY must be 128 hex chars (64 bytes); got {len(priv)} bytes")
    now = int(time.time())
    exp = now + ttl
    payload = {"publicKey": public_hex.upper(), "iat": now, "exp": exp, "aud": aud,
               "client": "meshcore-mqtt2mqtt-proxy/1.0.0420"}
    owner = cfg("OWNER_PUBLIC_KEY").strip()
    email = cfg("OWNER_EMAIL").strip()
    if owner:
        payload["owner"] = owner.upper()
    if email:
        payload["email"] = email.lower()
    header = _b64url(json.dumps({"alg": "Ed25519", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header}.{body}".encode()
    sig = _sign(signing_input, priv[:32], priv[32:], pub)
    nacl.signing.VerifyKey(pub).verify(signing_input, sig)  # prove the signature is valid
    return f"{header}.{body}.{sig.hex()}", exp


# ---------------------------------------------------------------- a destination
class Dest:
    def __init__(self, d):
        self.name       = d["name"]
        self.host       = d["host"]
        self.port       = d["port"]
        self.auth       = d["auth"]        # none | userpass | token
        self.aud        = d.get("aud", "")
        self.rewrite_from   = d.get("rewrite_from")
        self.rewrite_to     = d.get("rewrite_to")
        self.rewrite_keep   = d.get("rewrite_keep", False)
        self.retain_status  = d.get("retain_status", False)
        self.retain_all     = d.get("retain_all", False)
        self.qos            = d["qos"]
        self.token_exp      = 0
        self._token_refresh_pending = False

        transport = "websockets" if d["websocket"] else "tcp"

        # client IDs must be unique; use the full name, truncate with a warning
        raw_cid = f"mc_{self.name}"
        if len(raw_cid) > 23:
            cid = raw_cid[:23]
            log.warning("[%s] client ID truncated to 23 chars: '%s' -> '%s'",
                        self.name, raw_cid, cid)
        else:
            cid = raw_cid

        self.c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                             client_id=cid, transport=transport)
        self.c.reconnect_delay_set(min_delay=1, max_delay=60)
        self.c.on_connect    = self._on_connect
        self.c.on_disconnect = self._on_disconnect


        def _nodelay(client, userdata, sock):
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except (OSError, AttributeError):
                pass
        self.c.on_socket_open = _nodelay




        if d["tls"]:
            self.c.tls_set(cert_reqs=ssl.CERT_REQUIRED)
        if d["websocket"]:
            self.c.ws_set_options(path="/")

        if self.auth == "userpass":
            self.c.username_pw_set(d.get("user", ""), d.get("pass", ""))
        elif self.auth == "token":
            tok, self.token_exp = make_token(PUBLIC_KEY, PRIVATE_KEY, self.aud, TOKEN_TTL)
            self.c.username_pw_set("v1_" + PUBLIC_KEY.upper(), tok)

    def _on_connect(self, c, u, flags, rc, props=None):
        code = getattr(rc, "value", rc)
        if code == 0:
            log.info("[%s] connected to %s:%s", self.name, self.host, self.port)
            self._token_refresh_pending = False
        else:
            log.warning("[%s] connect REJECTED rc=%s (host/port/login/audience?)",
                        self.name, code)

    def _on_disconnect(self, c, u, *a):
        reason = a[1] if len(a) >= 2 else (a[0] if a else "?")
        log.warning("[%s] disconnected (reason: %s), will retry", self.name, reason)

    def start(self):
        self.c.connect_async(self.host, self.port, keepalive=60)
        self.c.loop_start()

    def refresh_token(self):
        """Update credentials and reconnect. Safe to call whether connected or not."""
        if self._token_refresh_pending:
            log.debug("[%s] token refresh already in progress, skipping", self.name)
            return
        self._token_refresh_pending = True
        tok, self.token_exp = make_token(PUBLIC_KEY, PRIVATE_KEY, self.aud, TOKEN_TTL)
        self.c.username_pw_set("v1_" + PUBLIC_KEY.upper(), tok)
        # reconnect() raises if the socket is already gone; that's fine —
        # paho's auto-reconnect loop will pick up the new credentials on its
        # next attempt, so we just log and move on.
        try:
            self.c.reconnect()
        except Exception as e:
            log.debug("[%s] reconnect after token refresh deferred (%s); "
                      "paho will retry automatically", self.name, e)

    def send(self, topic, payload):
        """Publish to this destination, applying any topic rewrite."""
        topics = [topic]
        if self.rewrite_from and self.rewrite_to:
            parts = topic.split("/")
            # meshcore/<IATA>/... — only rewrite if the IATA segment matches
            if len(parts) >= 2 and parts[1] == self.rewrite_from:
                new_topic = "/".join([parts[0], self.rewrite_to] + parts[2:])
                topics = [topic, new_topic] if self.rewrite_keep else [new_topic]

        retain = self.retain_all or (self.retain_status and topic.endswith("/status"))
        for t in topics:
            try:
                self.c.publish(t, payload, qos=self.qos, retain=retain)
            except Exception as e:
                log.warning("[%s] send error (skipped): %s", self.name, e)
        return topics


# ---------------------------------------------------------------- read destinations
def read_destinations():
    """
    Scan DEST1_ … DEST{MAX_DEST}_.

    - Gaps (missing HOST) are skipped with a warning so a disabled or
      mis-numbered block never kills later ones.
    - DEST#_ENABLED=no (or false/0) skips that block entirely but keeps scanning.
    """
    dests = []
    for i in range(1, MAX_DEST + 1):
        # ENABLED check first — lets you flip a dest off without touching anything else
        if not cfg_yes(f"DEST{i}_ENABLED", default=True):
            log.info("DEST%d skipped (ENABLED=no)", i)
            continue

        host = cfg(f"DEST{i}_HOST").strip()
        if not host:
            # No HOST configured for this slot — might be a gap, might just be the end.
            # Either way, skip rather than abort.
            if any(os.getenv(f"DEST{i}_{k}") for k in
                   ("NAME", "PORT", "AUTH", "USER", "PASS", "AUD", "TLS", "WEBSOCKET")):
                log.warning("DEST%d has config keys but no HOST — skipping (typo?)", i)
            continue

        auth = cfg(f"DEST{i}_AUTH", "none").strip().lower()
        if auth not in ("none", "userpass", "token"):
            log.warning("DEST%d_AUTH='%s' invalid; using none", i, auth)
            auth = "none"

        if auth == "token" and not cfg(f"DEST{i}_AUD").strip():
            log.error("DEST%d (%s) is AUTH=token but has no DEST%d_AUD — skipping.",
                      i, cfg(f"DEST{i}_NAME", host), i)
            continue

        rf = rt = None
        rw = cfg(f"DEST{i}_REWRITE_IATA").strip()
        if ":" in rw:
            a, b = (x.strip() for x in rw.split(":", 1))
            if a and b:
                rf, rt = a, b

        dests.append({
            "name":         cfg(f"DEST{i}_NAME", host).strip(),
            "host":         host,
            "port":         cfg_int(f"DEST{i}_PORT", 1883),
            "tls":          cfg_yes(f"DEST{i}_TLS"),
            "websocket":    cfg_yes(f"DEST{i}_WEBSOCKET"),
            "auth":         auth,
            "user":         cfg(f"DEST{i}_USER"),
            "pass":         cfg(f"DEST{i}_PASS"),
            "aud":          cfg(f"DEST{i}_AUD").strip(),
            "rewrite_from": rf,
            "rewrite_to":   rt,
            "rewrite_keep": cfg_yes(f"DEST{i}_REWRITE_KEEP"),
            "retain_status":cfg_yes(f"DEST{i}_RETAIN_STATUS"),
            "retain_all":   cfg_yes(f"DEST{i}_RETAIN"),
            "qos":          cfg_int(f"DEST{i}_QOS", cfg_int("QOS", 0)),
        })

    return dests


# ---------------------------------------------------------------- main
PUBLIC_KEY = PRIVATE_KEY = ""
TOKEN_TTL = 3600

async def run():
    from amqtt.broker import Broker
    from amqtt.client import MQTTClient

    port        = cfg_int("LISTEN_PORT", 1888)
    listen_user = cfg("LISTEN_USER").strip()
    listen_pass = cfg("LISTEN_PASS")
    max_payload = cfg_int("MAX_PAYLOAD", 65536)

    dest_cfgs = read_destinations()
    if not dest_cfgs:
        log.error("No destinations configured (or all disabled). Stopping.")
        return

    dests = [Dest(d) for d in dest_cfgs]
    for d in dests:
        d.start()

    # token auto-refresh — one task per token destination
    async def token_refresher(dest):
        while True:
            sleep_for = max(30, dest.token_exp - 300 - int(time.time()))
            await asyncio.sleep(sleep_for)
            try:
                dest.refresh_token()
                log.info("[%s] token refreshed", dest.name)
            except Exception as e:
                log.error("[%s] token refresh failed: %s", dest.name, e)
                await asyncio.sleep(30)

    refresh_tasks = [
        asyncio.create_task(token_refresher(d))
        for d in dests if d.auth == "token"
    ]

    # broker the device connects to
    if listen_user:
        from passlib.apps import custom_app_context as pwd
        pwfile = os.path.join(tempfile.gettempdir(), f"mc_proxy_pw_{os.getpid()}")
        fd = os.open(pwfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"{listen_user}:{pwd.hash(listen_pass)}\n")
        auth_cfg   = {"allow-anonymous": False, "password-file": pwfile}
        login_note = f"login required (user '{listen_user}')"
    else:
        auth_cfg   = {"allow-anonymous": True}
        login_note = "no login (anyone can connect)"

    broker = Broker({
        "listeners": {"default": {"type": "tcp", "bind": f"0.0.0.0:{port}"}},
        "sys_interval": 0,
        "auth": auth_cfg,
    })
    await broker.start()
    log.info("device broker listening on port %d (%s)", port, login_note)

    # proxy's own subscriber — reads everything the device sends
    creds = f"{listen_user}:{listen_pass}@" if listen_user else ""
    sub = MQTTClient(config={"auto_reconnect": True})
    await sub.connect(f"mqtt://{creds}127.0.0.1:{port}/")

    # subscribe to user topics only; explicitly exclude $SYS to avoid
    # forwarding internal broker stats to all destinations
    await sub.subscribe([
        ("meshcore/#", 0),   # device publishes here; adjust if your prefix differs
    ])
    log.info("copying every message to: %s",
             ", ".join(f"{d.name}(qos{d.qos})" for d in dests))

    n = 0
    try:
        while True:
            m = await sub.deliver_message()
            try:
                topic   = m.topic
                payload = bytes(m.data)

                # drop oversized messages before they fan out
                if len(payload) > max_payload:
                    log.warning("dropping oversized message on %s (%d bytes > %d limit)",
                                topic, len(payload), max_payload)
                    continue

                for d in dests:
                    d.send(topic, payload)

                n += 1
                if n <= 5 or n % 100 == 0:
                    log.info("#%d  %s  (%d bytes)", n, topic, len(payload))
            except Exception as e:
                log.warning("error on one message (continuing): %s", e)
    except asyncio.CancelledError:
        pass
    finally:
        for t in refresh_tasks:
            t.cancel()
        for d in dests:
            try:
                d.c.loop_stop()
                d.c.disconnect()
            except BaseException:
                pass
        await sub.disconnect()
        await broker.shutdown()


def main():
    global PUBLIC_KEY, PRIVATE_KEY, TOKEN_TTL
    ap = argparse.ArgumentParser(description="Copy one MQTT feed out to many brokers")
    ap.add_argument("--env", help="path to your proxy.env config file")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s",
                        datefmt="%H:%M:%S")

    # show broker connection problems as ONE clean line (no scary traceback dump)
    class NoTraceback(logging.Filter):
        def filter(self, record):
            record.exc_info = None
            record.exc_text = None
            return True

    for name in ("amqtt", "amqtt.broker", "amqtt.broker.plugins", "transitions"):
        lg = logging.getLogger(name)
        lg.addFilter(NoTraceback())
        lg.setLevel(logging.WARNING)

    import warnings
    warnings.filterwarnings("ignore", category=DeprecationWarning)

    load_env_file(args.env)
    PUBLIC_KEY  = cfg("PUBLIC_KEY").strip()
    PRIVATE_KEY = cfg("PRIVATE_KEY").strip()
    pkfile = cfg("PRIVATE_KEY_FILE").strip()
    if not PRIVATE_KEY and pkfile and os.path.exists(pkfile):
        PRIVATE_KEY = "".join(open(pkfile).read().split())
    TOKEN_TTL = cfg_int("TOKEN_TTL", 3600)

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()

