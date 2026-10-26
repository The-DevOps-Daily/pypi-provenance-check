#!/usr/bin/env bash
# Put a harmless stand-in for the litellm 1.107.0 wheel through uv, pip 23 and
# pip 26, then run ioc_check.py on what each tool left behind: the installed
# venv, uv's cache, pip's old http cache and pip's http-v2 cache.
#
#   bash scripts/cache_layout_demo.sh            (needs uv and openssl; uses PyPI to install pip)
#
# The wheel is built by tests/fixtures.py. Its cook.py and sitecustomize.py are
# comments. It is served from a local TLS server on 127.0.0.1, because pip only
# caches responses from secure origins.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'kill "${server:-0}" 2>/dev/null || true; rm -rf "$work"' EXIT
cd "$work"

python3 -I "$repo/tests/fixtures.py" fx >/dev/null
mkdir wheels && cp fx/litellm-1.107.0-py3-none-any.whl wheels/
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 \
  -subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null
cat > serve.py <<'EOF'
import functools, http.server, ssl, sys
class H(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        if self.path.endswith(".whl"):
            self.send_header("Cache-Control", "max-age=31536000, immutable, public")
        super().end_headers()
    def log_message(self, *a):
        pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(H, directory=sys.argv[1]))
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[2], sys.argv[3])
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print(srv.server_address[1], flush=True)
srv.serve_forever()
EOF
python3 -I serve.py wheels cert.pem key.pem > port.txt &
server=$!
for _ in $(seq 50); do [ -s port.txt ] && break; sleep 0.1; done
url="https://127.0.0.1:$(cat port.txt)/"

echo "## uv $(uv --version | cut -d' ' -f2): install into a venv"
uv venv -q --python 3.11 venv-uv
UV_CACHE_DIR="$work/uvcache" uv pip install -q --python venv-uv/bin/python \
  --no-index --find-links wheels litellm==1.107.0
for v in 23.0.1 26.2.2; do
  uv venv -q --python 3.11 "venv-pip$v"
  UV_CACHE_DIR="$work/uvcache-tools" uv pip install -q --python "venv-pip$v/bin/python" "pip==$v"
  "venv-pip$v/bin/python" -m pip download -q --cert cert.pem --cache-dir "$work/pipcache-$v" \
    --no-index --find-links "$url" -d "dl-$v" litellm==1.107.0
done

run() {
  echo
  echo "\$ python3 -I -S ioc_check.py $*"
  python3 -I -S "$repo/ioc_check.py" "$@" | sed "s#$work/##g" || true
}
run env venv-uv
run scan uvcache
run scan pipcache-23.0.1
run scan pipcache-26.2.2
echo
echo "## files the caches hold"
(cd "$work" && find uvcache/archive-v0 uvcache/wheels-v* pipcache-23.0.1 pipcache-26.2.2 -type f | sort)
