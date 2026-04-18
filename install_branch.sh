#!/usr/bin/env bash
set -e

# ─────────────────────────────────────────────────────
# PATH safeguard – works even from GUI shells / cron
# ─────────────────────────────────────────────────────
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
# quick sanity-check (coreutils + git + python must exist)
for bin in mkdir git python3; do
  command -v "$bin" >/dev/null || {
    echo "❌ '$bin' not found in PATH – current PATH is: $PATH"
    # exit 1
  }
done

# ─────────────────────────────────────────────────────
#               Variables & Paths
# ─────────────────────────────────────────────────────
ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/core"
VENVDIR="$ROOT/venv"
DATA="$SRC/desktop_data"
BRANCH="${2:-main}"

# ─────────────────────────────────────────────────────
# Bootstrap: clone repo, create venv, reinstall SDK & Rust
# ─────────────────────────────────────────────────────
bootstrap() {
  echo "🔧 Bootstrapping environment..."

  # Clone if missing
  if [ ! -d "$SRC" ]; then
    echo "📥 Cloning Summoner SDK from branch '$BRANCH'..."
    git clone --branch "$BRANCH" --depth 1 https://github.com/Summoner-Network/summoner-core.git "$SRC"
  fi

  # Create venv if missing
  if [ ! -d "$VENVDIR" ]; then
    echo "🐍 Creating virtualenv..."
    python3 -m venv "$VENVDIR"
  fi

  # Activate venv
  . "$VENVDIR/bin/activate"

  # Ensure build tools
  echo "🔧 Installing build requirements..."
  pip install --upgrade pip setuptools wheel maturin

  # Create the .env file
  cat <<EOF > "$SRC/.env"
DATABASE_URL=postgres://user:pass@localhost:5432/mydb
SECRET_KEY=supersecret
EOF

  # Reinstall Python & Rust SDK via backend scripts
  echo "🔁 Reinstalling Python & Rust SDK..."
  bash "$SRC/reinstall_python_sdk.sh" rust_server_v1_0_0
}

# ─────────────────────────────────────────────────────
# Usage message
# ─────────────────────────────────────────────────────
usage() {
  echo "Usage: $0 {setup|delete|reset|deps|test_server|clean} [branch]"
  # exit 1
}

# ─────────────────────────────────────────────────────
# Dispatch
# ─────────────────────────────────────────────────────
case "$1" in
  setup)
    if [ ! -d "$VENVDIR" ]; then
      echo "⚠️  Environment not found; running setup..."
      bootstrap
    else
      . "$VENVDIR/bin/activate"
    fi
    echo "✅ Environment ready at $ROOT"
    # exit 0
    ;;

  delete)
    echo "🔄 Deleting environment..."
    rm -rf "$SRC" "$VENVDIR" "$ROOT"/logs
    rm -f "$ROOT"/test_*.{py,json}
    echo "✅ Deletion complete"
    # exit 0
    ;;

  reset)
    echo "🔄 Resetting environment..."
    rm -rf "$SRC" "$VENVDIR" "$ROOT"/logs
    bootstrap
    echo "✅ Reset complete"
    # exit 0
    ;;

  deps)
    if [ ! -d "$VENVDIR" ]; then
      echo "⚠️  Environment not found; running setup..."
      bootstrap
    else
      . "$VENVDIR/bin/activate"
    fi
    bash "$SRC/reinstall_python_sdk.sh" rust_server_v1_0_0
    echo "✅ Dependencies reinstalled"
    # exit 0
    ;;

  test_server)
    if [ ! -d "$VENVDIR" ]; then
      echo "⚠️  Environment not found; running setup..."
      bootstrap
    else
      . "$VENVDIR/bin/activate"
    fi

    DEFAULT_CFG="$DATA/default_config.json"
    if [ ! -f "$DEFAULT_CFG" ]; then
      echo "❌ Default config missing: $DEFAULT_CFG"
      # exit 1
    fi
    cp "$DEFAULT_CFG" "$ROOT/test_server_config.json"
    cat > "$ROOT/test_server.py" <<'EOF'
from summoner.server import SummonerServer
from tooling.your_package import hello_summoner

if __name__ == "__main__":
    hello_summoner()
    srv = SummonerServer(name="test_Server")
    srv.run(config_path="test_server_config.json")
EOF
    LAUNCH_CMD="source \"$VENVDIR/bin/activate\" && python test_server.py --config test_server_config.json"
    bash "$SRC/open_server.sh" "$ROOT" "$LAUNCH_CMD"
    ;;

  clean)
    echo "🧹 Cleaning test scripts..."
    rm -rf "$ROOT"/logs/*
    rm -f "$ROOT"/test_*.{py,json}
    echo "✅ Clean complete"
    # exit 0
    ;;

  *)
    usage
    ;;
esac
