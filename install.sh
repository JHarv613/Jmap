#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  Jmap Installer / Uninstaller for Ubuntu 22.04 LTS
#  No root or sudo required — installs to ~/.local/bin
#
#  Usage:
#    ./install.sh             Install Jmap
#    ./install.sh --uninstall Remove Jmap
# ─────────────────────────────────────────────────────────────

INSTALL_DIR="$HOME/.local/bin"
LIB_DIR="$HOME/.local/lib"
LIB_FILE="$LIB_DIR/Jmap.py"
BIN_FILE="$INSTALL_DIR/Jmap"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Marker used to identify lines we added to shell config files
PATH_MARKER="# >>> Jmap PATH >>>"
PATH_MARKER_END="# <<< Jmap PATH <<<"

# ══════════════════════════════════════════════════════════════
#  UNINSTALL
# ══════════════════════════════════════════════════════════════
if [[ "$1" == "--uninstall" ]]; then
    echo ""
    echo "  ┌─────────────────────────────────┐"
    echo "  │     Jmap Uninstaller            │"
    echo "  └─────────────────────────────────┘"
    echo ""

    REMOVED=0

    # Remove launcher
    if [[ -f "$BIN_FILE" ]]; then
        rm -f "$BIN_FILE"
        echo "  [✓] Removed launcher  : $BIN_FILE"
        REMOVED=1
    else
        echo "  [!] Launcher not found: $BIN_FILE (already removed?)"
    fi

    # Remove library file
    if [[ -f "$LIB_FILE" ]]; then
        rm -f "$LIB_FILE"
        echo "  [✓] Removed library   : $LIB_FILE"
        REMOVED=1
    else
        echo "  [!] Library not found : $LIB_FILE (already removed?)"
    fi

    # Remove PATH block from shell config files
    remove_path_entry() {
        local FILE="$1"
        if [[ ! -f "$FILE" ]]; then
            return
        fi
        if ! grep -q "$PATH_MARKER" "$FILE"; then
            return
        fi
        if [[ ! -w "$FILE" ]]; then
            echo "  [!] Cannot write to $FILE — remove the Jmap PATH block manually."
            return
        fi
        # Use awk to delete the marked block (inclusive)
        awk "/$PATH_MARKER/{found=1} !found{print} /$PATH_MARKER_END/{found=0}" \
            "$FILE" > "${FILE}.jmap_tmp" && mv "${FILE}.jmap_tmp" "$FILE"
        echo "  [✓] Removed PATH entry from $FILE"
    }

    remove_path_entry "$HOME/.bashrc.user"
    remove_path_entry "$HOME/.profile"

    if [[ $REMOVED -eq 1 ]]; then
        echo ""
        echo "  Jmap has been uninstalled."
        echo "  Open a new terminal and the 'Jmap' command will be gone."
    else
        echo ""
        echo "  Nothing to uninstall — Jmap does not appear to be installed."
    fi
    echo ""
    exit 0
fi

# ══════════════════════════════════════════════════════════════
#  INSTALL
# ══════════════════════════════════════════════════════════════
echo ""
echo "  ┌─────────────────────────────────┐"
echo "  │     Jmap Installer              │"
echo "  │     Ubuntu 22.04 LTS            │"
echo "  │     No root required            │"
echo "  └─────────────────────────────────┘"
echo ""

# ── Check Python3 ──────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "  [ERROR] python3 not found."
    echo "          Ubuntu 22.04 should include it. Try: sudo apt install python3"
    exit 1
fi

PYTHON_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "  [✓] Python $PYTHON_VER detected at $(command -v python3)"

# ── Check Jmap.py is present ───────────────────────────────────
if [[ ! -f "$SCRIPT_DIR/Jmap.py" ]]; then
    echo "  [ERROR] Jmap.py not found in $SCRIPT_DIR"
    echo "          Make sure install.sh and Jmap.py are in the same folder."
    exit 1
fi

# ── Create install directories ─────────────────────────────────
mkdir -p "$INSTALL_DIR" || { echo "  [ERROR] Could not create $INSTALL_DIR"; exit 1; }
mkdir -p "$LIB_DIR"     || { echo "  [ERROR] Could not create $LIB_DIR";     exit 1; }

# ── Copy Jmap.py ───────────────────────────────────────────────
cp "$SCRIPT_DIR/Jmap.py" "$LIB_FILE" \
    && chmod 644 "$LIB_FILE" \
    && echo "  [✓] Copied Jmap.py → $LIB_FILE" \
    || { echo "  [ERROR] Failed to copy Jmap.py"; exit 1; }

# ── Write launcher wrapper ─────────────────────────────────────
cat > "$BIN_FILE" << WRAPPER
#!/bin/bash
exec python3 "$HOME/.local/lib/Jmap.py" "\$@"
WRAPPER

chmod +x "$BIN_FILE" \
    && echo "  [✓] Created launcher  → $BIN_FILE" \
    || { echo "  [ERROR] Failed to create launcher at $BIN_FILE"; exit 1; }

# ── Add ~/.local/bin to PATH (with permission check) ──────────
PATH_NEEDS_MANUAL=0

add_to_path() {
    local FILE="$1"

    # Already has the entry — nothing to do
    if [[ -f "$FILE" ]] && grep -q 'local/bin' "$FILE"; then
        echo "  [✓] ~/.local/bin already in PATH ($FILE)"
        return 0
    fi

    # File exists but is not writable
    if [[ -f "$FILE" ]] && [[ ! -w "$FILE" ]]; then
        echo "  [!] Cannot write to $FILE (permission denied) — see manual step below"
        PATH_NEEDS_MANUAL=1
        return 1
    fi

    # Safe to write — append a clearly marked block
    {
        echo ""
        echo "$PATH_MARKER"
        echo 'export PATH="$HOME/.local/bin:$PATH"'
        echo "$PATH_MARKER_END"
    } >> "$FILE" \
        && echo "  [✓] Added ~/.local/bin to PATH in $FILE" \
        || { echo "  [!] Write to $FILE failed — see manual step below"; PATH_NEEDS_MANUAL=1; }
}

add_to_path "$HOME/.bashrc.user"
add_to_path "$HOME/.profile"

# ── Manual PATH instructions (shown only if writes failed) ────
if [[ $PATH_NEEDS_MANUAL -eq 1 ]]; then
    echo ""
    echo "  ┌─── MANUAL STEP REQUIRED ──────────────────────────────┐"
    echo "  │ One or more shell config files could not be updated.  │"
    echo "  │ Add the line below manually to your ~/.bashrc.user:        │"
    echo "  │                                                       │"
    echo "  │   export PATH=\"\$HOME/.local/bin:\$PATH\"               │"
    echo "  │                                                       │"
    echo "  │ Then run:  source ~/.bashrc.user                           │"
    echo "  └───────────────────────────────────────────────────────┘"
fi

# ── Export PATH into the current shell session immediately ─────
export PATH="$HOME/.local/bin:$PATH"

# ── Verify installation ────────────────────────────────────────
echo ""
if "$BIN_FILE" --version &>/dev/null; then
    echo "  [✓] Installation verified — Jmap is working"
else
    echo "  [ERROR] Jmap was installed but failed to run. Check your python3 path."
    exit 1
fi

echo ""
echo "  ─────────────────────────────────────────────────────"
echo "  Jmap is installed. To start using it:"
echo ""
echo "    In a NEW terminal :  Jmap --help"
echo "    In THIS terminal  :  source ~/.bashrc.user && Jmap --help"
echo ""
echo "  To uninstall later :  ./install.sh --uninstall"
echo "  ─────────────────────────────────────────────────────"
echo ""
