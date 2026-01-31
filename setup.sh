#!/bin/bash

# DevilNet Setup Script
# Installs dependencies and creates a global 'devilnet' command.

# Function to print status
print_status() {
    echo -e "\033[1;34m[*]\033[0m $1"
}

print_success() {
    echo -e "\033[1;32m[+]\033[0m $1"
}

print_error() {
    echo -e "\033[1;31m[!]\033[0m $1"
}

# 1. Check for Python 3
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install it first."
    exit 1
fi

# 2. Install Dependencies
print_status "Installing Python dependencies from requirements.txt..."
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        print_error "Failed to install dependencies. Try running with sudo or check your internet connection."
        # We continue, as they might have them installed system-wide already
    else
        print_success "Dependencies installed."
    fi
else
    print_error "requirements.txt not found!"
    exit 1
fi

# 3. Create the executable wrapper
PROJECT_DIR="$(pwd)"
INSTALL_NAME="devilnet"
BIN_PATH="/usr/local/bin"

print_status "Creating '$INSTALL_NAME' command..."

# Create the wrapper script content
cat <<EOF > "$INSTALL_NAME"
#!/bin/bash
# DevilNet Wrapper
# Executing from: $PROJECT_DIR

# Ensure we use python3
PYTHON_CMD="python3"

# Check if running as root (often needed for network operations)
if [ "\$EUID" -ne 0 ]; then
  echo "Warning: DevilNet often requires root privileges for network scanning/spoofing."
  echo "You might need to run: sudo $INSTALL_NAME \$@"
fi

# Set PYTHONPATH to ensure imports work correctly
export PYTHONPATH="$PROJECT_DIR:\$PYTHONPATH"

# Execute the main script
exec "\$PYTHON_CMD" "$PROJECT_DIR/network_monitor/main.py" "\$@"
EOF

# Make it executable
chmod +x "$INSTALL_NAME"

# 4. Move to system bin
print_status "Installing to $BIN_PATH (requires sudo)..."

if sudo mv "$INSTALL_NAME" "$BIN_PATH/$INSTALL_NAME"; then
    print_success "Successfully installed '$INSTALL_NAME'!"
    echo ""
    echo "Usage:"
    echo "  sudo $INSTALL_NAME          # Run CLI mode"
    echo "  sudo $INSTALL_NAME --web    # Run Web UI mode"
    echo "  sudo $INSTALL_NAME --help   # Show options"
else
    print_error "Failed to move script to $BIN_PATH."
    rm -f "$INSTALL_NAME"
    exit 1
fi
