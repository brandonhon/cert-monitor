#!/bin/bash
# Installation script for cert-monitor

set -e

# Configuration
BINARY_NAME="cert-monitor"
SERVICE_NAME="cert-monitor"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/cert-monitor"
LOG_DIR="/var/log/cert-monitor"
CACHE_DIR="/var/lib/cert-monitor"
USER_NAME="cert-monitor"
GROUP_NAME="cert-monitor"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Detect OS and package manager
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi
    
    log_info "Detected OS: $OS $VERSION"
}

# Create user and group
create_user() {
    if ! id "$USER_NAME" &>/dev/null; then
        log_info "Creating user $USER_NAME..."
        useradd --system --shell /bin/false --home-dir /nonexistent --no-create-home "$USER_NAME"
    else
        log_info "User $USER_NAME already exists"
    fi
    
    if ! getent group "$GROUP_NAME" &>/dev/null; then
        log_info "Creating group $GROUP_NAME..."
        groupadd --system "$GROUP_NAME"
        usermod -a -G "$GROUP_NAME" "$USER_NAME"
    else
        log_info "Group $GROUP_NAME already exists"
    fi
}

# Create directories
create_directories() {
    log_info "Creating directories..."
    
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$CACHE_DIR"
    
    chown "$USER_NAME:$GROUP_NAME" "$LOG_DIR"
    chown "$USER_NAME:$GROUP_NAME" "$CACHE_DIR"
    chmod 755 "$CONFIG_DIR"
    chmod 755 "$LOG_DIR"
    chmod 755 "$CACHE_DIR"
}

# Install binary
install_binary() {
    local binary_path="$1"
    
    if [[ -z "$binary_path" ]]; then
        log_error "Binary path not provided"
        exit 1
    fi
    
    if [[ ! -f "$binary_path" ]]; then
        log_error "Binary not found at $binary_path"
        exit 1
    fi
    
    log_info "Installing binary to $INSTALL_DIR/$BINARY_NAME..."
    cp "$binary_path" "$INSTALL_DIR/$BINARY_NAME"
    chmod 755 "$INSTALL_DIR/$BINARY_NAME"
    chown root:root "$INSTALL_DIR/$BINARY_NAME"
}

# Install configuration
install_config() {
    local config_path="$1"
    
    if [[ -f "$CONFIG_DIR/config.yaml" ]]; then
        log_warn "Configuration file already exists, backing up..."
        cp "$CONFIG_DIR/config.yaml" "$CONFIG_DIR/config.yaml.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    if [[ -f "$config_path" ]]; then
        log_info "Installing configuration file..."
        cp "$config_path" "$CONFIG_DIR/config.yaml"
    else
        log_info "Creating default configuration file..."
        cat > "$CONFIG_DIR/config.yaml" <<EOF
# cert-monitor configuration
cert_dirs:
  - "/etc/ssl/certs"
  - "/usr/local/share/ca-certificates"

port: "3000"
bind_address: "0.0.0.0"
num_workers: 4
expiry_threshold_days: 30

log_file: "$LOG_DIR/cert-monitor.log"
cache_file: "$CACHE_DIR/cache.json"

enable_runtime_metrics: true
enable_weak_crypto_metrics: true
EOF
    fi
    
    chown root:root "$CONFIG_DIR/config.yaml"
    chmod 644 "$CONFIG_DIR/config.yaml"
}

# Install systemd service
install_systemd_service() {
    local service_path="$1"
    
    log_info "Installing systemd service..."
    
    if [[ -f "$service_path" ]]; then
        cp "$service_path" "/etc/systemd/system/$SERVICE_NAME.service"
    else
        # Create default service file
        cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=SSL Certificate Monitor
After=network.target
Wants=network.target

[Service]
Type=simple
User=$USER_NAME
Group=$GROUP_NAME
ExecStart=$INSTALL_DIR/$BINARY_NAME -config $CONFIG_DIR/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$LOG_DIR $CACHE_DIR

[Install]
WantedBy=multi-user.target
EOF
    fi
    
    systemctl daemon-reload
    log_info "Systemd service installed"
}

# Main installation function
install() {
    local binary_path="$1"
    local config_path="$2"
    local service_path="$3"
    
    log_info "Starting cert-monitor installation..."
    
    check_root
    detect_os
    create_user
    create_directories
    install_binary "$binary_path"
    install_config "$config_path"
    
    # Install systemd service if systemd is available
    if command -v systemctl >/dev/null 2>&1; then
        install_systemd_service "$service_path"
        
        log_info "Enabling and starting service..."
        systemctl enable "$SERVICE_NAME"
        systemctl start "$SERVICE_NAME"
        
        log_info "Service status:"
        systemctl status "$SERVICE_NAME" --no-pager -l
    else
        log_warn "Systemd not available, skipping service installation"
    fi
    
    log_info "Installation completed successfully!"
    log_info ""
    log_info "Configuration file: $CONFIG_DIR/config.yaml"
    log_info "Log file: $LOG_DIR/cert-monitor.log"
    log_info "Cache file: $CACHE_DIR/cache.json"
    log_info ""
    log_info "Service commands:"
    log_info "  Start:   systemctl start $SERVICE_NAME"
    log_info "  Stop:    systemctl stop $SERVICE_NAME"
    log_info "  Status:  systemctl status $SERVICE_NAME"
    log_info "  Reload:  systemctl reload $SERVICE_NAME"
    log_info "  Logs:    journalctl -u $SERVICE_NAME -f"
    log_info ""
    log_info "Metrics endpoint: http://localhost:3000/metrics"
    log_info "Health check:     http://localhost:3000/healthz"
}

# Uninstall function
uninstall() {
    log_info "Starting cert-monitor uninstallation..."
    
    check_root
    
    # Stop and disable service
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "Stopping service..."
        systemctl stop "$SERVICE_NAME"
    fi
    
    if systemctl is-enabled --quiet "$SERVICE_NAME"; then
        log_info "Disabling service..."
        systemctl disable "$SERVICE_NAME"
    fi
    
    # Remove service file
    if [[ -f "/etc/systemd/system/$SERVICE_NAME.service" ]]; then
        log_info "Removing systemd service..."
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload
    fi
    
    # Remove binary
    if [[ -f "$INSTALL_DIR/$BINARY_NAME" ]]; then
        log_info "Removing binary..."
        rm -f "$INSTALL_DIR/$BINARY_NAME"
    fi
    
    # Ask about configuration and data
    read -p "Remove configuration files? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        log_info "Configuration files removed"
    fi
    
    read -p "Remove log and cache files? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$LOG_DIR"
        rm -rf "$CACHE_DIR"
        log_info "Log and cache files removed"
    fi
    
    read -p "Remove user and group? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if id "$USER_NAME" &>/dev/null; then
            userdel "$USER_NAME"
            log_info "User $USER_NAME removed"
        fi
        if getent group "$GROUP_NAME" &>/dev/null; then
            groupdel "$GROUP_NAME"
            log_info "Group $GROUP_NAME removed"
        fi
    fi
    
    log_info "Uninstallation completed"
}

# Help function
show_help() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  install BINARY [CONFIG] [SERVICE]  Install cert-monitor"
    echo "  uninstall                          Uninstall cert-monitor"
    echo "  help                               Show this help"
    echo ""
    echo "Arguments:"
    echo "  BINARY   Path to cert-monitor binary (required for install)"
    echo "  CONFIG   Path to config.yaml (optional)"
    echo "  SERVICE  Path to systemd service file (optional)"
    echo ""
    echo "Examples:"
    echo "  $0 install ./cert-monitor"
    echo "  $0 install ./cert-monitor ./config.yaml"
    echo "  $0 install ./cert-monitor ./config.yaml ./deploy/cert-monitor.service"
    echo "  $0 uninstall"
}

# Main script logic
main() {
    case "${1:-}" in
        install)
            if [[ -z "$2" ]]; then
                log_error "Binary path required for installation"
                show_help
                exit 1
            fi
            install "$2" "$3" "$4"
            ;;
        uninstall)
            uninstall
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: ${1:-}"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"