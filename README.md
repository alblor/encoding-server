# Secure Media Encoding Server

A zero-trust, privacy-first media encoding server designed specifically for Proxmox environments, featuring dual-mode encryption, flexible FFmpeg parameter handling, and enterprise-grade security.

## Architecture Overview

This project implements a secure media encoding service using:
- **Proxmox LXC Containers**: Unprivileged containers optimized for Proxmox VE
- **Dual-Mode Encryption**: Automated (transparent) and manual encryption workflows
- **FFmpeg Parameter Engine**: Secure, flexible parameter handling with comprehensive validation
- **FastAPI + WebSocket**: Real-time API with frontend-ready SDK generation
- **Zero-Trust Security**: Complete data isolation with encrypted temporary storage

## Key Features

### 🔐 **Dual-Mode Encryption**
- **Automated Mode**: Users work with unencrypted data, server handles encryption transparently
- **Manual Mode**: Client-side encryption for untrusted operator scenarios

### 🛡️ **Enterprise Security**
- Zero plaintext exposure on server
- Complete process isolation and sandboxing  
- Encrypted RAM disk for temporary storage
- Comprehensive audit trail without sensitive data

### 🏗️ **Proxmox-Native Architecture**
- LXC container templates for rapid deployment
- ZFS integration with encrypted datasets
- VLAN networking with firewall isolation
- Proxmox Backup Server compatibility

### ⚡ **High-Performance Processing**
- Redis-based job queue with priority handling
- Real-time progress updates via WebSocket
- Concurrent job processing with resource management
- Support for complex FFmpeg operations

## Quick Start

```bash
# Clone the repository
git clone <repository-url>
cd encoding-server

# Start development environment
docker-compose -f docker-compose.dev.yml up -d

# Install client tools
pip install -r client-tools/requirements.txt

# Run tests
pytest tests/
```

## Project Structure

```
├── api/                    # FastAPI server implementation
├── client-tools/          # Encryption/decryption utilities
├── container-config/      # LXC and Proxmox configuration
│   ├── lxc/              # LXC container templates
│   ├── proxmox/          # Proxmox-specific configs
│   └── networking/       # VLAN and firewall rules
├── docs/                  # Documentation
├── tests/                 # Comprehensive test suite
├── scripts/               # Deployment and maintenance scripts
└── templates/             # Container and service templates
```

## Documentation

- [API Documentation](docs/api/) - Complete REST API reference
- [Deployment Guide](docs/deployment/) - Proxmox deployment procedures
- [Security Architecture](docs/security/) - Security model and best practices

## License

This project is designed for Lorenzo Albanese (alblor) homelab infrastructure.

---
**Author**: Lorenzo Albanese (alblor)  
**Architecture**: Proxmox-optimized secure media encoding