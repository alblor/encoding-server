# Simple LXC Deployment Guide
## Docker-in-LXC Nested Container Approach

**Author:** Lorenzo Albanese (alblor)  
**Target:** Homelab Proxmox deployment with maximum security preserved  
**Approach:** Single Alpine LXC container running Docker with existing docker-compose.secure.yml

---

## 🎯 Overview

This guide deploys your Secure Media Encoding Server using the **nested container approach** - running Docker inside an LXC container. This preserves ALL your existing security architecture while providing LXC benefits.

**Benefits:**
- ✅ **100% Security Preserved** - All AppArmor, Seccomp, Docker secrets work unchanged
- ✅ **Simple Management** - Single LXC container to backup, snapshot, migrate
- ✅ **Easy Updates** - Use existing Make commands and Docker image rebuilds
- ✅ **Proven Architecture** - Your 95.87% quality score system runs unchanged

---

## 📋 Prerequisites

**Proxmox VE Requirements:**
- Proxmox VE 7.0+ 
- 48GB+ RAM available (32GB for app, 16GB buffer)
- 8+ CPU cores
- 100GB+ storage for container
- Network connectivity

**Knowledge Requirements:**
- Basic Proxmox LXC management
- Basic Docker concepts
- Linux command line familiarity

---

## 🚀 Step 1: Create LXC Container

### 1.1 Download Alpine Template
```bash
# On Proxmox host
pveam update
pveam available | grep alpine
pveam download local alpine-3.19-default_20240207_amd64.tar.xz
```

### 1.2 Create Container
```bash
# Create UNPRIVILEGED container (more secure with Docker rootless)
pct create 200 \
  local:vztmpl/alpine-3.19-default_20240207_amd64.tar.xz \
  --hostname encoding-server \
  --memory 49152 \
  --cores 8 \
  --storage local-lvm \
  --rootfs local-lvm:20 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp \
  --unprivileged 1 \
  --features nesting=1 \
  --onboot 1
```

**Important Settings:**
- `--unprivileged 1` - Much more secure than privileged mode
- `--features nesting=1` - Enables nested containerization
- `--rootfs local-lvm:20` - 20GB storage (minimal since processing uses RAM)
- `--memory 49152` - 48GB RAM (32GB for app + buffer)
- `--cores 8` - Adjust to your hardware

**Security Benefits of Unprivileged Mode:**
- Container root is mapped to unprivileged user on host
- Better isolation from host system
- Reduced attack surface
- Compatible with Docker rootless mode

### 1.3 Start Container
```bash
pct start 200
pct enter 200
```

---

## 🔧 Step 2: Configure Alpine Linux

### 2.1 Update System
```bash
# Inside LXC container
apk update && apk upgrade
```

### 2.2 Install Essential Packages
```bash
apk add \
  docker docker-compose \
  git curl wget \
  make bash \
  openssl \
  python3 py3-pip \
  htop nano \
  shadow \
  uidmap
```

### 2.3 Configure Docker Rootless Mode
```bash
# Create regular user for Docker rootless
adduser -D encodinguser
adduser encodinguser wheel

# Configure subuid/subgid for user namespace mapping
echo "encodinguser:100000:65536" >> /etc/subuid
echo "encodinguser:100000:65536" >> /etc/subgid

# Switch to encodinguser
su - encodinguser

# Install Docker rootless
curl -fsSL https://get.docker.com/rootless | sh

# Add to PATH
echo 'export PATH=$HOME/bin:$PATH' >> ~/.bashrc
echo 'export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock' >> ~/.bashrc
source ~/.bashrc

# Start Docker rootless
systemctl --user enable docker
systemctl --user start docker

# Verify Docker is running
docker --version
docker info
```

**Security Benefits:**
- Docker daemon runs as regular user (not root)
- All containers run in user namespace
- No privileged access to host system
- Compatible with unprivileged LXC

---

## 📦 Step 3: Deploy Application

### 3.1 Get Your Codebase (as encodinguser)
```bash
# Make sure you're still the encodinguser
whoami  # Should show 'encodinguser'

# Option A: Git clone (if you have a repo)
cd /home/encodinguser
git clone <your-repo-url> encoding-server
cd encoding-server

# Option B: Copy from host/upload
# Copy your project files to /home/encodinguser/encoding-server
```

### 3.2 Generate Secrets
```bash
cd /home/encodinguser/encoding-server
./scripts/generate_secrets.sh
```

### 3.3 Build and Deploy with Rootless Docker
```bash
# Use your existing Make commands - they work with rootless Docker!
make secure-build
make secure-up

# Docker will use the rootless daemon automatically
```

**Note:** All Docker commands now run as the encodinguser, not root. This provides much better security isolation.

### 3.4 Verify Deployment
```bash
# Check containers are running
docker ps

# Check logs
make secure-logs

# Test the API (from inside LXC)
curl -k https://localhost:8443/health
```

---

## 🌐 Step 4: Network Configuration

### 4.1 Get LXC Container IP
```bash
# On Proxmox host
pct config 200 | grep net0
# Or inside container
ip addr show eth0
```

### 4.2 Configure Firewall (Proxmox Host)
```bash
# Allow HTTPS access to container
iptables -I FORWARD -p tcp --dport 8443 -d <CONTAINER_IP> -j ACCEPT

# Or configure through Proxmox GUI:
# Datacenter > Firewall > Add rule
# Direction: In
# Action: ACCEPT  
# Protocol: TCP
# Dest port: 8443
```

### 4.3 Test External Access
```bash
# From your workstation
curl -k https://<CONTAINER_IP>:8443/health
```

---

## 🔄 Step 5: Update Procedures

### 5.1 Code Updates
```bash
# Enter container
pct enter 200
cd /opt/encoding-server

# Update code (git pull or upload new files)
git pull origin main

# Rebuild and redeploy
make secure-down
make secure-build  
make secure-up
```

### 5.2 Container Snapshots (Backup/Rollback)
```bash
# On Proxmox host - Create snapshot before updates
pct snapshot 200 before-update-$(date +%Y%m%d)

# If update fails, rollback
pct rollback 200 before-update-20240904
```

### 5.3 System Updates
```bash
# Inside container
apk update && apk upgrade
# Restart if needed
reboot
```

---

## 📊 Step 6: Monitoring & Maintenance

### 6.1 Health Monitoring
```bash
# Inside container
cd /opt/encoding-server

# Run tests to verify everything works
make test-all

# Check service status
make secure-logs
```

### 6.2 Resource Monitoring
```bash
# Inside container
htop
docker stats

# On Proxmox host
pct status 200
pct config 200
```

### 6.3 Log Management
```bash
# View application logs
make secure-logs

# View Docker logs
docker logs encoding-server-secure-encoding-api-1

# System logs
dmesg
tail -f /var/log/messages
```

---

## 🛠️ Troubleshooting

### Common Issues

**1. Docker rootless won't start in LXC**
```bash
# Ensure container is unprivileged with nesting enabled
pct set 200 --unprivileged 1 --features nesting=1
pct reboot 200

# Inside container, check user namespaces
cat /etc/subuid
cat /etc/subgid

# Restart Docker rootless service
su - encodinguser
systemctl --user restart docker
```

**2. Permission denied errors**
```bash
# Make sure you're running as encodinguser, not root
whoami  # Should show 'encodinguser'

# Check Docker rootless socket
ls -la $XDG_RUNTIME_DIR/docker.sock

# If needed, restart rootless Docker
systemctl --user stop docker
systemctl --user start docker
```

**3. Cannot access from outside**
```bash
# Check container IP
ip addr show eth0

# Check firewall (on Proxmox host)
iptables -L FORWARD | grep 8443

# Verify service is running
curl -k https://localhost:8443/health
```

**4. Out of memory errors**
```bash
# Increase container memory
pct set 200 --memory 65536  # 64GB
pct reboot 200
```

**5. SSL certificate issues**
```bash
# Inside container
cd /opt/encoding-server
make cert-status

# Regenerate if needed
rm -rf certificates/enterprise/*
make secure-down && make secure-up
```

---

## 🔐 Security Notes

**What's Preserved:**
- ✅ All AppArmor profiles work unchanged
- ✅ All Seccomp filters work unchanged  
- ✅ Docker secrets integration works unchanged
- ✅ HTTPS-only operation preserved
- ✅ Memory isolation (tmpfs) preserved
- ✅ All your existing security architecture!

**Enhanced Security with Unprivileged LXC + Docker Rootless:**
- 🔒 **Double Isolation**: Unprivileged LXC + rootless Docker
- 🔒 **User Namespace Mapping**: Container root ≠ host root
- 🔒 **No Privileged Access**: Docker daemon runs as regular user
- 🔒 **Reduced Attack Surface**: Much smaller security footprint
- 🔒 **Container Isolation**: Complete separation from Proxmox host
- 🔒 **Snapshot-based Recovery**: Easy backup and rollback
- 🔒 **Resource Limits**: Enforced by Proxmox without privilege escalation

---

## 🎉 Summary

You now have:

1. **Secure LXC Container** running on Proxmox
2. **Docker inside LXC** with your proven architecture unchanged  
3. **All 95.87% quality score features preserved**
4. **Simple update process** using existing tools
5. **Easy backup/rollback** with LXC snapshots

**To access your encoding server:**
- Internal: `https://localhost:8443`  
- External: `https://<CONTAINER_IP>:8443`

**To manage:**
- Enter container: `pct enter 200`
- Use all your existing Make commands
- Updates: rebuild images or update code
- Backups: LXC snapshots

**This approach gives you the best of both worlds - LXC management benefits with your proven Docker security architecture completely preserved!**