"""
TLS/HTTPS Configuration and Certificate Management System
Provides comprehensive transport security for the media encoding server.

Author: Lorenzo Albanese (alblor)
"""

import os
import ssl
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import subprocess
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)


class TLSManager:
    """Manages TLS certificates and SSL context for secure transport."""
    
    def __init__(self, cert_dir: str = "/tmp/memory-pool/certs"):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        
        # Docker secrets directory (highest priority)
        self.secrets_dir = Path("/run/secrets")
        
        # Enterprise certificate directory (persistent)
        self.enterprise_cert_dir = Path("/opt/enterprise-certs")
        
        # Certificate paths (temporary)
        self.cert_file = self.cert_dir / "server.crt"
        self.key_file = self.cert_dir / "server.key"
        self.ca_file = self.cert_dir / "ca.crt"
        
        # Docker secrets certificate paths (highest priority)
        self.secrets_cert_file = self.secrets_dir / "tls_cert"
        self.secrets_key_file = self.secrets_dir / "tls_key"
        
        # Enterprise certificate paths
        self.enterprise_cert_file = self.enterprise_cert_dir / "server.crt"
        self.enterprise_key_file = self.enterprise_cert_dir / "server.key"
        
        # TLS configuration
        self.tls_version = ssl.TLSVersion.TLSv1_2  # Minimum TLS 1.2
        self.cipher_suites = [
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256", 
            "ECDHE-RSA-AES256-SHA384",
            "ECDHE-RSA-AES128-SHA256",
            "DHE-RSA-AES256-GCM-SHA384",
            "DHE-RSA-AES128-GCM-SHA256"
        ]
    
    def generate_self_signed_cert(self, 
                                  common_name: str = "localhost",
                                  alt_names: list = None,
                                  days_valid: int = 365) -> bool:
        """Generate a self-signed certificate for development use."""
        try:
            logger.info("🔐 Generating self-signed TLS certificate for development")
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Media Encoding"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=days_valid)
            )
            
            # Add Subject Alternative Names
            if not alt_names:
                alt_names = ["localhost", "127.0.0.1", "::1"]
            
            san_list = []
            for name in alt_names:
                try:
                    # Try as IP address first
                    import ipaddress
                    ip = ipaddress.ip_address(name)
                    san_list.append(x509.IPAddress(ip))
                except ValueError:
                    # Not an IP, treat as DNS name
                    san_list.append(x509.DNSName(name))
            
            cert = cert.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )
            
            # Add key usage extensions
            cert = cert.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=False,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            )
            
            cert = cert.add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                ]),
                critical=True,
            )
            
            # Sign the certificate
            cert = cert.sign(private_key, hashes.SHA256())
            
            # Save certificate and private key
            with open(self.cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open(self.key_file, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Set secure permissions
            os.chmod(self.cert_file, 0o644)
            os.chmod(self.key_file, 0o600)
            
            logger.info("✅ Self-signed certificate generated successfully")
            logger.info(f"📜 Certificate: {self.cert_file}")
            logger.info(f"🗝️  Private key: {self.key_file}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to generate self-signed certificate: {e}")
            return False
    
    def get_ssl_context_from_secrets(self) -> Optional[ssl.SSLContext]:
        """
        Create SSL context from Docker secrets certificates.
        
        Returns:
            SSL context if secrets are available, None otherwise
        """
        if not (self.secrets_cert_file.exists() and self.secrets_key_file.exists()):
            logger.debug("Docker secrets certificates not available")
            return None
            
        try:
            logger.info("🔐 Loading TLS certificates from Docker secrets")
            
            # Create SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = self.tls_version
            
            # Load certificate and key from secrets
            context.load_cert_chain(
                certfile=str(self.secrets_cert_file),
                keyfile=str(self.secrets_key_file)
            )
            
            # Set cipher suites for security
            context.set_ciphers(':'.join(self.cipher_suites))
            
            # Security settings
            context.options |= ssl.OP_NO_SSLv2
            context.options |= ssl.OP_NO_SSLv3
            context.options |= ssl.OP_NO_TLSv1
            context.options |= ssl.OP_NO_TLSv1_1
            context.options |= ssl.OP_SINGLE_DH_USE
            context.options |= ssl.OP_SINGLE_ECDH_USE
            
            logger.info("✅ SSL context created successfully from Docker secrets")
            return context
            
        except Exception as e:
            logger.error(f"Failed to create SSL context from Docker secrets: {e}")
            return None
    
    def validate_certificate(self, renewal_threshold_days: int = 7) -> bool:
        """Validate existing certificate and key files with automatic renewal logic."""
        try:
            if not self.cert_file.exists() or not self.key_file.exists():
                logger.warning("📋 Certificate files not found - will generate new certificate")
                return False
            
            # Load and validate certificate
            with open(self.cert_file, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            
            # Check expiration with renewal threshold
            now = datetime.utcnow()
            renewal_date = now + timedelta(days=renewal_threshold_days)
            
            if cert.not_valid_after < now:
                logger.error("⏰ Certificate has expired - automatic renewal required")
                return False
            
            if cert.not_valid_after < renewal_date:
                logger.warning(f"🔄 Certificate expires within {renewal_threshold_days} days - automatic renewal triggered")
                logger.warning(f"📅 Expiry date: {cert.not_valid_after.isoformat()}")
                return False
            
            # Load and validate private key
            with open(self.key_file, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            
            # Verify key matches certificate
            public_key = cert.public_key()
            if public_key.public_numbers() != private_key.public_key().public_numbers():
                logger.error("🔑 Private key does not match certificate - regeneration required")
                return False
            
            days_until_expiry = (cert.not_valid_after - now).days
            logger.info(f"✅ Certificate validation successful - valid for {days_until_expiry} more days")
            return True
            
        except Exception as e:
            logger.error(f"❌ Certificate validation failed: {e} - will regenerate")
            return False
    
    def load_enterprise_certificates(self) -> bool:
        """Load enterprise certificates if available and valid."""
        try:
            if not (self.enterprise_cert_file.exists() and self.enterprise_key_file.exists()):
                logger.debug("🏢 No enterprise certificates found - using self-signed")
                return False
            
            logger.info("🏢 Enterprise certificates detected - validating...")
            
            # Validate enterprise certificate format
            with open(self.enterprise_cert_file, "rb") as f:
                enterprise_cert = x509.load_pem_x509_certificate(f.read())
            
            # Check expiration
            now = datetime.utcnow()
            if enterprise_cert.not_valid_after < now:
                logger.warning("⚠️  Enterprise certificate expired - falling back to self-signed")
                return False
            
            # Validate private key
            with open(self.enterprise_key_file, "rb") as f:
                enterprise_private_key = serialization.load_pem_private_key(f.read(), password=None)
            
            # Verify key matches certificate
            if enterprise_cert.public_key().public_numbers() != enterprise_private_key.public_key().public_numbers():
                logger.error("🔑 Enterprise private key does not match certificate - falling back to self-signed")
                return False
            
            # Copy valid enterprise certificates to working directory
            import shutil
            shutil.copy2(self.enterprise_cert_file, self.cert_file)
            shutil.copy2(self.enterprise_key_file, self.key_file)
            
            # Set secure permissions
            os.chmod(self.cert_file, 0o644)
            os.chmod(self.key_file, 0o600)
            
            days_until_expiry = (enterprise_cert.not_valid_after - now).days
            logger.info(f"✅ Enterprise certificate loaded successfully - valid for {days_until_expiry} more days")
            logger.info(f"🏢 Subject: {enterprise_cert.subject.rfc4514_string()}")
            
            return True
            
        except Exception as e:
            logger.warning(f"⚠️  Failed to load enterprise certificates: {e} - falling back to self-signed")
            return False
    
    def ensure_valid_certificate(self, 
                                common_name: str = "localhost",
                                alt_names: list = None,
                                renewal_threshold_days: int = 7,
                                force_regenerate: bool = False) -> bool:
        """Ensure a valid certificate exists, generating if needed (container-restart safe)."""
        try:
            logger.info("🔍 Checking certificate validity on startup...")
            
            if force_regenerate:
                logger.info("🔄 Forced certificate regeneration requested")
                needs_generation = True
            else:
                # First priority: Try to load enterprise certificates
                if self.load_enterprise_certificates():
                    logger.info("✅ Enterprise certificates loaded - skipping self-signed generation")
                    return True
                
                # Fallback: Check existing self-signed certificates
                needs_generation = not self.validate_certificate(renewal_threshold_days)
            
            if needs_generation:
                logger.info("🔧 Generating new TLS certificate...")
                
                # Backup existing certificate if it exists
                if self.cert_file.exists():
                    backup_cert = self.cert_dir / f"server.crt.backup.{int(datetime.utcnow().timestamp())}"
                    backup_key = self.cert_dir / f"server.key.backup.{int(datetime.utcnow().timestamp())}"
                    
                    try:
                        import shutil
                        shutil.copy2(self.cert_file, backup_cert)
                        shutil.copy2(self.key_file, backup_key)
                        logger.info(f"💾 Backed up existing certificate to {backup_cert.name}")
                    except Exception as backup_error:
                        logger.warning(f"⚠️  Could not backup existing certificate: {backup_error}")
                
                # Generate new certificate
                success = self.generate_self_signed_cert(
                    common_name=common_name,
                    alt_names=alt_names,
                    days_valid=365
                )
                
                if success:
                    logger.info("✅ Certificate regeneration completed successfully")
                    return True
                else:
                    logger.error("❌ Certificate regeneration failed")
                    return False
            else:
                logger.info("✅ Existing certificate is valid and current")
                return True
                
        except Exception as e:
            logger.error(f"❌ Certificate validation/generation failed: {e}")
            return False
    
    def get_ssl_context(self, force_regenerate: bool = False) -> Optional[ssl.SSLContext]:
        """
        Create and configure SSL context for secure transport.
        
        Priority order:
        1. Docker secrets certificates (production)
        2. Enterprise certificates (persistent)
        3. Self-signed certificates (fallback)
        """
        try:
            # First priority: Try Docker secrets certificates
            if not force_regenerate:
                secrets_context = self.get_ssl_context_from_secrets()
                if secrets_context:
                    logger.info("✅ Using TLS certificates from Docker secrets")
                    return secrets_context
            
            # Fallback: Ensure certificate exists and is valid (with automatic renewal)
            if not self.ensure_valid_certificate(force_regenerate=force_regenerate):
                logger.error("❌ Failed to ensure valid SSL certificate")
                return None
            
            logger.info("🔧 Creating SSL context from generated/enterprise certificates")
            
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            
            # Configure TLS version and ciphers
            context.minimum_version = self.tls_version
            context.set_ciphers(':'.join(self.cipher_suites))
            
            # Load certificate and key
            context.load_cert_chain(
                certfile=str(self.cert_file),
                keyfile=str(self.key_file)
            )
            
            # Additional security settings
            context.check_hostname = False  # We handle this in FastAPI
            context.verify_mode = ssl.CERT_NONE  # Client auth not required
            
            # Enable session tickets for performance
            context.options |= ssl.OP_SINGLE_DH_USE
            context.options |= ssl.OP_SINGLE_ECDH_USE
            
            # Disable insecure options
            context.options |= ssl.OP_NO_SSLv2
            context.options |= ssl.OP_NO_SSLv3
            context.options |= ssl.OP_NO_TLSv1
            context.options |= ssl.OP_NO_TLSv1_1
            
            logger.info("🔐 SSL context created successfully")
            logger.info(f"📋 TLS version: {context.minimum_version}")
            logger.info(f"🔐 Cipher suites: {len(self.cipher_suites)} configured")
            
            return context
            
        except Exception as e:
            logger.error(f"❌ Failed to create SSL context: {e}")
            return None
    
    def get_certificate_info(self) -> Dict[str, Any]:
        """Get information about the current certificate."""
        try:
            if not self.cert_file.exists():
                return {"status": "no_certificate"}
            
            with open(self.cert_file, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            
            # Extract certificate information
            subject = cert.subject
            issuer = cert.issuer
            
            return {
                "status": "valid",
                "subject": subject.rfc4514_string(),
                "issuer": issuer.rfc4514_string(),
                "serial_number": str(cert.serial_number),
                "not_valid_before": cert.not_valid_before.isoformat(),
                "not_valid_after": cert.not_valid_after.isoformat(),
                "is_self_signed": subject == issuer,
                "days_until_expiry": (cert.not_valid_after - datetime.utcnow()).days,
                "signature_algorithm": cert.signature_hash_algorithm.name,
            }
            
        except Exception as e:
            return {"status": "error", "message": str(e)}


# Global TLS manager instance
tls_manager = TLSManager()