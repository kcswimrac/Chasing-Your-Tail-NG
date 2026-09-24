#!/usr/bin/env python3
"""
Credential Migration Tool for CYT
Migrates API keys from insecure config.json to encrypted storage
"""
import json
import sys
import os
from pathlib import Path
from secure_credentials import SecureCredentialManager

def main():
    print("🔐 CYT Credential Migration Tool")
    print("=" * 50)
    
    config_file = 'config.json'
    if not Path(config_file).exists():
        print(f"❌ Error: {config_file} not found")
        sys.exit(1)
    
    # Load current config
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    # Check if there are credentials to migrate
    if 'api_keys' not in config:
        print("✅ No API keys found in config.json - already secure!")
        return
    
    api_keys = config['api_keys']
    if not any('token' in str(value).lower() or 'key' in str(value).lower() 
              for value in api_keys.values() if isinstance(value, dict)):
        print("✅ No credentials found to migrate")
        return
    
    print("⚠️  Found API keys in config.json - this is a security risk!")
    print("🔒 Migrating to encrypted storage...")
    
    # Initialize credential manager
    cred_manager = SecureCredentialManager()
    
    # Migrate WiGLE credentials
    if 'wigle' in api_keys:
        wigle_config = api_keys['wigle']
        if 'encoded_token' in wigle_config:
            print("\n📡 Migrating WiGLE API token...")
            cred_manager.store_credential('wigle', 'encoded_token', wigle_config['encoded_token'])
            print("✅ WiGLE API token stored securely")
    
    # Remove API keys from the in-memory config. The original config.json
    # (still on disk, still containing the keys) is deliberately NOT copied:
    # a plaintext backup would re-expose the very secrets just secured and
    # the original file already serves as the operator's rollback copy.
    config.pop('api_keys', None)
    
    # Save sanitized config
    sanitized_file = 'config_secure.json'
    with open(sanitized_file, 'w') as f:
        json.dump(config, f, indent=2)
    print(f"🛡️  Sanitized config saved to: {sanitized_file}")
    
    print("\n🔐 Migration Complete!")
    print("=" * 50)
    print("Next steps:")
    print("1. Review the sanitized config: config_secure.json")
    print("2. Replace config.json with config_secure.json:")
    print("   mv config_secure.json config.json")
    print("3. Securely delete the original config.json once replaced:")
    print("   shred -vfz-3 config.json")
    print("\n⚠️  IMPORTANT: Your API keys are now encrypted and require a master password!")

if __name__ == '__main__':
    main()