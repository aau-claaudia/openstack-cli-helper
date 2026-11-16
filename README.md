# openstack-cli-helper
Scripts for helping using the OpenStack CLI and managing instances on AAU Strato Cloud (`strato-new.claaudia.aau.dk`).

## 1. Get Access Token (Authentication)

Download or clone the library:

```bash
curl --output strato-login.py https://raw.githubusercontent.com/aau-claaudia/openstack-cli-helper/refs/heads/main/strato-login.py
```

Get the token and generate your `strato-openrc.sh`:

```bash
python3 -u strato-login.py
```

Load your credentials into your shell session:

```bash
source strato-openrc.sh
```

*(Optional) Install standard OpenStack CLI:*

```bash
pip3 install python-openstackclient
```

---

## 2. Create Instances (`strato-create-instance.py`)

Provision OpenStack instances with project quota checking, automatic SSH keypair creation, network configuration, and public floating IP assignment.

### Features
- **Project Quota Aware**: Evaluates vCPUs, RAM, and instance limits before launching to prevent out-of-quota errors.
- **SSH Keypair Automation**: If no keypair exists in OpenStack (or a new one is requested), it generates the keypair via OpenStack API and saves the private key locally (`~/.ssh/<key_name>.pem` with secure permissions `chmod 0600`).
- **Dynamic Interactive CLI**: Step-by-step guided wizard (like `strato-login.py`) with defaults and quota availability indicators.
- **One-Command Setup**: Single-line automated provisioning for scripting and CI/CD pipelines.
- **Floating IP**: Automatically allocates and binds a public floating IP.
- **Zero External Dependencies**: Works out-of-the-box with standard Python 3.6+ (or `requests` if installed).

### Usage

#### Dynamic Interactive Mode (Wizard)
Simply run the script to launch the interactive selection wizard:

```bash
python3 strato-create-instance.py
```

The wizard will display your project quota, guide you through choosing an image, flavor (flagging any that exceed your quota), network, SSH key, and public IP, then launch the VM and output the SSH command.

#### One-Command Setup (Non-Interactive)
Launch an instance directly in a single command:

```bash
python3 strato-create-instance.py --name my-vm --image "Ubuntu 24.04" --flavor m1.small --yes
```

#### Opening Custom Ports & Port Ranges
You can specify ports or port ranges to automatically open in the instance's security group (supports single ports, ranges, and TCP/UDP):

```bash
# Open web ports (80, 443) and a port range (8000 to 8080)
python3 strato-create-instance.py --name web-vm --ports "80, 443, 8000-8080" --yes

# Specify UDP ports (e.g. DNS or custom service)
python3 strato-create-instance.py --name dns-vm --ports "53/udp, 5000-5050/udp" --yes
```

*(In interactive wizard mode, Step 6 also prompts you for any additional ports or port ranges).*

If the specified keypair doesn't exist in OpenStack, the script automatically creates it and saves the private key to `~/.ssh/<key_name>.pem`.

#### Useful Discovery Flags
Inspect available resources and project limits without launching:

```bash
# View project resource quotas and usage
python3 strato-create-instance.py --list-quota

# View available compute flavors with quota compatibility status
python3 strato-create-instance.py --list-flavors

# View active OS images
python3 strato-create-instance.py --list-images

# View project networks
python3 strato-create-instance.py --list-networks

# View registered SSH keypairs
python3 strato-create-instance.py --list-keys

# List active project instances
python3 strato-create-instance.py --list-instances

# Dry-run validation
python3 strato-create-instance.py --name test-vm --image ubuntu --flavor m1.small --dry-run
```

---

## 3. Manage Instances (`strato-manage-instance.py`)

Stop, start, reboot, or delete existing instances and automatically clean up associated public floating IPs.

### Interactive Management Console
Run without arguments to launch the interactive management dashboard:

```bash
python3 strato-manage-instance.py
```

This presents a numbered list of all instances in your project and allows you to stop, start, reboot, or delete any selected instance.

### One-Command Quick Actions

```bash
# List instances with IP addresses and status
python3 strato-manage-instance.py --list

# Stop an instance (power off)
python3 strato-manage-instance.py --stop my-vm

# Start an instance (power on)
python3 strato-manage-instance.py --start my-vm

# Soft reboot an instance
python3 strato-manage-instance.py --reboot my-vm

# Permanently delete an instance and release its floating IP
python3 strato-manage-instance.py --delete my-vm --yes
```

*(Note: `--stop`, `--start`, `--delete`, and `--list-instances` are also available directly on `strato-create-instance.py`)*

