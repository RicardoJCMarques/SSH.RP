# Key Management

SSH.RP needs two Ed25519 keys. Both are created with `ssh-keygen` and pasted into `include/keys.h`, which is compiled into the firmware.

| Key | Purpose | What goes into `keys.h` |
| :--- | :--- | :--- |
| Your login key (`id_ed25519`) | Lets you log in | The content of `id_ed25519.pub`. The private key stays on your PC |
| Board host key (`host_key`) | Identifies the board | The content of `host_key`, the private key |

Both are stored in an `sshrp` folder inside your user's `.ssh` folder (`C:\Users\<you>\.ssh\sshrp` on Windows).

**What you need:** the OpenSSH client (`ssh` and `ssh-keygen`), which comes with Windows 10/11, macOS and Linux. Any terminal works.

---

## 1. Create the keys

Open a terminal and go to the key folder, creating it first:

| Terminal | Commands |
| :--- | :--- |
| Command Prompt | `mkdir %USERPROFILE%\.ssh\sshrp` then `cd %USERPROFILE%\.ssh\sshrp` |
| PowerShell (the default VS Code terminal on Windows) | `mkdir ~\.ssh\sshrp` then `cd ~\.ssh\sshrp` |
| Git Bash, macOS, Linux | `mkdir -p ~/.ssh/sshrp` then `cd ~/.ssh/sshrp` |

If the folder already exists, `mkdir` reports an error; ignore it.

Then create the two keys:

```text
ssh-keygen -t ed25519 -f id_ed25519 -C sshrp
ssh-keygen -t ed25519 -f host_key -C sshrp-board
```

Each command asks for a passphrase twice:

- `id_ed25519`: set one, or press Enter twice for none.
- `host_key`: **press Enter twice.** The board can't use a host key that has a passphrase.

The folder now holds `id_ed25519`, `id_ed25519.pub`, `host_key` and `host_key.pub`.

---

## 2. Fill in `keys.h`

1. In the repository, copy `include/keys.h.example` to `include/keys.h`.
2. Open `host_key` (the file without `.pub`) in a text editor such as VS Code or Notepad. Copy all of it and paste it over the three placeholder lines of `SSH_HOST_KEY`, between `R"KEY(` and `)KEY"`.
3. Open `id_ed25519.pub`, copy its single line, and paste it over the placeholder line of `SSH_AUTHORIZED_KEY`.
4. Optional: to also allow password login, uncomment the `SSH_PASSWORD` line and set a password.

The result looks like this:

```cpp
static const char SSH_HOST_KEY[] = R"KEY(
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
...four more lines...
-----END OPENSSH PRIVATE KEY-----
)KEY";

static const char SSH_AUTHORIZED_KEY[] = R"KEY(
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... sshrp
)KEY";
```

Then build and upload the firmware (see the [README](../README.md#5-build-and-upload)).

> `keys.h` contains the board's private key. `.gitignore` keeps it out of commits; don't force-add it or share it.

---

## 3. Connect

```text
ssh -i ~/.ssh/sshrp/id_ed25519 sshrp@192.168.1.120
```

Use the address set in `BOARD_IP` in `src/main.cpp`. `ssh` expands the `~` itself, so the command works in every terminal.

- **First connection:** OpenSSH shows the board's fingerprint and asks whether to continue. Answer `yes`; it then remembers the board. To check the fingerprint first, run `ssh-keygen -lf host_key.pub` in the key folder and compare.
- **Password login** (only if `SSH_PASSWORD` is set): `ssh -o PreferredAuthentications=password sshrp@192.168.1.120`
- **Post-quantum warning:** OpenSSH 10.1 and newer print `WARNING: connection is not using a post-quantum key exchange algorithm`. It's expected, because the board supports `curve25519-sha256` only. Add `-o WarnWeakCrypto=no-pq-kex` to hide it, or use the config in step 4.

---

## 4. Optional: shorter `ssh` command

`ssh` only tries its default key files (such as `~/.ssh/id_ed25519`) and keys loaded in ssh-agent, which is why step 3 needs `-i`. To connect with just `ssh sshrp@192.168.0.120`, or `ssh sshrp`, add this block to your SSH config file, `~/.ssh/config` (`C:\Users\<you>\.ssh\config` on Windows; create it if it doesn't exist):

```text
# SSH.RP board
Host sshrp 192.168.1.120
    HostName 192.168.1.120
    User admin
    IdentitiesOnly yes
    IdentityFile ~/.ssh/sshrp/id_ed25519
    # Optional: hide the post-quantum warning of OpenSSH 10.1+
    IgnoreUnknown WarnWeakCrypto
    WarnWeakCrypto no-pq-kex
```

- `IdentitiesOnly yes` makes `ssh` offer only this key, not every key in ssh-agent.
- The `~` path works with both the Windows `ssh` and the Git Bash `ssh`, so one `IdentityFile` line covers both.
- If you change `BOARD_IP`, change both addresses here too.

---

## Troubleshooting

| Problem | Fix |
| :--- | :--- |
| `Connection refused` | The board is on the network, but its SSH server didn't start because a key in `keys.h` is invalid (the serial monitor names which). Usually `host_key` has a passphrase: recreate it, pressing Enter at both prompts, and paste it again. The line after `-----BEGIN OPENSSH PRIVATE KEY-----` must start with `b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ`. |
| `Permission denied (publickey…)` | `keys.h` doesn't contain the `id_ed25519.pub` of the key you're using, or the user isn't `admin`. Redo step 2, then rebuild and upload. |
| `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED` | The board has a new host key, or another device now has its address. If you changed the host key, run `ssh-keygen -R 192.168.1.120` and connect again. |
| `no matching cipher found` | Something forces a cipher the board doesn't support, such as `chacha20-poly1305@openssh.com` (in `~/.ssh/config` or an `-o Ciphers=` option). Remove it. |