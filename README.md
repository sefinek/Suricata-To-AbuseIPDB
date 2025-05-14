# 🛡️ Suricata AbuseIPDB Reporter
An integration tool designed to analyze Suricata logs and report IP addresses to the [AbuseIPDB](https://www.abuseipdb.com) database.  
To prevent excessive reporting of the same IP address within a short time period, the tool uses a temporary cache file to track previously reported IP addresses.

⭐ If you like this repository or find it useful, I'd greatly appreciate it if you could give it a star. Many thanks!  
🧱 Also, check this out: [sefinek/Cloudflare-WAF-To-AbuseIPDB](https://github.com/sefinek/Cloudflare-WAF-To-AbuseIPDB)

> [!IMPORTANT]
> - If you'd like to make changes to any files in this repository, please start by creating a [public fork](https://github.com/sefinek/Suricata-To-AbuseIPDB/fork).


## 📋 Requirements
- [Node.js + npm](https://gist.github.com/sefinek/fb50041a5f456321d58104bbf3f6e649)
- [PM2](https://www.npmjs.com/package/pm2) (`npm i -g pm2`)
- [Git](https://gist.github.com/sefinek/1de50073ffbbae82fc901506304f0ada)
- Linux (Ubuntu or Debian)


## ✅ Features
1. **Easy Configuration** – The [`config.js`](config.default.js) file allows for quick and simple configuration.
2. **Simple Installer** – Enables fast and seamless integration deployment.
3. **Bulk Reporting Support** – If the script encounters a rate limit, it will start buffering collected IPs and send a bulk report.
4. **Self-IP Protection (IPv4 & IPv6)** – The script will never report IP addresses belonging to you or your server, even if you're using a dynamic IP address.
5. **Local IP Filtering** – Local IP addresses will never be reported.
6. **Discord Webhooks Integration**:
    - Critical notifications
    - Script error alerts
    - Daily summaries of reported IPs
7. **Automatic Updates** – The script regularly fetches and applies the latest updates. You can disable this feature if you'd prefer.


## 📥 Installation (Ubuntu & Debian)

### Install Node.js
```bash
sudo apt install -y curl && \
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && \
sudo apt install -y nodejs
```

### Install Git
```bash
sudo add-apt-repository -y ppa:git-core/ppa && \
sudo apt update && sudo apt install -y git
```

### Clone & Set up
```bash
sudo apt update && sudo apt upgrade
cd ~
git clone --recurse-submodules https://github.com/sefinek/Suricata-To-AbuseIPDB.git
cd Suricata-To-AbuseIPDB
npm install
cp config.default.js config.js
npm install -g pm2
pm2 start .
eval "$(pm2 startup | grep sudo)"
pm2 save
```

### 🔍 Check Logs
```bash
pm2 logs suricata-abuseipdb
```

### 📄 Example Reports
```text

```


## 🤝 Development
If you want to contribute to the development of this project, feel free to create a new [Pull request](https://github.com/sefinek/Suricata-To-AbuseIPDB/pulls). I will definitely appreciate it!


## 🔑 [GPL-3.0 License](LICENSE)
Copyright 2025 © by [Sefinek](https://sefinek.net). All rights reserved.