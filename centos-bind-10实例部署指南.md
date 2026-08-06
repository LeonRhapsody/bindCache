# 2核2G云主机 — 10个CentOS容器 + BIND DNS 部署指南

---

## ⚠️ 前置说明：可行性分析

| 资源 | 总量 | 单实例预估 | 10实例需求 | 是否可行 |
|------|------|-----------|-----------|---------|
| CPU | 2核 | 0.1核 (轻载BIND) | ~1核 | ✅ |
| 内存 | 2GB | 150-200MB (CentOS+BIND) | 1.5-2GB | ⚠️ 非常紧张 |
| 磁盘 | 视云主机而定 | ~500MB/容器 | ~5GB | ✅ |

> **结论**：只能用 **Docker 容器**方案，不能跑完整虚拟机。10个BIND实例会把2GB内存吃满，建议每个容器的 BIND 做**最小化配置**（关闭不必要的功能），或先起 5 个测试。

---

## 一、环境准备

### 1.1 云主机基础配置

```bash
# 连接到云主机
ssh root@你的云主机公网IP

# 查看系统信息
cat /etc/os-release
free -h          # 确认内存
lscpu            # 确认CPU
df -h            # 确认磁盘

# 关闭 SELinux（避免权限问题）
setenforce 0
sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config

# 关闭 firewalld（或用 iptables，按需选择）
systemctl stop firewalld
systemctl disable firewalld
```

### 1.2 安装 Docker

```bash
# ===== 方式A：CentOS 7 =====
yum install -y yum-utils
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
yum install -y docker-ce docker-ce-cli containerd.io

# ===== 方式B：CentOS 8 / Stream =====
dnf install -y dnf-plugins-core
dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
dnf install -y docker-ce docker-ce-cli containerd.io

# 启动 Docker
systemctl start docker
systemctl enable docker
docker --version   # 确认安装成功
```

### 1.3 拉取 CentOS 基础镜像

```bash
docker pull centos:7
# 如果 centos:7 拉不到（已停止维护），改用：
# docker pull centos:centos7.9.2009
# 或者用 Rocky Linux 替代：
# docker pull rockylinux:8
```

---

## 二、目录规划

```bash
# 创建统一的管理目录
mkdir -p /data/bind-cluster/{configs,data,zones,scripts}

# 为 10 个实例创建独立目录
for i in $(seq 1 10); do
    mkdir -p /data/bind-cluster/data/ns${i}/{etc,var,log}
done

# 目录结构一览
# /data/bind-cluster/
# ├── configs/          # 各实例的 named.conf
# │   ├── ns1.conf
# │   ├── ns2.conf
# │   └── ...
# ├── data/             # 各实例运行时数据
# │   ├── ns1/
# │   │   ├── etc/      # BIND 配置挂载
# │   │   ├── var/      # BIND 数据文件（zone file 等）
# │   │   └── log/      # 日志
# │   ├── ns2/
# │   └── ...
# ├── zones/            # 共享的 zone 文件（可选）
# └── scripts/          # 管理脚本
```

---

## 三、创建 Docker 网络

由于 10 个 BIND 实例不能同时占用宿主机 53 端口，这里提供两种方案：

### 方案A：宿主机端口映射（推荐，简单）

每个 BIND 实例映射到宿主机的不同端口：

```bash
# 创建专用桥接网络
docker network create \
    --subnet=172.20.0.0/16 \
    --gateway=172.20.0.1 \
    bind-net
```

### 方案B：macvlan 网络（高级，每个容器独立IP）

如果云主机支持多IP：

```bash
# 假设宿主机网卡为 eth0，网段为 10.0.0.0/24
docker network create -d macvlan \
    --subnet=10.0.0.0/24 \
    --gateway=10.0.0.1 \
    -o parent=eth0 \
    bind-macvlan
```

> 本文档以 **方案A** 为例，10个实例分别映射 5301-5310 端口。

---

## 四、生成 BIND 配置文件

### 4.1 创建每个实例的 named.conf

```bash
cd /data/bind-cluster/configs

for i in $(seq 1 10); do
    cat > ns${i}.conf << 'INNER_EOF'
options {
    directory       "/var/named";
    pid-file        "/var/run/named/named.pid";
    session-keyfile "/var/run/named/session.key";

    // 监听所有地址
    listen-on       port 53 { any; };
    listen-on-v6    port 53 { none; };

    // 允许查询来源（按需调整）
    allow-query     { any; };

    // 不允许递归（纯权威DNS）
    recursion       no;

    // 允许区域传输来源
    allow-transfer  { none; };

    // 最小化响应，减少内存
    minimal-responses yes;

    // ===== 内存控制（2G小内存刚需） =====
    max-cache-size  10M;        // 限制缓存大小
    max-cache-ttl   300;        // 最大缓存 5 分钟
};

// 日志
logging {
    channel default_log {
        file "/var/log/named.log" versions 1 size 5m;
        severity info;
        print-time yes;
    };
    category default { default_log; };
};

// 引入 zone 文件
include "/etc/named/named.zones";
INNER_EOF
done
```

### 4.2 创建每个实例的 zone 配置

```bash
for i in $(seq 1 10); do
    cat > /data/bind-cluster/configs/named.zones.ns${i} << INNER_EOF
// ===== ns${i} 的 Zone 配置 =====
// 示例：每个实例解析一个不同的域名

zone "example${i}.local" IN {
    type master;
    file "/var/named/example${i}.local.zone";
    allow-update { none; };
};

// 反向解析（可选）
zone "0.20.172.in-addr.arpa" IN {
    type master;
    file "/var/named/db.172.20.0";
};
INNER_EOF
done
```

### 4.3 生成 Zone 数据文件

```bash
for i in $(seq 1 10); do
    cat > /data/bind-cluster/data/ns${i}/var/example${i}.local.zone << INNER_EOF
\$TTL 86400
@   IN  SOA ns${i}.example${i}.local. admin.example${i}.local. (
        $(date +%Y%m%d)01   ; Serial
        3600                ; Refresh
        1800                ; Retry
        604800              ; Expire
        86400               ; Minimum TTL
)
    IN  NS  ns${i}.example${i}.local.

ns${i}  IN  A   172.20.0.$((i + 10))    ; 容器内网IP
www     IN  A   172.20.0.$((i + 10))
app     IN  A   172.20.0.$((i + 10))
INNER_EOF
done
```

---

## 五、构建自定义 Docker 镜像

创建一个包含 BIND + SSH + 多用户的镜像。

### 5.1 编写 Dockerfile

```bash
cat > /data/bind-cluster/Dockerfile << 'DOCKERFILE_EOF'
FROM centos:7

# 安装 BIND、SSH 服务、基础工具
RUN yum install -y epel-release && \
    yum install -y \
        bind bind-utils \
        openssh-server \
        sudo passwd which vim net-tools \
        procps-ng iproute && \
    yum clean all && \
    rm -rf /var/cache/yum

# SSH 配置
RUN ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N '' && \
    ssh-keygen -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key -N '' && \
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N '' && \
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config

# 创建 BIND 运行目录
RUN mkdir -p /var/run/named && \
    chown named:named /var/run/named && \
    mkdir -p /var/log/named && \
    chown named:named /var/log/named

# 启动脚本
RUN echo '#!/bin/bash' > /entrypoint.sh && \
    echo '/usr/sbin/sshd' >> /entrypoint.sh && \
    echo '/usr/sbin/named -u named -g -c /etc/named/named.conf' >> /entrypoint.sh && \
    chmod +x /entrypoint.sh

# 创建 BIND 配置目录软链接
RUN mkdir -p /etc/named && \
    ln -sf /etc/named.conf /etc/named/named.conf 2>/dev/null; exit 0

STOPSIGNAL SIGTERM

ENTRYPOINT ["/entrypoint.sh"]
DOCKERFILE_EOF
```

### 5.2 构建镜像

```bash
cd /data/bind-cluster
docker build -t centos-bind:latest .
```

---

## 六、创建10个用户（宿主机层面记录，容器内创建）

### 6.1 用户规划表

| 容器名 | 用户名 | 密码 | SSH端口 | DNS端口 | 容器IP |
|--------|--------|------|---------|---------|--------|
| bind-ns1 | dnsadmin1 | 独立随机密码 | 22001 | 5301 | 172.20.0.11 |
| bind-ns2 | dnsadmin2 | 独立随机密码 | 22002 | 5302 | 172.20.0.12 |
| bind-ns3 | dnsadmin3 | 独立随机密码 | 22003 | 5303 | 172.20.0.13 |
| bind-ns4 | dnsadmin4 | 独立随机密码 | 22004 | 5304 | 172.20.0.14 |
| bind-ns5 | dnsadmin5 | 独立随机密码 | 22005 | 5305 | 172.20.0.15 |
| bind-ns6 | dnsadmin6 | 独立随机密码 | 22006 | 5306 | 172.20.0.16 |
| bind-ns7 | dnsadmin7 | 独立随机密码 | 22007 | 5307 | 172.20.0.17 |
| bind-ns8 | dnsadmin8 | 独立随机密码 | 22008 | 5308 | 172.20.0.18 |
| bind-ns9 | dnsadmin9 | 独立随机密码 | 22009 | 5309 | 172.20.0.19 |
| bind-ns10 | dnsadmin10 | 独立随机密码 | 22010 | 5310 | 172.20.0.20 |

---

## 七、启动 10 个容器（核心操作）

### 7.1 一键部署脚本

```bash
cat > /data/bind-cluster/scripts/deploy-all.sh << 'SCRIPT_EOF'
#!/bin/bash
set -e

# ============================================
# 10实例一键部署脚本
# ============================================

NETWORK="bind-net"

echo "====== 开始部署 10 个 BIND 容器 ======"

for i in $(seq 1 10); do
    CONTAINER="bind-ns${i}"
    USERNAME="dnsadmin${i}"
    PASSWORD_FILE="/root/secure/bind-ns${i}.password"
    if [ ! -s "${PASSWORD_FILE}" ]; then
        echo "缺少密码文件 ${PASSWORD_FILE}，请为每个实例生成独立随机密码" >&2
        exit 1
    fi
    PASSWORD="$(cat "${PASSWORD_FILE}")"
    SSH_PORT=$((22000 + i))
    DNS_PORT=$((5300 + i))
    IP="172.20.0.$((10 + i))"

    echo ""
    echo "------------------------------------------------------"
    echo ">>> 部署 ${CONTAINER} (用户: ${USERNAME}, SSH: ${SSH_PORT}, DNS: ${DNS_PORT})"
    echo "------------------------------------------------------"

    # 1. 如果容器已存在则先删除
    docker rm -f ${CONTAINER} 2>/dev/null || true

    # 2. 创建容器
    docker run -d \
        --name ${CONTAINER} \
        --hostname ${CONTAINER} \
        --network ${NETWORK} \
        --ip ${IP} \
        --memory="150m" \
        --memory-swap="150m" \
        --cpus="0.3" \
        -p ${SSH_PORT}:22 \
        -p ${DNS_PORT}:53/tcp \
        -p ${DNS_PORT}:53/udp \
        -v /data/bind-cluster/configs/ns${i}.conf:/etc/named.conf:ro \
        -v /data/bind-cluster/configs/named.zones.ns${i}:/etc/named/named.zones:ro \
        -v /data/bind-cluster/data/ns${i}/var:/var/named \
        -v /data/bind-cluster/data/ns${i}/log:/var/log/named \
        --restart unless-stopped \
        centos-bind:latest

    # 3. 等待容器启动
    sleep 3

    # 4. 在容器内创建用户并设密码
    docker exec ${CONTAINER} useradd -m -s /bin/bash ${USERNAME}
    docker exec ${CONTAINER} bash -c "echo '${USERNAME}:${PASSWORD}' | chpasswd"

    # 5. 给用户 sudo 权限（可选）
    docker exec ${CONTAINER} bash -c "echo '${USERNAME} ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers.d/${USERNAME}"

    # 6. 确保 BIND 数据目录权限正确
    docker exec ${CONTAINER} chown -R named:named /var/named
    docker exec ${CONTAINER} chown -R named:named /var/log/named
    docker exec ${CONTAINER} chmod 755 /var/named

    # 7. 重新启动容器（让其加载完整配置）
    docker restart ${CONTAINER}

    echo ">>> ${CONTAINER} 部署完成！"
done

echo ""
echo "====== 全部部署完成 ======"
echo ""
echo "验证命令: docker ps --filter \"name=bind-ns\" --format \"table {{.Names}}\t{{.Status}}\t{{.Ports}}\""
SCRIPT_EOF

chmod +x /data/bind-cluster/scripts/deploy-all.sh
```

### 7.2 执行部署

```bash
cd /data/bind-cluster
bash scripts/deploy-all.sh
```

### 7.3 验证部署结果

```bash
# 查看所有容器状态
docker ps --filter "name=bind-ns" \
    --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# 检查每个容器的 BIND 是否启动
for i in $(seq 1 10); do
    echo -n "bind-ns${i}: "
    docker exec bind-ns${i} pgrep -a named || echo "BIND 未运行!"
done

# 检查内存使用
docker stats --no-stream --filter "name=bind-ns" \
    --format "table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.CPUPerc}}"
```

---

## 八、登录方式

### 8.1 SSH 登录（从容器的 SSH 端口登录）

```bash
# 登录第一个实例
ssh dnsadmin1@<云主机IP> -p 22001
# 密码从 /root/secure/bind-ns1.password 获取

# 登录第二个实例
ssh dnsadmin2@<云主机IP> -p 22002
# 密码从 /root/secure/bind-ns2.password 获取

# ... 依此类推，端口 22001-22010

# 简化：使用别名
cat >> ~/.ssh/config << 'EOF'
Host bind-ns1
    HostName <云主机IP>
    Port 22001
    User dnsadmin1

Host bind-ns2
    HostName <云主机IP>
    Port 22002
    User dnsadmin2

# ... 依此类推
EOF

# 之后直接：
ssh bind-ns1
```

### 8.2 Docker exec 登录（直接在宿主机操作）

```bash
# 以创建的用户身份登录容器
docker exec -it -u dnsadmin1 bind-ns1 /bin/bash

# 以 root 身份登录（管理用）
docker exec -it bind-ns1 /bin/bash
```

---

## 九、BIND 服务验证

### 9.1 验证每个实例的 DNS 解析

```bash
# 在宿主机上测试
for i in $(seq 1 10); do
    DNS_PORT=$((5300 + i))
    echo "====== 测试 bind-ns${i} (端口 ${DNS_PORT}) ======"

    # 查询 SOA 记录
    dig @127.0.0.1 -p ${DNS_PORT} example${i}.local SOA +short

    # 查询 A 记录
    dig @127.0.0.1 -p ${DNS_PORT} www.example${i}.local +short
done
```

### 9.2 进入容器内部检查

```bash
# 以 ns1 为例
docker exec bind-ns1 systemctl status named 2>/dev/null || \
docker exec bind-ns1 pgrep -la named

# 查看日志
docker exec bind-ns1 tail -f /var/log/named/named.log

# 检查端口监听
docker exec bind-ns1 netstat -tunlp | grep 53
```

### 9.3 查看每个容器的 zone 文件

```bash
for i in $(seq 1 10); do
    echo "=== ns${i} zones ==="
    docker exec bind-ns${i} ls -la /var/named/
done
```

---

## 十、日常管理脚本

### 10.1 批量操作脚本

```bash
cat > /data/bind-cluster/scripts/ctl-all.sh << 'SCRIPT_EOF'
#!/bin/bash
ACTION=${1:-status}
N=${2:-10}

case $ACTION in
    start)
        for i in $(seq 1 $N); do
            docker start bind-ns${i}
            echo "bind-ns${i} 已启动"
        done
        ;;
    stop)
        for i in $(seq 1 $N); do
            docker stop bind-ns${i}
            echo "bind-ns${i} 已停止"
        done
        ;;
    restart)
        for i in $(seq 1 $N); do
            docker restart bind-ns${i}
            echo "bind-ns${i} 已重启"
        done
        ;;
    reload)
        # 重载 BIND 配置（不重启容器）
        for i in $(seq 1 $N); do
            docker exec bind-ns${i} rndc reload 2>/dev/null || \
            docker restart bind-ns${i}
            echo "bind-ns${i} BIND 已重载"
        done
        ;;
    status)
        docker ps --filter "name=bind-ns" \
            --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        echo ""
        echo "--- 内存使用 ---"
        docker stats --no-stream --filter "name=bind-ns" \
            --format "table {{.Name}}\t{{.MemUsage}}"
        ;;
    logs)
        i=${2:-1}
        docker logs -f --tail=50 bind-ns${i}
        ;;
    *)
        echo "用法: $0 {start|stop|restart|reload|status|logs [N]}"
        ;;
esac
SCRIPT_EOF

chmod +x /data/bind-cluster/scripts/ctl-all.sh
```

### 10.2 常用管理命令速查

```bash
# 查看所有实例状态
bash /data/bind-cluster/scripts/ctl-all.sh status

# 重启所有
bash /data/bind-cluster/scripts/ctl-all.sh restart

# 查看 ns3 的日志
bash /data/bind-cluster/scripts/ctl-all.sh logs 3

# 进入 ns5 容器
docker exec -it bind-ns5 bash

# 查看某个容器的配置
cat /data/bind-cluster/configs/ns5.conf

# 修改 ns5 的 zone 文件后重载
vim /data/bind-cluster/data/ns5/var/example5.local.zone
# 修改 serial 号
docker exec bind-ns5 rndc reload
```

---

## 十一、内存优化建议

2GB 内存跑 10 个 BIND 非常极限，以下优化**强烈建议执行**：

### 11.1 BIND 层面优化

```bash
# 在每个容器中创建内存优化配置
for i in $(seq 1 10); do
    cat >> /data/bind-cluster/configs/ns${i}.conf << 'INNER_EOF'

# ===== 内存优化 =====
# 减少并发查询线程
recursive-clients 50;

# 禁用 DNSSEC（节省大量内存）
dnssec-enable no;
dnssec-validation no;

# 减少 UDP 缓冲区
edns-udp-size 512;
max-udp-size 512;

# 减少同时打开的 TCP 连接
tcp-clients 20;

# 禁用 IPv6
listen-on-v6 { none; };
INNER_EOF
done
```

### 11.2 Docker 层面限制

已经在部署脚本中设置了：
- `--memory="150m"` — 每个容器限制 150MB
- `--cpus="0.3"` — 每个容器限制 0.3 核

### 11.3 宿主机层面优化

```bash
# 启用 swap（如果内存不足）
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab

# 清理 Docker 无用资源
docker system prune -a -f
```

---

## 十二、故障排查

### 12.1 常见问题

| 问题 | 排查命令 | 解决方法 |
|------|---------|---------|
| BIND 未启动 | `docker exec bind-ns1 named -g` 前台调试 | 检查 named.conf 语法 |
| 容器 OOM | `docker inspect bind-ns1 \| grep -i oom` | 降低 `--memory` 或增加 swap |
| 端口冲突 | `netstat -tunlp \| grep 5301` | 检查端口是否被占用 |
| SSH 连不上 | `docker exec bind-ns1 pgrep sshd` | `docker exec bind-ns1 /usr/sbin/sshd` |
| DNS 查询失败 | `dig @127.0.0.1 -p 5301 example1.local` | 检查 iptables 和容器网络 |

### 12.2 彻底重置

```bash
# 停止并删除所有 BIND 容器
for i in $(seq 1 10); do
    docker rm -f bind-ns${i}
done

# 清理数据（谨慎！）
# rm -rf /data/bind-cluster/data/ns{1..10}/var/*
# rm -rf /data/bind-cluster/data/ns{1..10}/log/*

# 重新部署
bash /data/bind-cluster/scripts/deploy-all.sh
```

---

## 附录：单实例手动部署（学习用）

如果只想先起一个实例手动学习：

```bash
# 步骤1：创建容器
docker run -d --name bind-ns1 \
    --hostname bind-ns1 \
    --network bind-net --ip 172.20.0.11 \
    --memory="200m" --cpus="0.5" \
    -p 22001:22 -p 5301:53/tcp -p 5301:53/udp \
    -v /data/bind-cluster/configs/ns1.conf:/etc/named.conf:ro \
    -v /data/bind-cluster/configs/named.zones.ns1:/etc/named/named.zones:ro \
    -v /data/bind-cluster/data/ns1/var:/var/named \
    -v /data/bind-cluster/data/ns1/log:/var/log/named \
    centos-bind:latest

# 步骤2：创建用户
docker exec bind-ns1 useradd -m -s /bin/bash dnsadmin1
docker exec -i bind-ns1 chpasswd < <(printf 'dnsadmin1:%s\n' "$(cat /root/secure/bind-ns1.password)")

# 步骤3：修复权限 + 重启
docker exec bind-ns1 chown -R named:named /var/named /var/log/named
docker restart bind-ns1

# 步骤4：验证
dig @127.0.0.1 -p 5301 example1.local SOA +short
ssh dnsadmin1@<云主机IP> -p 22001
```

---

> **文档版本**: v1.0 | **适用系统**: CentOS 7/8/Stream | **内存要求**: ≥ 2GB（建议4GB）
