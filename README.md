# sshh

原版 Calculator / ZeroCore PersistenceHelper 运行时激活绕过。

## 作用

- 不改主二进制，避免透明窗/重签问题
- Hook 两处激活检查（`0x8C904` / `0x8C7A8`）强制返回 1
- Hook `-[TSHWelcomeViewController tsh_checkActivationAndEnterHome]` 直接 `ToHome:YES`

## 构建（roothide）

```sh
cd /var/mobile/Containers/Shared/AppGroup/.jbroot-CC8D8B1B95BFD42F/var/mobile/SuSu/sshh
source ./devkit/roothide.sh
make package
# 或
make package install
```

## 使用

1. 确认 Calculator 是**未补丁原版** PersistenceHelper
2. 安装本插件
3. `killall Calculator` 后重开

## 日志

```sh
log stream --predicate 'eventMessage CONTAINS "[sshh]"' --level debug
```
