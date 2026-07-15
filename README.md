# sshh

原版 Calculator / ZeroCore PersistenceHelper 运行时辅助。

## 功能

1. **激活绕过**
   - Hook 欢迎页 `tsh_checkActivationAndEnterHome` 直接 `ToHome:`
   - Hook 底层校验 `0x8C904` / `0x8C7A8` 返回 1
2. **绘制启动诊断**
   - Hook `-[ViewController startButtonTapped]`
   - Hook `+[HUDThread StartAndEnd:]` / `CheckHudThreadState:`
   - Hook `posix_spawn` 打印 path/argv/返回值

## 构建

```sh
cd /path/to/sshh
source ./devkit/roothide.sh
make package
# 或
./build_roothide.sh
```

## 日志

```sh
log stream --predicate 'eventMessage CONTAINS "[sshh]"' --level debug
```

点“开启绘制”后重点看：

- `startButtonTapped`
- `HUDThread StartAndEnd:1`
- `posix_spawn ENTER/OK/FAIL`
- `HUD post-start check pidExists=...`
