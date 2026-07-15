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
3. **日志窗关闭解锁**
   - 原版加载中 `canCloseLogPanel=NO`，X 点不动
   - 强制允许关闭，并恢复 closeButton enabled/alpha
4. **HUD 触摸路由修复（0.1.5 强化）**
   - 原版 `HIDDeliverTouchOnMain` 只对全局 hit 窗口做 hitTest
   - 该全局 once 写成 `windows.firstObject`，常为不可点的 `HUDMainWindow`
   - 现已在 **每次** deliver touch 强制写成 `LOGRootWindow`
   - 额外 hook `TSEventFetcher` 做 inWindow/onView 重定向兜底
   - 提升 `LOGRootWindow` 层级，`HUDMainWindow hitTest` 恒 nil

## 构建

```sh
cd /path/to/sshh
source ./devkit/roothide.sh
make package
# 或
./build_roothide.sh
```

GitHub Actions：push 到 `main` 会自动 roothide 编译，产物在 Actions artifact `roothide-packages`。

## 日志

```sh
log stream --predicate 'eventMessage CONTAINS "[sshh]"' --level debug
```

点“开启绘制”后重点看：

- `loaded ... hud=1`
- `deliver-touch hook installed`
- `hit window forced LOG`
- `deliver_touch #N forced=1 before=... after=LOGRootWindow`
- `closeTapped`（点 X 时应出现）

## 版本

- `0.1.3` 初次 HUD 触摸修复（只 hook set_hit_window + 关锁）
- `0.1.4` ARC 编译修复
- `0.1.5` 每次 `HIDDeliverTouchOnMain` 强制 LOG 窗 + TSEventFetcher 重定向
