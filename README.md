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


## 0.1.3 HUD 触摸修复

现象：日志窗看得见但点不了/滑不动。

原因：
1. 加载中 `canCloseLogPanel=NO`，X 被禁用
2. 自定义 HID 只 `hitTest(windows.firstObject)`，firstObject 常是不可交互的 `HUDMainWindow`

修复：
- 强制关闭解锁
- 提升 `LOGRootWindow` 层级
- `HUDMainWindow hitTest` 恒返回 nil
- 强制 HID 命中窗口为 `LOGRootWindow`
