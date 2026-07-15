# sshh

原版 Calculator / ZeroCore PersistenceHelper 运行时辅助。

## 0.1.6 触摸修复（收敛）

截图已证明插件生效，且原版在“漏洞加载完成”后会自己解锁关闭。
因此“点不了”不是 close 锁问题。

0.1.5 过激改动可能反而破坏触摸：
- 把 `windowLevel` 拉到 1e7，却不重新 `registerWindowWithContextID:atLevel:`
- `TSEventFetcher` 参数重写有风险
- `hitTest` 强行返回 rootView 可能打断 UIControl

0.1.6：
- **不再改 windowLevel**
- 每次 `HIDDeliverTouchOnMain` 仍强制全局 hit 窗 = `LOGRootWindow`
- 修复 `HideView/secureHostView` 内部可点层级
- 重新 accessibility 登记（保持原 level）
- 文件日志：`/var/mobile/Library/Caches/sshh-touch.log`

## 装完后请做

1. 重新开启绘制
2. 点几下日志窗
3. 把下面文件发我：

```sh
cat /var/mobile/Library/Caches/sshh-touch.log
```

关键行：
- `loaded ... hud=1 v=0.1.6`
- `deliver-touch hook installed`
- `deliver_touch #N ... hit=...`
- `HUDApplication sendEvent`
- `closeTapped ENTER`

如果完全没有 `deliver_touch` / `sendEvent`，说明 HID 合成链没进进程，问题在更底层（权限/backboard），不是按钮逻辑。
